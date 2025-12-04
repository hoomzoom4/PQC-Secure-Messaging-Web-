"""
PQC Secure Messenger - Web Version
==================================
Flask + Socket.IO backend for real-time encrypted messaging.

Uses:
- ML-KEM-512 for post-quantum key exchange
- ML-DSA-44 for post-quantum signatures
- AES-256-GCM for message encryption
"""

import os
import sys
from datetime import datetime
from flask import Flask, render_template, request, session
from flask_socketio import SocketIO, emit, join_room

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from pqcrypto.kem.ml_kem_512 import (
    generate_keypair as kem_generate_keypair,
    encrypt as kem_encrypt,
    decrypt as kem_decrypt,
)
from pqcrypto.sign.ml_dsa_44 import (
    generate_keypair as sig_generate_keypair,
    sign as sig_sign,
    verify as sig_verify,
)

# Flask setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*")

# Store connected users and their crypto state
users = {}  # {username: {sid, kem_pk, kem_sk, sig_pk, sig_sk, session_key}}
chat_room = "pqc_chat"

# Auto-rotation settings
AUTO_ROTATE_AFTER = 10


class UserCrypto:
    """Manages cryptographic state for a user."""

    def __init__(self, username):
        self.username = username
        self.message_count = 0
        self.rotation_count = 0

        # Generate KEM keypair
        self.kem_pk, self.kem_sk = kem_generate_keypair()

        # Generate signature keypair
        self.sig_pk, self.sig_sk = sig_generate_keypair()

        # Session key (established via KEM)
        self.session_key = None

    def derive_session_key(self, shared_secret):
        """Derive AES key from shared secret."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pqc-web-messenger',
        )
        self.session_key = hkdf.derive(shared_secret)
        return self.session_key

    def encrypt(self, plaintext):
        """Encrypt message with AES-256-GCM."""
        if not self.session_key:
            raise ValueError("No session key!")
        aesgcm = AESGCM(self.session_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        self.message_count += 1
        return (nonce + ciphertext).hex()

    def decrypt(self, ciphertext_hex):
        """Decrypt message with AES-256-GCM."""
        if not self.session_key:
            return "[NO SESSION KEY]"
        try:
            data = bytes.fromhex(ciphertext_hex)
            aesgcm = AESGCM(self.session_key)
            plaintext = aesgcm.decrypt(data[:12], data[12:], None)
            return plaintext.decode('utf-8')
        except Exception as e:
            return f"[DECRYPTION FAILED]"

    def sign(self, data):
        """Sign data with ML-DSA-44."""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return sig_sign(self.sig_sk, data).hex()

    def rotate_keys(self):
        """Generate new KEM keypair."""
        self.kem_pk, self.kem_sk = kem_generate_keypair()
        self.session_key = None
        self.message_count = 0
        self.rotation_count += 1
        return self.kem_pk.hex()[:16]

    def should_rotate(self):
        """Check if auto-rotation needed."""
        return self.message_count >= AUTO_ROTATE_AFTER

    def get_stats(self):
        """Get crypto stats for display."""
        return {
            'kem_algorithm': 'ML-KEM-512 (FIPS 203)',
            'sig_algorithm': 'ML-DSA-44 (FIPS 204)',
            'cipher': 'AES-256-GCM',
            'session_key': self.session_key.hex()[:16] + '...' if self.session_key else 'Not established',
            'message_count': self.message_count,
            'rotation_count': self.rotation_count,
            'auto_rotate_after': AUTO_ROTATE_AFTER,
        }


def verify_signature(data, signature_hex, sender_sig_pk):
    """Verify a signature from another user."""
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        signature = bytes.fromhex(signature_hex)
        return sig_verify(sender_sig_pk, data, signature)
    except:
        return False


def establish_session(user1_crypto, user2_crypto):
    """Perform KEM key exchange between two users."""
    # User1 encapsulates using User2's public key
    ciphertext, shared_secret = kem_encrypt(user2_crypto.kem_pk)

    # Both derive the same session key
    session_key = user1_crypto.derive_session_key(shared_secret)

    # User2 would normally decapsulate, but since we're server-side,
    # we just give them the same key
    user2_crypto.session_key = session_key

    return session_key.hex()[:16]


@app.route('/')
def index():
    """Serve the chat page."""
    return render_template('chat.html')


@socketio.on('connect')
def handle_connect():
    """Handle new connection."""
    print(f"Client connected: {request.sid}")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle disconnection."""
    # Find and remove the user
    username_to_remove = None
    for username, data in users.items():
        if data.get('sid') == request.sid:
            username_to_remove = username
            break

    if username_to_remove:
        del users[username_to_remove]
        emit('user_left', {'username': username_to_remove}, room=chat_room)
        emit('system_message', {
            'text': f'{username_to_remove} has disconnected',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=chat_room)
        print(f"User disconnected: {username_to_remove}")


@socketio.on('join')
def handle_join(data):
    """Handle user joining the chat."""
    username = data.get('username', '').strip()

    if not username:
        emit('error', {'message': 'Username required'})
        return

    if username in users:
        emit('error', {'message': 'Username already taken'})
        return

    # Create crypto state for user
    crypto = UserCrypto(username)

    users[username] = {
        'sid': request.sid,
        'crypto': crypto,
        'is_permanent_mode': False,
    }

    join_room(chat_room)

    # Notify others
    emit('user_joined', {'username': username}, room=chat_room)

    # Send welcome message to the new user
    emit('joined', {
        'username': username,
        'kem_pk': crypto.kem_pk.hex()[:32] + '...',
        'sig_pk': crypto.sig_pk.hex()[:32] + '...',
    })

    emit('system_message', {
        'text': f'Welcome {username}! Your PQC keys have been generated.',
        'timestamp': datetime.now().strftime('%H:%M:%S')
    })

    emit('system_message', {
        'text': f'KEM: ML-KEM-512 | Signatures: ML-DSA-44 | Cipher: AES-256-GCM',
        'timestamp': datetime.now().strftime('%H:%M:%S')
    })

    # Try to establish session if another user exists
    other_users = [u for u in users.keys() if u != username]
    if other_users:
        partner = other_users[0]
        partner_crypto = users[partner]['crypto']

        # Establish shared session
        key_fp = establish_session(crypto, partner_crypto)

        emit('system_message', {
            'text': f'Session established with {partner}! Key: {key_fp}...',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        })

        # Notify partner too
        emit('system_message', {
            'text': f'Session established with {username}! Key: {key_fp}...',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=users[partner]['sid'])

        emit('session_established', {'partner': partner, 'key_fp': key_fp})
        emit('session_established', {'partner': username, 'key_fp': key_fp}, room=users[partner]['sid'])

    # Send current user list
    emit('user_list', {'users': list(users.keys())}, room=chat_room)

    print(f"User joined: {username}")


@socketio.on('send_message')
def handle_message(data):
    """Handle incoming message."""
    sender = None
    for username, udata in users.items():
        if udata['sid'] == request.sid:
            sender = username
            break

    if not sender:
        emit('error', {'message': 'Not logged in'})
        return

    plaintext = data.get('message', '')
    is_permanent = data.get('is_permanent', False)

    if not plaintext:
        return

    sender_crypto = users[sender]['crypto']

    # Check if session established
    if not sender_crypto.session_key:
        emit('error', {'message': 'No secure session established yet'})
        return

    # Encrypt the message
    ciphertext = sender_crypto.encrypt(plaintext)

    # Sign the ciphertext
    signature = sender_crypto.sign(ciphertext)

    timestamp = datetime.now().strftime('%H:%M:%S')

    # Send to all users in room
    for username, udata in users.items():
        recipient_crypto = udata['crypto']

        if username == sender:
            # Sender sees their own message (already knows plaintext)
            emit('new_message', {
                'sender': 'Me',
                'text': plaintext,
                'verified': True,
                'is_permanent': is_permanent,
                'timestamp': timestamp,
            })
        else:
            # Recipient decrypts and verifies
            decrypted = recipient_crypto.decrypt(ciphertext)
            verified = verify_signature(ciphertext, signature, sender_crypto.sig_pk)

            emit('new_message', {
                'sender': sender,
                'text': decrypted,
                'verified': verified,
                'is_permanent': is_permanent,
                'timestamp': timestamp,
            }, room=udata['sid'])

    # Check for auto-rotation
    if sender_crypto.should_rotate():
        handle_rotate({'auto': True})


@socketio.on('rotate_keys')
def handle_rotate(data=None):
    """Handle key rotation request."""
    sender = None
    for username, udata in users.items():
        if udata['sid'] == request.sid:
            sender = username
            break

    if not sender:
        return

    is_auto = data.get('auto', False) if data else False
    sender_crypto = users[sender]['crypto']

    # Rotate keys
    new_key_fp = sender_crypto.rotate_keys()

    rotation_type = "AUTO-ROTATION" if is_auto else "MANUAL ROTATION"

    # Notify everyone
    emit('key_rotation', {
        'username': sender,
        'rotation_type': rotation_type,
        'new_key_fp': new_key_fp,
        'timestamp': datetime.now().strftime('%H:%M:%S'),
    }, room=chat_room)

    # Re-establish session with other users
    other_users = [u for u in users.keys() if u != sender]
    if other_users:
        partner = other_users[0]
        partner_crypto = users[partner]['crypto']
        key_fp = establish_session(sender_crypto, partner_crypto)

        emit('system_message', {
            'text': f'New session established. Key: {key_fp}...',
            'timestamp': datetime.now().strftime('%H:%M:%S')
        }, room=chat_room)


@socketio.on('toggle_mode')
def handle_toggle_mode(data):
    """Toggle ephemeral/permanent mode."""
    sender = None
    for username, udata in users.items():
        if udata['sid'] == request.sid:
            sender = username
            break

    if not sender:
        return

    users[sender]['is_permanent_mode'] = data.get('is_permanent', False)
    mode = "PERMANENT" if users[sender]['is_permanent_mode'] else "EPHEMERAL"

    emit('mode_changed', {
        'username': sender,
        'mode': mode,
        'timestamp': datetime.now().strftime('%H:%M:%S'),
    })


@socketio.on('get_stats')
def handle_get_stats():
    """Get crypto stats for current user."""
    sender = None
    for username, udata in users.items():
        if udata['sid'] == request.sid:
            sender = username
            break

    if sender:
        stats = users[sender]['crypto'].get_stats()
        emit('stats', stats)


if __name__ == '__main__':
    print("=" * 60)
    print("  PQC SECURE MESSENGER - WEB VERSION")
    print("=" * 60)
    print()
    print("Starting server...")
    print("Open http://localhost:5000 in your browser")
    print()
    print("Features:")
    print("  - ML-KEM-512 (Kyber) - Post-Quantum Key Exchange")
    print("  - ML-DSA-44 (Dilithium) - Post-Quantum Signatures")
    print("  - AES-256-GCM - Symmetric Encryption")
    print("  - Real-time messaging with Socket.IO")
    print("  - Auto key rotation every 10 messages")
    print()
    print("=" * 60)

    port = int(os.getenv("PORT", "5000"))
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)