# PQC Secure Messenger - Web Version

A real-time encrypted messaging application using **Post-Quantum Cryptography (PQC)**. This prototype demonstrates quantum-resistant cryptography in a practical messaging application, preparing for the post-quantum computing era.

**Live Demo:** [https://hamizan.cc](https://hamizan.cc)

---

## Table of Contents

- [What is Post-Quantum Cryptography?](#what-is-post-quantum-cryptography)
- [Features](#features)
- [Technical Architecture](#technical-architecture)
- [Getting Started](#getting-started)
  - [Online Version (Railway Deployment)](#online-version-railway-deployment)
  - [Offline Version (Local Browser)](#offline-version-local-browser)
- [How the Cryptography Works](#how-the-cryptography-works)
- [Project Structure](#project-structure)
- [Security Considerations](#security-considerations)
- [Deployment](#deployment)

---

## What is Post-Quantum Cryptography?

Current encryption methods (RSA, ECC) will be broken by quantum computers. PQC algorithms are designed to resist attacks from both classical and quantum computers. This prototype uses:

- **ML-KEM-512** (FIPS 203) - Module-Lattice-Based Key Encapsulation Mechanism, formerly known as Kyber
- **ML-DSA-44** (FIPS 204) - Module-Lattice-Based Digital Signature Algorithm, formerly known as Dilithium
- **AES-256-GCM** - Symmetric encryption (quantum-resistant when using 256-bit keys)

These algorithms were selected by NIST as the first standardized post-quantum cryptographic algorithms.

---

## Features

### Cryptographic Features
- **Quantum-resistant key exchange** using ML-KEM-512 (Kyber)
- **Quantum-resistant digital signatures** using ML-DSA-44 (Dilithium)
- **Authenticated encryption** with AES-256-GCM
- **Forward secrecy** through automatic key rotation
- **Message authentication** with PQC signatures

### User Features
- **Real-time messaging** via WebSockets (Socket.IO)
- **Auto key rotation** every 10 messages
- **Visual forward secrecy barriers** in chat interface
- **Ephemeral mode** (messages disappear after 7 days) vs **Permanent mode**
- **Cryptographic statistics** display (key fingerprints, rotation count)
- **Multi-user support** with session key management

---

## Technical Architecture

### Backend (Python/Flask)
- **Flask** - Web framework
- **Flask-SocketIO** - Real-time WebSocket communication
- **pqcrypto** - Python bindings for PQC algorithms (C library)
- **cryptography** - AES-GCM encryption and key derivation (HKDF)

### Frontend (HTML/CSS/JavaScript)
- **Socket.IO Client** - Real-time communication
- **Vanilla JavaScript** - No frameworks, lightweight implementation
- **Responsive design** - Mobile-friendly interface

### Cryptographic Flow

1. **User Joins:**
   - Server generates ML-KEM-512 keypair for key exchange
   - Server generates ML-DSA-44 keypair for signatures

2. **Session Establishment:**
   - When two users connect, server performs KEM encapsulation
   - Shared secret is derived using HKDF-SHA256
   - AES-256-GCM session key is established

3. **Message Exchange:**
   - Sender encrypts message with AES-256-GCM
   - Ciphertext is signed with ML-DSA-44
   - Recipient verifies signature and decrypts

4. **Key Rotation:**
   - After 10 messages, keys automatically rotate
   - New ML-KEM-512 keypair generated
   - New session key established
   - Visual barrier shown in chat

---

## Getting Started

### Online Version (Railway Deployment)

The application is **live at [hamizan.cc](https://hamizan.cc)**!

#### Domain Setup
1. **Domain purchased** from [Namecheap.com](https://namecheap.com): `hamizan.cc`
2. **DNS configured** through [Cloudflare](https://cloudflare.com):
   - Added domain to Cloudflare
   - Changed nameservers at Namecheap to Cloudflare's
   - Created DNS A/CNAME records pointing to Railway
3. **Deployed** on [Railway.app](https://railway.app):
   - Connected GitHub repository
   - Railway auto-detects Python and installs dependencies
   - Application runs on Railway's infrastructure
   - SSL/TLS automatically handled by Cloudflare

#### How Railway Deployment Works
Railway reads `requirements.txt` and automatically:
- Installs Python dependencies
- Detects Flask application
- Runs `python app.py` (reads PORT environment variable)
- Provides a public URL that Cloudflare points to

---

### Offline Version (Local Browser)

The **offline version** runs entirely on your local machine without internet connectivity. Perfect for testing, development, or air-gapped environments.

#### System Requirements
- **Python 3.8+** (Python 3.9-3.11 recommended)
- **pip** (Python package manager)
- **Any modern browser** (Chrome, Firefox, Edge, Safari)
- **Windows, macOS, or Linux**

#### Installation Steps (Brand New Device)

**Step 1: Install Python**

<details>
<summary><b>Windows</b></summary>

1. Download Python from [python.org/downloads](https://python.org/downloads)
2. Run installer, **check "Add Python to PATH"**
3. Verify installation:
```bash
python --version
pip --version
```
</details>

<details>
<summary><b>macOS</b></summary>

```bash
# Install Homebrew first (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python3

# Verify
python3 --version
pip3 --version
```
</details>

<details>
<summary><b>Linux (Ubuntu/Debian)</b></summary>

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
python3 --version
pip3 --version
```
</details>

**Step 2: Set Up the Offline Version**

```bash
# Navigate to the offline version directory
cd PQC-Secure-Messaging-Offline-

# Create a virtual environment (isolated Python environment)
python -m venv venv

# Activate the virtual environment
# Windows:
venv\Scripts\activate

# macOS/Linux:
source venv/bin/activate

# Install dependencies (needs internet for first-time setup)
pip install -r requirements.txt

# Run the application
python app.py
```

**Step 3: Access in Browser**

Open your browser and navigate to:
```
http://localhost:5000
```

You should see the PQC Secure Messenger login screen!

#### Using the Offline Version

1. **Open two browser tabs/windows** to `http://localhost:5000`
2. **Enter different usernames** in each tab (e.g., "Alice" and "Bob")
3. **Start chatting!** The cryptography happens locally
4. **Watch key rotations** - after 10 messages, keys automatically rotate
5. **Check the stats** - see cryptographic details in the interface

#### Stopping the Server

Press `Ctrl+C` in the terminal where `app.py` is running.

#### Running Again Later

```bash
# Navigate to directory
cd PQC-Secure-Messaging-Offline-

# Activate virtual environment
venv\Scripts\activate  # Windows
source venv/bin/activate  # macOS/Linux

# Run server
python app.py
```

---

## How the Cryptography Works

### 1. Key Generation (ML-KEM-512 & ML-DSA-44)

When a user joins:
```python
# Generate KEM keypair for key exchange
kem_pk, kem_sk = kem_generate_keypair()  # ML-KEM-512

# Generate signature keypair
sig_pk, sig_sk = sig_generate_keypair()  # ML-DSA-44
```

### 2. Session Key Establishment

When two users connect:
```python
# User A encapsulates using User B's public key
ciphertext, shared_secret = kem_encrypt(user_b_kem_pk)

# Derive AES-256 key using HKDF
session_key = HKDF(
    algorithm=SHA256(),
    length=32,
    salt=None,
    info=b'pqc-web-messenger'
).derive(shared_secret)
```

### 3. Message Encryption & Signing

Sending a message:
```python
# Encrypt with AES-256-GCM
aesgcm = AESGCM(session_key)
nonce = os.urandom(12)
ciphertext = aesgcm.encrypt(nonce, plaintext, None)

# Sign with ML-DSA-44
signature = sig_sign(sig_sk, ciphertext)
```

### 4. Message Verification & Decryption

Receiving a message:
```python
# Verify signature
is_valid = sig_verify(sender_sig_pk, ciphertext, signature)

# Decrypt if valid
plaintext = aesgcm.decrypt(nonce, ciphertext, None)
```

### 5. Automatic Key Rotation

After 10 messages:
```python
# Generate new KEM keypair
new_kem_pk, new_kem_sk = kem_generate_keypair()

# Re-establish session
new_ciphertext, new_shared_secret = kem_encrypt(partner_kem_pk)
new_session_key = derive_key(new_shared_secret)
```

This provides **forward secrecy** - old messages cannot be decrypted even if current keys are compromised.

---

## Project Structure

```
PQC-Secure-Messaging-Web/
├── app.py                          # Main Flask application (online version)
├── requirements.txt                # Python dependencies
├── templates/
│   └── chat.html                   # Frontend interface
├── PQC-Secure-Messaging-Offline-/  # Offline version
│   ├── app.py                      # Standalone offline server
│   ├── requirements.txt            # Same dependencies
│   ├── templates/
│   │   └── chat.html               # Same interface
│   └── venv/                       # Virtual environment (after setup)
└── README.md                       # This file
```

### Key Files

- **app.py** (421 lines)
  - `UserCrypto` class - Manages keys, encryption, signatures
  - `establish_session()` - KEM key exchange
  - Socket.IO event handlers - Join, message, rotate, disconnect

- **chat.html**
  - Socket.IO client connection
  - Message display with verification badges
  - Key rotation barriers
  - Cryptographic stats display

- **requirements.txt**
  ```
  flask==3.1.2
  flask-socketio==5.5.1
  python-socketio==5.15.0
  eventlet==0.40.4
  cryptography==46.0.3      # AES-GCM, HKDF
  pqcrypto==0.3.4           # ML-KEM-512, ML-DSA-44
  gunicorn==21.2.0          # Production server
  ```

---

## Security Considerations

### This is a Prototype for Educational Purposes

**Limitations:**

1. **Server-Side Encryption** - The server handles encryption/decryption, meaning:
   - This is NOT true end-to-end encryption
   - The server can read all messages
   - Trust in the server is required

2. **No User Authentication** - Usernames are not verified; anyone can claim any name

3. **In-Memory Storage** - All data (keys, messages) stored in RAM:
   - Data lost on server restart
   - No persistence for "permanent" messages

4. **No Rate Limiting** - Vulnerable to spam/DoS attacks

5. **Simplified Key Management** - Production systems need:
   - Key storage/backup mechanisms
   - Certificate authorities for public key verification
   - Key revocation mechanisms

### Why These Trade-offs?

This prototype prioritizes **demonstrating PQC algorithms** over production security. The focus is on:
- Showing how ML-KEM-512 and ML-DSA-44 work
- Demonstrating key rotation and forward secrecy
- Providing an educational reference implementation

### For Production Use

Consider:
- **Client-side encryption** (true E2E) using browser-based PQC libraries
- **User authentication** (OAuth, JWT, etc.)
- **Database storage** with encrypted fields
- **Rate limiting** and input validation
- **Audit logging** of cryptographic operations
- **Key escrow** or recovery mechanisms for enterprises

---

## Deployment

### Current Setup (hamizan.cc)

**Domain:** [Namecheap.com](https://namecheap.com)
- Registered `hamizan.cc` domain

**DNS/CDN:** [Cloudflare](https://cloudflare.com)
- Added domain to Cloudflare
- Updated nameservers at Namecheap
- Configured DNS records pointing to Railway
- SSL/TLS encryption enabled
- DDoS protection included

**Hosting:** [Railway.app](https://railway.app)
- Connected GitHub repository
- Automatic deployments on git push
- Reads `PORT` environment variable
- Managed Python runtime
- Free tier with usage limits

### Deploy Your Own Instance

#### Option 1: Railway.app (Recommended)

1. Fork this repository on GitHub
2. Sign up at [Railway.app](https://railway.app)
3. Create new project → "Deploy from GitHub"
4. Select your forked repository
5. Railway auto-detects Python and deploys
6. Get your Railway URL
7. (Optional) Add custom domain via Cloudflare

#### Option 2: Render.com

1. Sign up at [Render.com](https://render.com)
2. New Web Service → Connect repository
3. Build command: `pip install -r requirements.txt`
4. Start command: `python app.py`
5. Deploy

#### Option 3: Self-Hosted VPS

See the offline version setup, then configure Nginx as reverse proxy and use systemd for service management.

---

## Contributing

This is an educational prototype. Contributions welcome for:
- Bug fixes
- Documentation improvements
- Additional PQC algorithm demonstrations
- Performance optimizations
- Security enhancements (for educational purposes)

---

## License

This project is open-source for educational purposes. Please credit the original author when using or modifying.

---

## Learn More

- **NIST PQC:** https://csrc.nist.gov/projects/post-quantum-cryptography
- **ML-KEM (Kyber):** FIPS 203 standard
- **ML-DSA (Dilithium):** FIPS 204 standard
- **pqcrypto library:** https://github.com/PQClean/PQClean

---

**Built with quantum-resistant cryptography for the future.**
