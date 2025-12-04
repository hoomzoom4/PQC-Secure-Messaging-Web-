# PQC Secure Messenger - Web Version

A real-time encrypted messaging application using **Post-Quantum Cryptography**.

## Features

- **ML-KEM-512** (Kyber) - Quantum-resistant key exchange
- **ML-DSA-44** (Dilithium) - Quantum-resistant digital signatures
- **AES-256-GCM** - Symmetric encryption
- **Real-time messaging** via WebSockets
- **Auto key rotation** every 10 messages
- **Visual forward secrecy barriers**
- **Ephemeral (7-day) vs Permanent modes**

## Local Development

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the server
python app.py

# Open http://localhost:5000 in your browser
```

## Deployment to hamizan.cc

### Option 1: VPS (DigitalOcean, Linode, etc.)

1. **SSH into your server:**
```bash
ssh root@your-server-ip
```

2. **Install Python and dependencies:**
```bash
apt update
apt install python3 python3-pip python3-venv nginx
```

3. **Clone/upload your code:**
```bash
mkdir -p /var/www/pqc-messenger
cd /var/www/pqc-messenger
# Upload your web/ folder contents here
```

4. **Set up virtual environment:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

5. **Create systemd service** (`/etc/systemd/system/pqc-messenger.service`):
```ini
[Unit]
Description=PQC Secure Messenger
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/pqc-messenger
ExecStart=/var/www/pqc-messenger/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

6. **Start the service:**
```bash
systemctl start pqc-messenger
systemctl enable pqc-messenger
```

7. **Configure Nginx** (`/etc/nginx/sites-available/pqc-messenger`):
```nginx
server {
    listen 80;
    server_name hamizan.cc;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

8. **Enable and restart Nginx:**
```bash
ln -s /etc/nginx/sites-available/pqc-messenger /etc/nginx/sites-enabled/
nginx -t
systemctl restart nginx
```

9. **Add HTTPS with Let's Encrypt:**
```bash
apt install certbot python3-certbot-nginx
certbot --nginx -d hamizan.cc
```

### Option 2: Railway.app (Easier)

1. Create a `Procfile` in the web folder:
```
web: python app.py
```

2. Push to GitHub

3. Connect Railway to your repo

4. Set environment variables if needed

5. Deploy!

### Option 3: Render.com

1. Create a new Web Service
2. Connect your GitHub repo
3. Set build command: `pip install -r requirements.txt`
4. Set start command: `python app.py`
5. Deploy!

## Security Notes

- This is a **prototype** for educational purposes
- The server can see messages (not true end-to-end encryption)
- For production, add proper authentication and HTTPS
- Consider rate limiting and input validation

## Project Structure

```
web/
├── app.py              # Flask + Socket.IO backend
├── requirements.txt    # Python dependencies
├── templates/
│   └── chat.html       # Frontend (HTML/CSS/JS)
└── README.md           # This file
```
