# Deployment Guide

This guide covers the deployment of the Phishing Detector on a Linux VPS (Ubuntu 22.04 LTS).

## Prerequisites
*   **Server**: Ubuntu 22.04 / Debian 11
*   **RAM**: Minimum 4GB (AI models require memory)
*   **Disk**: 20GB+ SSD
*   **Domains**: A domain pointing to your server IP (e.g., `scanner.example.com`).

---

## 1. Backend Setup

### Step 1: System Dependencies
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3-pip python3-venv git nginx
```

### Step 2: Clone Repository
```bash
git clone https://github.com/sudo-baoz/phishing-detector.git
cd phishing-detector
```

### Step 3: Python Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium  # If using Playwright for scraping
```

### Step 4: Environment Variables
Create `.env` file:
```bash
cp .env.example .env
nano .env
```
Fill in your API Keys (Gemini, Cloudflare, etc.).

### Step 5: Systemd Service
Create a service to keep the API running.
File: `/etc/systemd/system/phishing-api.service`

```ini
[Unit]
Description=Phishing Detector API
After=network.target

[Service]
User=root
WorkingDirectory=/root/phishing-detector
Environment="PATH=/root/phishing-detector/.venv/bin"
ExecStart=/root/phishing-detector/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable it:
```bash
sudo systemctl daemon-reload
sudo systemctl enable phishing-api
sudo systemctl start phishing-api
```

---

## 2. Frontend Setup

### Step 1: Build React App
```bash
cd frontend
# Install dependencies
npm install

# Configure Build Environment
echo "VITE_API_URL=https://scanner.example.com/api" > .env.production

# Build
npm run build
```
Output will be in `frontend/dist`.

### Step 2: Nginx Configuration
File: `/etc/nginx/sites-available/phishing-detector`

```nginx
server {
    listen 80;
    server_name scanner.example.com;

    # Frontend (Static Files)
    location / {
        root /root/phishing-detector/frontend/dist;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    # Backend API Proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        rewrite ^/api/(.*) /$1 break;
    }
}
```

Enable Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/phishing-detector /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## 3. Docker Deployment (Alternative)

If you prefer Docker, create this `docker-compose.yml`:

```yaml
version: '3.8'
services:
  backend:
    build: .
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000
    volumes:
      - .:/app
    environment:
      - DB_TYPE=sqlite
    ports:
      - "8000:8000"

  frontend:
    build: ./frontend
    ports:
      - "80:80"
```
