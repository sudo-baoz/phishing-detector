# 🎯 Phishing Detector - Complete Setup Guide

Comprehensive deployment and security guide for production-ready phishing URL detection system.

---

## 📋 **Table of Contents**

1. [Quick Start](#quick-start)
2. [Environment Configuration](#environment-configuration)
3. [Cloudflare Turnstile Setup](#cloudflare-turnstile-setup)
4. [HTTPS & Nginx Configuration](#https--nginx-configuration)
5. [Deployment Options](#deployment-options)
6. [GitHub Security](#github-security)
7. [Troubleshooting](#troubleshooting)

---

## 🚀 **Quick Start**

### Local Development

**Backend:**
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Copy environment template
cp .env.example .env

# 3. Edit .env with your keys
nano .env

# 4. Run server
uvicorn app.main:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
cp .env.example .env
nano .env  # Add VITE_API_URL and VITE_CLOUDFLARE_SITE_KEY
npm run dev
```

---

## ⚙️ **Environment Configuration**

### Backend `.env`

```env
# Database
DB_TYPE=sqlite              # or mysql, postgresql
DB_NAME=phishing_detector

# Server
PORT=8000
DEBUG=false

# CORS (⚠️ Replace with your actual domains)
CORS_ORIGINS=https://yourfrontend.com,http://localhost:5173

# Security
CLOUDFLARE_SECRET_KEY=your_secret_key_here
TURNSTILE_ENABLED=true

# AI
GEMINI_API_KEY=your_gemini_api_key_here
```

### Frontend `.env`

```env
# API URL
VITE_API_URL=https://api.yourbackend.com  # or http://127.0.0.1:8000 for dev

# Cloudflare Turnstile
VITE_CLOUDFLARE_SITE_KEY=your_site_key_here
```

---

## 🛡️ **Cloudflare Turnstile Setup**

### 1. Get Keys

Visit [Cloudflare Dashboard](https://dash.cloudflare.com/) → Turnstile → Add Site

**Configuration:**
- Domain: `yourfrontend.com`
- Widget Mode: Managed (recommended)  
- Widget Type: Non-Interactive

Copy:
- **Site Key** → `VITE_CLOUDFLARE_SITE_KEY` (frontend)
- **Secret Key** → `CLOUDFLARE_SECRET_KEY` (backend)

### 2. Frontend Integration

Already integrated in `Scanner.jsx`. Just add environment variable!

### 3. Verify

```bash
# Test frontend
curl https://yourfrontend.com  # Should load Turnstile widget

# Test backend
curl -X POST https://api.yourbackend.com/scan \
  -H "cf-turnstile-response: test-token" \
  -d '{"url":"https://example.com"}'
# Should return 403 if token invalid
```

---

## 🔐 **HTTPS & Nginx Configuration**

### 1. Install Nginx & Certbot

```bash
sudo apt update
sudo apt install nginx certbot python3-certbot-nginx -y
```

### 2. Configure Nginx

Create `/etc/nginx/sites-available/phishing-api`:

```nginx
server {
    listen 80;
    server_name api.yourbackend.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.yourbackend.com;

    ssl_certificate /etc/letsencrypt/live/api.yourbackend.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.yourbackend.com/privkey.pem;

    # CORS headers
    add_header 'Access-Control-Allow-Origin' 'https://yourfrontend.com' always;
    add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE' always;
    add_header 'Access-Control-Allow-Headers' 'Origin, Content-Type, Accept, cf-turnstile-response' always;
    add_header 'Access-Control-Allow-Credentials' 'true' always;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable & start:
```bash
sudo ln -s /etc/nginx/sites-available/phishing-api /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 3. SSL Certificate

```bash
sudo certbot --nginx -d api.yourbackend.com
```

---

## 🌐 **Deployment Options**

### Option 1: VPS (Recommended)

**Backend:**
```bash
# On VPS
git clone your-repo
cd phishing-detector
pip install -r requirements.txt
cp .env.example .env
nano .env  # Configure

# Create systemd service
sudo nano /etc/systemd/system/phishing-api.service
```

Service file:
```ini
[Unit]
Description=Phishing Detector API
After=network.target

[Service]
User=your-user
WorkingDirectory=/path/to/phishing-detector
Environment="PATH=/path/to/phishing-detector/venv/bin"
ExecStart=/path/to/phishing-detector/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

Start service:
```bash
sudo systemctl daemon-reload
sudo systemctl start phishing-api
sudo systemctl enable phishing-api
```

**Frontend: Vercel**
```bash
cd frontend
npm run build
vercel --prod
```

Add env vars in Vercel dashboard!

### Option 2: Docker

```bash
docker-compose up -d
```

See `DEPLOYMENT.md` for full Docker guide.

---

## 🔒 **GitHub Security**

### ⚠️ **NEVER Commit:**
- `.env` files
- API keys
- Database credentials
- Production domains (use placeholders)

### ✅ **Safe to Commit:**
- `.env.example` (with placeholders)
- Source code
- `nginx-cors.conf` (with YOUR_DOMAIN placeholders)

### **Pre-Commit Checklist:**
```bash
# Verify .env is gitignored
git status | grep ".env"  # Should show nothing

# Check for secrets
git diff | grep -i "api.*key\|secret"

# Check for production domains
git diff | grep "yourproductionsite.com"
```

See `GITHUB_SECURITY.md` for complete guide.

---

## 🐛 **Troubleshooting**

### CORS Errors

**Problem:** `Access-Control-Allow-Origin` missing

**Solution:**
1. Check backend `CORS_ORIGINS` in `.env`
2. Verify Nginx forwards headers correctly
3. Restart backend and Nginx

### 403 Forbidden (Turnstile)

**Problem:** `bot_protection_required`

**Solution:**
1. Add Turnstile widget to frontend
2. Check `CLOUDFLARE_SECRET_KEY` in backend `.env`
3. Verify token sent in `cf-turnstile-response` header

### Scanner Widget Missing

**Problem:** Turnstile not showing

**Solution:**
1. Check `VITE_CLOUDFLARE_SITE_KEY` in `frontend/.env`
2. Restart dev server
3. See `SCANNER_TODO.md` for manual integration steps

### Mixed Content Error

**Problem:** Frontend HTTPS → Backend HTTP blocked

**Solution:**
1. Setup SSL for backend (see HTTPS section)
2. Update `VITE_API_URL` to `https://`

---

## 📚 **Additional Resources**

- **Full Deployment Guide:** `DEPLOYMENT.md`
- **GitHub Security:** `GITHUB_SECURITY.md`
- **Scanner Integration:** `SCANNER_TODO.md`
- **API Documentation:** Visit `/docs` endpoint

---

## 📞 **Support**

For issues:
1. Check `SCANNER_TODO.md` for pending steps
2. Review `GITHUB_SECURITY.md` for security practices
3. See `DEPLOYMENT.md` for deployment details

---

**Last Updated:** 2026-02-02
**Version:** 1.0.0

Ready for production deployment! 🚀
