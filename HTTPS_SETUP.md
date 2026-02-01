# 🔐 HTTPS Setup for VPS - Nginx Reverse Proxy

**Problem:** Frontend (HTTPS) → Backend (HTTP) = Mixed Content Error ❌

**Solution:** Setup Nginx reverse proxy with SSL certificate ✅

---

## Quick Fix for Production

### Step 1: Set Environment Variable in Vercel

Go to Vercel Dashboard → Your Project → Settings → Environment Variables

Add:
```
Variable: VITE_API_URL
Value: https://api.baodarius.me
Environment: Production
```

Redeploy frontend.

---

### Step 2: Setup Nginx Reverse Proxy on VPS

#### Install Nginx
```bash
sudo apt update
sudo apt install nginx -y
```

#### Create Nginx Configuration
```bash
sudo nano /etc/nginx/sites-available/phishing-api
```

Paste this config:
```nginx
server {
    listen 80;
    server_name api.baodarius.me;  # Your API subdomain

    location / {
        proxy_pass http://127.0.0.1:8000;  # FastAPI backend
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

#### Enable Site
```bash
sudo ln -s /etc/nginx/sites-available/phishing-api /etc/nginx/sites-enabled/
sudo nginx -t  # Test config
sudo systemctl restart nginx
```

---

### Step 3: Setup SSL Certificate (Let's Encrypt)

#### Install Certbot
```bash
sudo apt install certbot python3-certbot-nginx -y
```

#### Generate SSL Certificate
```bash
sudo certbot --nginx -d api.baodarius.me
```

Follow prompts:
- Enter email
- Agree to TOS
- Choose: **Redirect HTTP to HTTPS** (option 2)

#### Auto-Renewal (already set up by certbot)
```bash
sudo certbot renew --dry-run  # Test auto-renewal
```

---

### Step 4: Update DNS

Add A record:
```
Type: A
Name: api
Value: 180.93.2.59 (your VPS IP)
TTL: Auto
```

Wait 5-10 minutes for DNS propagation.

---

### Step 5: Verify Setup

Test HTTPS endpoint:
```bash
curl https://api.baodarius.me/
```

Should return:
```json
{
  "message": "Phishing URL Detection API",
  "version": "1.0.0",
  "status": "operational"
}
```

---

## Alternative: Direct SSL in FastAPI (Not Recommended)

If you can't use Nginx, you can run uvicorn with SSL:

#### Generate Self-Signed Certificate (dev only)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

#### Run Uvicorn with SSL
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 \
  --ssl-keyfile=key.pem \
  --ssl-certfile=cert.pem
```

⚠️ **Not recommended for production** - use Nginx instead!

---

## Final Configuration Summary

After setup, your architecture will be:

```
User Browser (HTTPS)
  ↓
Frontend: https://ai.baodarius.me (Vercel)
  ↓
Backend API: https://api.baodarius.me (Nginx → Uvicorn)
  ↓
FastAPI: http://127.0.0.1:8000 (localhost only)
```

**Security:**
- ✅ All traffic encrypted (HTTPS)
- ✅ No mixed content errors
- ✅ Auto-renewing SSL certificate
- ✅ FastAPI only accessible via Nginx

---

## Troubleshooting

### SSL Certificate Issues
```bash
# Check certificate
sudo certbot certificates

# Force renewal
sudo certbot renew --force-renewal
```

### Nginx Errors
```bash
# Check logs
sudo tail -f /var/log/nginx/error.log

# Test config
sudo nginx -t

# Restart
sudo systemctl restart nginx
```

### CORS Still Blocked
Update `app/main.py`:
```python
allow_origins=["https://ai.baodarius.me", "https://api.baodarius.me"]
```

---

## Production Checklist

- [ ] DNS A record for api.baodarius.me → VPS IP
- [ ] Nginx installed and configured
- [ ] SSL certificate installed (Let's Encrypt)
- [ ] FastAPI CORS updated with HTTPS origins
- [ ] Vercel environment variable: VITE_API_URL=https://api.baodarius.me
- [ ] Frontend redeployed
- [ ] Test: curl https://api.baodarius.me/
- [ ] Test: Scan URL from frontend

---

**Estimated Setup Time:** 15-20 minutes
