# 🚀 Deployment Guide - Phishing Detector

Complete deployment instructions for various hosting platforms.

---

## Table of Contents
1. [Vercel (Frontend)](#vercel-frontend)
2. [Railway (Backend)](#railway-backend)
3. [Render (Full-Stack)](#render-full-stack)
4. [Docker](#docker-deployment)
5. [Environment Variables](#environment-variables)
6. [Domain Configuration](#domain-configuration)
7. [SSL/HTTPS Setup](#sslhttps-setup)

---

## Vercel (Frontend)

### Prerequisites
- GitHub account
- Vercel account ([vercel.com](https://vercel.com))
- Frontend code pushed to GitHub

### Step-by-Step

#### 1. Import Project
1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Click **"New Project"**
3. Select GitHub repository
4. Choose `frontend` directory as root

#### 2. Configure Build Settings
```
Framework Preset: Vite
Root Directory: frontend
Build Command: npm run build
Output Directory: dist
Install Command: npm install
```

#### 3. Environment Variables
Add in Vercel Dashboard → Settings → Environment Variables:

| Variable | Value | Environment |
|----------|-------|-------------|
| `VITE_API_URL` | `https://your-backend.railway.app` | Production |
| `VITE_API_URL` | `http://localhost:8000` | Development |

#### 4. Deploy
Click **"Deploy"** → Wait 2-3 minutes → Done! ✅

**Your URL:** `https://phishing-detector.vercel.app`

---

## Railway (Backend)

### Prerequisites
- GitHub account
- Railway account ([railway.app](https://railway.app))
- Backend code pushed to GitHub

### Step-by-Step

#### 1. Create New Project
1. Go to [Railway Dashboard](https://railway.app/dashboard)
2. Click **"New Project"**
3. Select **"Deploy from GitHub repo"**
4. Choose repository

#### 2. Configure Service
```
Root Directory: .
Build Command: (auto-detected)
Start Command: uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

#### 3. Add PostgreSQL (Optional)
1. Click **"New"** → **"Database"** → **"PostgreSQL"**
2. Railway auto-creates `DATABASE_URL` variable
3. Update backend to use PostgreSQL instead of SQLite

#### 4. Environment Variables
Add in Railway → Variables:

```env
GEMINI_API_KEY=your_gemini_api_key
DATABASE_URL=${{Postgres.DATABASE_URL}}  # Auto-generated
CORS_ORIGINS=https://phishing-detector.vercel.app,http://localhost:5173
SECRET_KEY=random-secret-key-generate-with-openssl
PORT=${{PORT}}  # Auto-generated
```

#### 5. Generate Domain
1. Go to Settings → Networking
2. Click **"Generate Domain"**
3. Copy URL (e.g., `phishing-backend-production.up.railway.app`)

#### 6. Update Frontend
Update `VITE_API_URL` in Vercel to Railway backend URL.

---

## Render (Full-Stack)

### Option 1: Single Web Service (Static + API)

#### Backend Service

1. **Create Web Service**
   - Repository: Your GitHub repo
   - Root Directory: `.`
   - Environment: Python 3.10+

2. **Build & Start**
   ```
   Build Command: pip install -r requirements.txt
   Start Command: uvicorn app.main:app --host 0.0.0.0 --port $PORT
   ```

3. **Environment Variables**
   ```env
   GEMINI_API_KEY=your_key
   DATABASE_URL=postgresql://...  (from Render PostgreSQL)
   CORS_ORIGINS=https://your-frontend.onrender.com
   PYTHON_VERSION=3.10.0
   ```

#### Frontend Service

1. **Create Static Site**
   - Repository: Same repo
   - Root Directory: `frontend`

2. **Build**
   ```
   Build Command: npm install && npm run build
   Publish Directory: dist
   ```

3. **Environment Variables**
   ```env
   VITE_API_URL=https://your-backend.onrender.com
   ```

---

### Option 2: Docker Compose (Advanced)

#### Create `render.yaml`
```yaml
services:
  - type: web
    name: phishing-detector-backend
    env: docker
    dockerfilePath: ./Dockerfile
    envVars:
      - key: GEMINI_API_KEY
        sync: false
      - key: DATABASE_URL
        fromDatabase:
          name: phishing-db
          property: connectionString
      - key: PORT
        value: 8000

  - type: web
    name: phishing-detector-frontend
    env: static
    buildCommand: cd frontend && npm install && npm run build
    staticPublishPath: ./frontend/dist
    envVars:
      - key: VITE_API_URL
        value: https://phishing-detector-backend.onrender.com

databases:
  - name: phishing-db
    databaseName: phishing_detector
    user: phishing_user
```

#### Deploy via Blueprint
```bash
# Push render.yaml to repo root
git add render.yaml
git commit -m "Add Render blueprint"
git push

# Render will auto-detect and deploy
```

---

## Docker Deployment

### Single Container (Development)

#### Create `Dockerfile`
```dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app ./app
COPY models ./models

# Expose port
EXPOSE 8000

# Start server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

#### Build & Run
```bash
docker build -t phishing-detector-backend .
docker run -p 8000:8000 --env-file .env phishing-detector-backend
```

---

### Docker Compose (Full-Stack)

#### Create `docker-compose.yml`
```yaml
version: '3.8'

services:
  backend:
    build: .
    container_name: phishing-backend
    ports:
      - "8000:8000"
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}
      - DATABASE_URL=postgresql://user:password@db:5432/phishing
      - CORS_ORIGINS=http://localhost:5173
    depends_on:
      - db
    volumes:
      - ./models:/app/models

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: phishing-frontend
    ports:
      - "5173:5173"
    environment:
      - VITE_API_URL=http://localhost:8000
    depends_on:
      - backend

  db:
    image: postgres:15-alpine
    container_name: phishing-db
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=phishing
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

volumes:
  postgres_data:
```

#### Frontend Dockerfile
Create `frontend/Dockerfile`:
```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 5173

CMD ["npm", "run", "dev", "--", "--host"]
```

#### Deploy
```bash
docker-compose up -d
```

---

## Environment Variables

### Backend (.env)
```env
# Required
GEMINI_API_KEY=AIzaSy...  # From Google AI Studio

# Database
DATABASE_URL=sqlite:///./phishing_detector.db  # Or PostgreSQL URL

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000

# CORS (Important!)
CORS_ORIGINS=http://localhost:5173,https://your-frontend.com

# Security
SECRET_KEY=your-super-secret-key-min-32-chars  # Generate with: openssl rand -hex 32
```

### Frontend (.env or Vite config)
```env
# API Endpoint
VITE_API_URL=http://localhost:8000  # Development
VITE_API_URL=https://api.your-domain.com  # Production
```

### Generate Secret Key
```bash
# Linux/macOS
openssl rand -hex 32

# Python
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Domain Configuration

### Custom Domain on Vercel
1. Vercel Dashboard → Project → Settings → Domains
2. Add domain: `phishing-detector.com`
3. Update DNS:
   ```
   Type: CNAME
   Name: @
   Value: cname.vercel-dns.com
   ```

### Custom Domain on Railway
1. Railway Dashboard → Project → Settings → Networking
2. Add custom domain: `api.phishing-detector.com`
3. Update DNS:
   ```
   Type: CNAME
   Name: api
   Value: [railway-generated-cname]
   ```

---

## SSL/HTTPS Setup

### Automatic (Recommended)

**Vercel:** SSL auto-enabled ✅
**Railway:** SSL auto-enabled ✅
**Render:** SSL auto-enabled ✅

### Manual (Nginx Reverse Proxy)

#### Install Certbot
```bash
sudo apt install certbot python3-certbot-nginx
```

#### Generate Certificate
```bash
sudo certbot --nginx -d phishing-detector.com -d www.phishing-detector.com
```

#### Nginx Configuration
```nginx
server {
    listen 443 ssl http2;
    server_name phishing-detector.com;

    ssl_certificate /etc/letsencrypt/live/phishing-detector.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/phishing-detector.com/privkey.pem;

    location / {
        proxy_pass http://localhost:5173;  # Frontend
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    location /api {
        proxy_pass http://localhost:8000;  # Backend
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Production Checklist

### Before Deployment
- [ ] Update `GEMINI_API_KEY` with production key
- [ ] Change `SECRET_KEY` (never use default!)
- [ ] Set `DATABASE_URL` to production database
- [ ] Update `CORS_ORIGINS` with production URLs
- [ ] Remove debug logs
- [ ] Test all endpoints locally
- [ ] Run security scan: `npm audit` / `safety check`

### After Deployment
- [ ] Verify frontend loads
- [ ] Test URL scanning
- [ ] Test Sentinel AI chat
- [ ] Check language switching
- [ ] Verify database connection
- [ ] Monitor error logs
- [ ] Set up uptime monitoring (UptimeRobot, Pingdom)

---

## Monitoring & Logs

### Vercel Logs
```bash
vercel logs [deployment-url]
```

### Railway Logs
Dashboard → Project → Deployments → View Logs

### Render Logs
Dashboard → Service → Logs (real-time)

### Docker Logs
```bash
docker-compose logs -f backend
docker-compose logs -f frontend
```

---

## Troubleshooting

### CORS Errors
**Symptom:** `Access-Control-Allow-Origin` error in browser console

**Fix:**
1. Check `CORS_ORIGINS` in backend `.env`
2. Must include frontend URL (with https://)
3. No trailing slash
4. Restart backend after change

### Database Connection Failed
**Symptom:** `OperationalError: unable to open database file`

**Fix:**
1. Verify `DATABASE_URL` format
2. Check database service is running
3. For PostgreSQL: Use connection pooling

### 502 Bad Gateway
**Symptom:** Vercel shows 502 error

**Fix:**
1. Check backend is responding (visit `/docs`)
2. Verify `VITE_API_URL` is correct
3. Check firewall settings
4. Restart backend service

---

## Cost Estimates

### Free Tier (Recommended for Testing)
- **Vercel:** Free (100GB bandwidth, unlimited requests)
- **Railway:** $5/month free credit
- **Render:** Free (with limits)

### Production (Low Traffic)
- **Vercel Pro:** $20/month
- **Railway:** ~$5-10/month
- **Render Starter:** $7/month
- **Total:** ~$30-40/month

---

**Need Help?** Open an issue on [GitHub](https://github.com/sudo-baoz/phishing-detector/issues)
