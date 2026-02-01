# 🛡️ Phishing Detector - AI-Powered Threat Intelligence System

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![React](https://img.shields.io/badge/react-19.0.0-61dafb)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/fastapi-0.115.6-009688)](https://fastapi.tiangolo.com/)

> **Award-Winning UI** | **Multi-Language Support** | **AI-Powered Analysis** | **Real-time Threat Detection**

Comprehensive phishing detection system with advanced AI analysis, OSINT intelligence gathering, and an intelligent chatbot assistant (Sentinel AI) powered by Google Gemini.

---

## ✨ Features

### 🎯 Core Capabilities
- ⚡ **Real-time URL Analysis** - Instant phishing detection with ML model
- 🧠 **AI-Powered Insights** - Sentinel AI chatbot for security guidance
- 🌐 **Multi-Language Support** - English & Vietnamese (i18n ready)
- 🔍 **OSINT Intelligence** - WHOIS, DNS, geolocation, SSL analysis
- 📊 **Visual Analytics** - Circular gauges, glassmorphism UI, matrix rain effects
- 🚀 **Auto-Scan URLs** - Sentinel AI automatically detects and scans URLs in chat

### 🎨 Premium UI/UX
- **Glassmorphism Design** - Backdrop blur effects with semi-transparent cards
- **Matrix Rain Background** - Animated cyberpunk aesthetic
- **Circular Progress Gauge** - Animated SVG verdict display
- **Neon Glow Effects** - Interactive hover states and shadows
- **Responsive Layout** - Mobile-first design with CSS Grid

### 🤖 Sentinel AI Assistant
- **Context-Aware Responses** - Understands scan results
- **URL Auto-Detection** - Automatically scans URLs mentioned in chat
- **Multi-Language** - Responds in user's language (EN/VI)
- **Security Expertise** - Professional cyber security analysis

---

## 🛠️ Tech Stack

### Backend
- **FastAPI** - High-performance Python web framework
- **SQLAlchemy** - ORM for database management
- **scikit-learn** - Machine learning for phishing detection
- **Google Gemini AI** - Advanced language model for Sentinel AI
- **python-whois** - Domain information retrieval
- **dnspython** - DNS record analysis

### Frontend
- **React 19** - Modern UI library
- **Vite** - Lightning-fast build tool
- **Tailwind CSS** - Utility-first CSS framework
- **Framer Motion** - Smooth animations
- **i18next** - Internationalization framework
- **Lucide React** - Beautiful icon library

---

## 📦 Installation

### Prerequisites
- **Python 3.10+**
- **Node.js 18+**
- **npm** or **yarn**
- **Git**

### 1. Clone Repository
```bash
git clone https://github.com/sudo-baoz/phishing-detector.git
cd phishing-detector
```

### 2. Backend Setup

#### Create Virtual Environment
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# Linux/macOS
python3 -m venv .venv
source .venv/bin/activate
```

#### Install Dependencies
```bash
pip install -r requirements.txt
```

#### Configure Environment Variables
Create `.env` file in root directory:
```env
# Google Gemini API
GEMINI_API_KEY=your_gemini_api_key_here

# Database
DATABASE_URL=sqlite:///./phishing_detector.db

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
CORS_ORIGINS=http://localhost:5173,http://localhost:3000

# Security
SECRET_KEY=your-secret-key-change-this-in-production
```

**Get Gemini API Key:**
1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create new API key
3. Copy and paste into `.env`

#### Run Backend
```bash
uvicorn app.main:app --reload --port 8000
```

Backend will be available at: **http://localhost:8000**
API Docs: **http://localhost:8000/docs**

---

### 3. Frontend Setup

#### Navigate to Frontend Directory
```bash
cd frontend
```

#### Install Dependencies
```bash
npm install
```

#### Run Development Server
```bash
npm run dev
```

Frontend will be available at: **http://localhost:5173**

---

## 🚀 Deployment

### Option 1: Vercel (Frontend) + Railway (Backend)

#### Deploy Frontend to Vercel
1. Install Vercel CLI:
```bash
npm i -g vercel
```

2. Deploy:
```bash
cd frontend
vercel
```

3. Set Environment Variables in Vercel Dashboard:
   - `VITE_API_URL` = Your backend URL

#### Deploy Backend to Railway
1. Create account at [Railway.app](https://railway.app)
2. New Project → Deploy from GitHub
3. Select repository
4. Add Environment Variables:
   - `GEMINI_API_KEY`
   - `DATABASE_URL` (use Railway PostgreSQL)
   - `CORS_ORIGINS` (add Vercel URL)
5. Deploy!

---

### Option 2: Render (Full-Stack)

#### Deploy Backend
1. Create account at [Render.com](https://render.com)
2. New → Web Service
3. Connect GitHub repository
4. Configure:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Add Environment Variables
6. Create PostgreSQL database (optional, or use SQLite)

#### Deploy Frontend
1. New → Static Site
2. Connect GitHub repository
3. Configure:
   - **Build Command:** `cd frontend && npm install && npm run build`
   - **Publish Directory:** `frontend/dist`
4. Add Environment Variable:
   - `VITE_API_URL` = Backend URL

---

### Option 3: Docker (All Platforms)

#### Create `docker-compose.yml`
```yaml
version: '3.8'

services:
  backend:
    build: .
    ports:
      - "8000:8000"
    environment:
      - GEMINI_API_KEY=${GEMINI_API_KEY}
      - DATABASE_URL=sqlite:///./phishing_detector.db
    volumes:
      - ./database:/app/database

  frontend:
    build: ./frontend
    ports:
      - "5173:5173"
    environment:
      - VITE_API_URL=http://localhost:8000
    depends_on:
      - backend
```

#### Deploy
```bash
docker-compose up -d
```

---

## 📁 Project Structure

```
phishing-detector/
├── app/                          # Backend application
│   ├── routers/                  # API endpoints
│   │   ├── scan.py              # URL scanning endpoint
│   │   └── chat.py              # Sentinel AI chat endpoint
│   ├── services/                 # Business logic
│   │   ├── ai_engine.py         # ML phishing detection
│   │   ├── chat_agent.py        # Sentinel AI service
│   │   ├── osint.py             # Intelligence gathering
│   │   └── response_builder.py  # Response formatting
│   ├── schemas/                  # Pydantic models
│   ├── models/                   # SQLAlchemy models
│   └── main.py                   # FastAPI app entry
├── frontend/                     # React application
│   ├── src/
│   │   ├── components/          # UI components
│   │   │   ├── Scanner.jsx      # Main scanner interface
│   │   │   ├── ChatWidget.jsx   # Sentinel AI chat
│   │   │   └── LanguageSwitcher.jsx
│   │   ├── locales/             # i18n translations
│   │   │   ├── en.json          # English
│   │   │   └── vi.json          # Vietnamese
│   │   ├── services/            # API clients
│   │   └── i18n.js              # i18n configuration
│   └── package.json
├── models/                       # Trained ML models
│   └── advanced_model.pkl
├── .env                          # Environment variables
├── requirements.txt              # Python dependencies
└── README.md                     # This file
```

---

## 🎮 Usage

### Basic Workflow

1. **Enter URL** - Type suspicious URL in search bar
2. **Click "INITIATE SCAN"** - System analyzes the URL
3. **View Results** - See circular gauge with verdict (SAFE/PHISHING)
4. **Explore Details** - Check network intel, forensics, content analysis
5. **Ask Sentinel AI** - Get expert security advice via chatbot

### Sentinel AI Chat Examples

**English:**
```
User: "Is this safe? https://paypal-verify.tk"
AI: ⚠️ CRITICAL WARNING: This URL is HIGHLY DANGEROUS...
```

**Vietnamese:**
```
User: "Kiểm tra https://google.com"
AI: ✅ URL này AN TOÀN (95.0% confidence)...
```

### Language Switching
- Click **Globe icon** (top-right)
- Select **English** or **Tiếng Việt**
- All UI text updates instantly

---

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `GEMINI_API_KEY` | Google Gemini API key | - | ✅ Yes |
| `DATABASE_URL` | Database connection string | `sqlite:///./phishing_detector.db` | No |
| `API_HOST` | Backend host | `0.0.0.0` | No |
| `API_PORT` | Backend port | `8000` | No |
| `CORS_ORIGINS` | Allowed origins (comma-separated) | `http://localhost:5173` | No |
| `SECRET_KEY` | JWT secret key | - | ⚠️ Production |
| `VITE_API_URL` | Frontend API URL | `http://localhost:8000` | No |

---

## 🐛 Troubleshooting

### Backend Issues

**Error: "404 models/gemini-1.5-flash is not found"**
- **Fix:** Update to `gemini-2.5-flash` in `chat_agent.py`
- Already fixed in latest version ✅

**Error: "GEMINI_API_KEY not found"**
- **Fix:** Create `.env` file with valid API key
- Get key from [Google AI Studio](https://makersuite.google.com/app/apikey)

**Error: "Database connection failed"**
- **Fix:** Check `DATABASE_URL` in `.env`
- For SQLite: Ensure directory exists

### Frontend Issues

**Blank screen / Black screen**
- **Fix:** Check browser console (F12)
- Ensure backend is running on port 8000
- Verify `VITE_API_URL` in frontend

**"NaN%" in circular gauge**
- **Fix:** Backend not returning `confidence_score`
- Already fixed in latest version ✅

**Language switching not working**
- **Fix:** Clear browser localStorage
- Hard refresh (Ctrl+Shift+R)

---

## 🧪 Testing

### Run Backend Tests
```bash
pytest tests/ -v
```

### Manual Testing Checklist
- [ ] URL scanning works
- [ ] Sentinel AI responds correctly
- [ ] Language switching (EN ↔ VI)
- [ ] Matrix rain animation visible
- [ ] Circular gauge animates
- [ ] Mobile responsive design

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

---

## 📄 License

This project is licensed under the **Apache License 2.0** - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Google Gemini** - AI language model
- **FastAPI** - Modern web framework
- **React Team** - UI library
- **Tailwind CSS** - Utility CSS
- **Framer Motion** - Animation library

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/sudo-baoz/phishing-detector/issues)
- **Email:** maibao123bao@gmail.com
- **Documentation:** [Wiki](https://github.com/sudo-baoz/phishing-detector/wiki)

---

## 🗺️ Roadmap

- [ ] Add more ML models (ensemble learning)
- [ ] Implement user authentication
- [ ] Add scan history dashboard
- [ ] Support more languages (FR, ES, ZH)
- [ ] Browser extension
- [ ] API rate limiting
- [ ] Redis caching
- [ ] Webhook notifications

---

**Built with ❤️ by sudo-baoz**
