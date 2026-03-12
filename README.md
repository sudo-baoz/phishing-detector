<div align="center">

<img src="https://i.imgur.com/zzY1gKN.jpeg" alt="Phishing Detector Logo" width="250"/>

# 🛡️ Phishing Detector
### AI-Powered Forensic & Threat Intel System

[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![React](https://img.shields.io/badge/react-19.0.0-61DAFB.svg?style=flat&logo=react&logoColor=black)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/fastapi-0.115.6-009688.svg?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Security](https://img.shields.io/badge/security-Turnstile%20Protected-orange)](https://www.cloudflare.com/)

<br/>

> **Next-Gen Phishing Detection** | **Deep URL Forensics** | **AI-Driven Analysis** | **OSINT Integration**

<br/>

A comprehensive **Phishing Detection System** designed for Blue Teams and security researchers. This tool combines traditional **OSINT** techniques (Whois, DNS, SSL analysis) with **Generative AI (Gemini)** to detect sophisticated phishing campaigns, evasion techniques, and malicious infrastructure in real-time.

</div>

---

## ✨ Key Features

### 🔍 Deep Forensic Analysis
* **Real-time URL Scanning:** Instant analysis using ML models and heuristic rules.
* **Infrastructure Inspection:** Automated checks for Domain Age, Registrar, ASN, and IP Reputation.
* **Evasion Detection:** Identifies Typosquatting (Homograph attacks), URL Obfuscation, and multiple redirection chains.
* **Content-Based Analysis:** DOM inspection to detect fake login forms and cloaking techniques.

### 🤖 Sentinel AI Assistant
* **Context-Aware Intelligence:** Chat with Sentinel AI to explain *why* a URL is malicious.
* **Auto-Detection:** Automatically extracts and scans URLs mentioned in the conversation.
* **Bilingual Support:** Native support for **English** and **Vietnamese**, tailored for regional threat landscapes.

### 🛡️ Enterprise-Grade Security
* **Cloudflare Turnstile Integration:** Protects the scanner itself from bot abuse and DDoS using Smart CAPTCHA.
* **Secure API:** JWT Authentication and rate limiting ready.

### 🎨 Modern UX/UI
* **Cyberpunk Aesthetic:** Glassmorphism design with Matrix rain effects.
* **Visual Verdict:** Animated circular gauges for clear "Safe" vs "Phishing" scoring.
* **Responsive:** Mobile-first design optimized for quick field analysis.

---

## 🛠️ Tech Stack

### Core Engine (Backend)
* **Framework:** FastAPI (High-performance async Python)
* **AI/ML:** Google Gemini Pro (LLM), Scikit-learn (Feature extraction)
* **Forensics:** `python-whois`, `dnspython`, `requests` (Header analysis)
* **Security:** Cloudflare Turnstile Verification
* **Database:** SQLAlchemy (SQLite/PostgreSQL)

### Interface (Frontend)
* **Library:** React 19 + Vite
* **Styling:** Tailwind CSS + Framer Motion (Animations)
* **State Management:** React Hooks
* **I18n:** `i18next` (Internationalization)

---

## 📦 Installation

### Prerequisites
* Python 3.10+
* Node.js 18+
* Cloudflare Account (for Turnstile Keys)
* Google AI Studio Account (for Gemini API)

### 1. Clone Repository
```bash
git clone https://github.com/sudo-baoz/phishing-detector.git
cd phishing-detector
```

### 2. Backend Setup

**The backend must run in a virtual environment (venv).** Otherwise, dependencies may conflict with the system.

```bash
# Create virtual environment
python -m venv .venv

# Activate venv (required before running backend)
# Windows (PowerShell/CMD):
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies (inside venv)
pip install -r requirements.txt
```

**Configuration (.env):**
Create `.env` file in the root directory:

```env
# Database
DB_TYPE=sqlite
DB_NAME=phishing_detector

# Server
PORT=8000
DEBUG=false

# CORS (Replace with your frontend domain)
CORS_ORIGINS=https://yourfrontend.com,http://localhost:5173

# Security
CLOUDFLARE_SECRET_KEY=your_secret_key_here
# Dev: set false to skip Turnstile verification (avoids 404/CSP errors in console)
TURNSTILE_ENABLED=true

# AI
GEMINI_API_KEY=your_gemini_api_key_here
```

**Run server (always in activated venv):**

```bash
uvicorn app.main:app --reload --port 8000
```

### 3. Frontend Setup

```bash
cd frontend
npm install

# Create .env
cp .env.example .env
# Edit .env and add:
# VITE_API_URL=http://localhost:8000
# VITE_CLOUDFLARE_SITE_KEY=your_site_key

# Start Dev Server
npm run dev
```

Access: `http://localhost:5173`

**Note (dev):** If using default (placeholder) Turnstile key, frontend will NOT load the widget to avoid 404 / "Private Access Token" / CSP errors in console. Backend needs `TURNSTILE_ENABLED=false` in `.env` to accept requests without token.

---

## 🏗️ Build Instructions

### Production Build - Backend

```bash
# Activate virtual environment
source .venv/bin/activate

# Run with production settings
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

**Systemd Service (Linux):**
Create `/etc/systemd/system/phishing-api.service`:

```ini
[Unit]
Description=Phishing Detector API
After=network.target

[Service]
User=your-user
WorkingDirectory=/path/to/phishing-detector
Environment="PATH=/path/to/phishing-detector/.venv/bin"
ExecStart=/path/to/phishing-detector/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable phishing-api
sudo systemctl start phishing-api
```

### Production Build - Frontend

```bash
cd frontend

# Build for production
npm run build

# Preview build locally
npm run preview

# Deploy to Vercel/Netlify
vercel --prod
# or
netlify deploy --prod
```

The build output will be in `frontend/dist/`.

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

---

## 🧩 How It Works

1. **Input:** User submits a URL or mentions it in chat.
2. **Pre-processing:** The system resolves the URL, follows redirects (unshortening), and normalizes the string.
3. **OSINT Gathering:** Fetches Whois data, DNS records (A, MX, NS, TXT), and SSL certificate details.
4. **AI Analysis:** The aggregated data is sent to **Gemini AI** with a specific prompt to analyze for social engineering traits.
5. **Verdict:** A risk score (0-100) is calculated, and a detailed report is generated.

---

## 📜 License

This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](LICENSE) file for details.

### What this means:
- ✅ You can use, modify, and distribute this software
- ✅ You must disclose source code when distributing
- ✅ You must use the same GPL-3.0 license for derivative works
- ✅ You must state changes made to the code

### Important Notes:
- This project uses **GPL-3.0 compatible** libraries only
- All source files include copyright headers as required by GPL-3.0
- Commercial use is allowed under GPL-3.0 terms

---

## ⚠️ Legal Disclaimer

**EDUCATIONAL PURPOSE ONLY.**
This tool is designed to help security researchers and users identify potential phishing threats. The developers are not responsible for any misuse of this tool or for any damages caused by accessing malicious websites detected by this system. Always use a sandbox environment when analyzing live malware or phishing sites.

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request for any bugs or feature enhancements.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/NewFeature`)
3. Commit your Changes (`git commit -m 'Add some NewFeature'`)
4. Push to the Branch (`git push origin feature/NewFeature`)
5. Open a Pull Request

---

## ☕ Support the Project

If you find this tool useful for your research or security work, please consider buying me a coffee! Your support helps cover server costs (API keys, hosting) and keeps the updates coming.

<div align="center">

| **Platform** | **Link / Info** |
| :--- | :--- |
| <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="45" alt="Buy Me A Coffee"> | [**Buy me a coffee**](https://buymeacoffee.com/baoz) |
| <img src="https://cdn.haitrieu.com/wp-content/uploads/2022/10/Logo-MoMo-Square.png" height="40" alt="MoMo"> | **0395818082** (Mai Quoc Bao) |
| <img src="https://img.vietqr.io/image/VCB-9395818082-compact.png" height="45" alt="VietQR"> | **Vietcombank**<br>STK: `9395818082`<br>CTK: `Mai Quoc Bao` |

### 🪙 Crypto Donations

| Coin | Network | Address |
| :--- | :---: | :--- |
| **USDT** | BEP20 (BSC) | `0x2cc9c23be635a6959e35474dabd15c3aa7171ea4` |
| **ETH** | ERC20 | `0x2cc9c23be635a6959e35474dabd15c3aa7171ea4` |

</div>

---

**Built with 💻 & ☕ by [sudo-baoz](https://github.com/sudo-baoz)**

**Copyright (c) 2026 BaoZ. Licensed under GPL-3.0.**
