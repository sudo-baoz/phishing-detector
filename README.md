# 🛡️ Phishing Detector - AI-Powered Forensic & Threat Intel System

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![React](https://img.shields.io/badge/react-19.0.0-61DAFB.svg?style=flat&logo=react&logoColor=black)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/fastapi-0.115.6-009688.svg?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Security](https://img.shields.io/badge/security-Turnstile%20Protected-orange)](https://www.cloudflare.com/)

> **Next-Gen Phishing Detection** | **Deep URL Forensics** | **AI-Driven Analysis** | **OSINT Integration**

A comprehensive **Phishing Detection System** designed for Blue Teams and security researchers. This tool combines traditional **OSINT** techniques (Whois, DNS, SSL analysis) with **Generative AI (Gemini)** to detect sophisticated phishing campaigns, evasion techniques, and malicious infrastructure in real-time.

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
* **Bilingual Support:** Native support for **English** and **Vietnamese** (Tiếng Việt), tailored for regional threat landscapes.

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
git clone [https://github.com/sudo-baoz/phishing-detector.git](https://github.com/sudo-baoz/phishing-detector.git)
cd phishing-detector

```

### 2. Backend Setup

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

```

**Configuration (.env):**
Create a `.env` file in the root directory:

```env
GEMINI_API_KEY=your_gemini_api_key
DATABASE_URL=sqlite:///./phishing_detector.db
SECRET_KEY=your_super_secret_key
CLOUDFLARE_SECRET_KEY=0x4AAAAAA...

```

**Run Server:**

```bash
uvicorn app.main:app --reload --port 8000

```

### 3. Frontend Setup

```bash
cd frontend
npm install

# Create .env.local
echo "VITE_CLOUDFLARE_SITE_KEY=your_site_key" > .env.local

# Start Dev Server
npm run dev

```

Access the application at: `http://localhost:5173`

---

## 🧩 How It Works

1. **Input:** User submits a URL or mentions it in chat.
2. **Pre-processing:** The system resolves the URL, follows redirects (unshortening), and normalizes the string.
3. **OSINT Gathering:** Fetches Whois data, DNS records (A, MX, NS, TXT), and SSL certificate details.
4. **AI Analysis:** The aggregated data is sent to **Gemini AI** with a specific prompt to analyze for social engineering traits.
5. **Verdict:** A risk score (0-100) is calculated, and a detailed report is generated.

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
| <img src="https://upload.wikimedia.org/wikipedia/vi/f/fe/MoMo_Logo.png" height="40" alt="MoMo"> | **0395818082** (Mai Quoc Bao) |
| <img src="https://img.vietqr.io/image/VCB-9395818082-compact.png" height="45" alt="VietQR"> | **Vietcombank**<br>STK: `9395818082`<br>CTK: `Mai Quoc Bao` |

### 🪙 Crypto Donations

| Coin | Network | Address |
| :--- | :---: | :--- |
| **USDT** | BEP20 (BSC) | `0x2cc9c23be635a6959e35474dabd15c3aa7171ea4` |
| **ETH** | ERC20 | `0x2cc9c23be635a6959e35474dabd15c3aa7171ea4` |

</div>
---

**Built with 💻 & ☕ by [sudo-baoz**](https://www.google.com/search?q=https://github.com/sudo-baoz)

```
