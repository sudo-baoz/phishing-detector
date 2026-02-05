# Changelog

All notable changes to the **Phishing Detector** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-02-05

### 🚀 Major Security Enhancements (The "Elite Analyst" Update)
This release introduces a multi-layered security engine designed to "Fail Fast" and reduce reliance on expensive AI calls for obvious threats.

#### Added
- **Google Safe Browsing Integration**:
  - Implemented as the **Primary Validation Layer**.
  - Blocks known malware and social engineering sites immediately.
  - Added `GOOGLE_SAFE_BROWSING_KEY` to configuration.
- **Fail-Fast Typosquatting Detection**:
  - New checks using `textdistance` (Levenshtein Similarity).
  - Automatically flags domains mimicking high-value targets (e.g., `faceb00k.com`, `paypal-secure.com`) with >80% visual similarity.
  - Bypasses AI analysis for these high-confidence threats.
- **Deep Network Forensics**:
  - **Domain Age Analysis**: Flags domains created less than 30 days ago.
  - **ASN/Hosting Reputation**: Detects "High-Risk Hosting" patterns (e.g., Banking sites hosted on DigitalOcean/OVH/Hetzner).
  - Calculates a **Network Trust Score** (0-100).
- **Advanced Redirect Tracing**:
  - **Open Redirect Abuse Detection**: Identifies trusted domains (YouTube, Google) redirecting to untrusted destinations.
  - **Infinite Loop Protection**: Enhanced `trace_redirects` with `requests.Session` and loop limits.
  - **Final URL Analysis**: All security checks (AI, RAG, Network) now operate on the *destination* URL, not the shortening service.

#### Security
- **Smart Orchestration**: The scanning pipeline now follows a strict hierarchy for efficiency:
  1. Redirect Trace (Get Final URL)
  2. Google Safe Browsing (Stop if Malware)
  3. Typosquatting Check (Stop if Impersonation)
  4. Network Forensics & AI Analysis (Only if previous checks pass)

---

## [1.2.0] - 2026-02-04

### Added
- **Vietnamese Localization (i18n)**: Full support for Vietnamese language in reports and UI.
- **Deep Technical Analysis**:
  - SSL Certificate Age verification (< 48 hours alert).
  - JavaScript Entropy analysis (detects obfuscated scripts).
  - Keyword Pattern Matching (sensitive terms in URL).
- **Mobile Optimization**: Responsive UI improvements for report cards and chat widget.
- **Semantic RAG**: "Lightweight" RAG system using local embeddings to find similar past threats.

## [1.1.0] - 2026-02-01

### Added
- **Cloudflare Turnstile**: Integrated CAPTCHA protection for the scan endpoint.
- **AI Persona**: "Sentinel AI" implemented with Google Gemini 1.5 Flash.
- **Docker Support**: Added `docker-compose.yml` and `Dockerfile` for easy deployment.

## [1.0.0] - 2026-01-20

### Initial Release
- Basic URL scanning with Random Forest (ML) model.
- React Frontend (Vite) with basic Reporting UI.
- FastAPI Backend with Async SQLModel usage.
