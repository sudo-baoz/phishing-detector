# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.0] - 2026-02-06

### 🌐 i18n Sync, Navbar & Toolbox Redesign, Backend Fix

This release fixes backend breach-check crash, centralizes frontend text in translations (en/vi), redesigns the Navbar and Security Toolbox, adds a professional About page with contact info, and makes the Ethics & Safety Policy modal fully bilingual.

#### Fixed

- **Backend – Breach check crash** ([app/routers/tools.py](app/routers/tools.py)):
  - `AttributeError: 'list' object has no attribute 'get'`: XposedOrNot API returns breaches as a **list of lists** (e.g. `[["BreachName", "Desc..."], ...]`), but the code treated each item as a dict.
  - Breach parsing now supports list items (`b[0]` as name), dict fallback (`b.get("name","Name")`), and string fallback; uses `data.get("Breaches", [])` (with fallbacks). Returns `{ status, breaches, count }` correctly.

- **Frontend – Language Switcher overlap**:
  - Language Switcher was fixed in the corner and overlapped by the sticky Navbar. It is now **integrated inside the Navbar** (right section) with an `embedded` prop so it no longer uses fixed positioning.

- **Frontend – Ethics & Safety Policy only in English**:
  - Ethics modal (Navbar and Scanner footer) now uses **translations (en/vi)**. Added `ethics` section in [frontend/src/constants/translations.js](frontend/src/constants/translations.js) (title, trigger, acknowledge, three policy cards in both languages).
  - [EthicsModal.jsx](frontend/src/components/EthicsModal.jsx) accepts optional `language` prop and falls back to `useTranslation()` so it stays in sync when opened from Navbar or Scanner.

#### Added

- **Centralized i18n** ([frontend/src/constants/translations.js](frontend/src/constants/translations.js)):
  - Single source of truth for **nav** (home, tools, about, ethics), **tools** (title, subtitle, breach/unshorten/pass title & description), **about** (title, subtitle, description, mission, contact, github_btn), **ethics** (modal title, trigger, acknowledge, three policy cards).
  - `getTranslations(lang)` helper; supports `vi` / `vi-VN` and falls back to `en`.

- **App global language** ([frontend/src/App.jsx](frontend/src/App.jsx)):
  - `useTranslation()` to derive `language` (`'vi'` when `i18n.language` starts with `vi`, else `'en'`). Passes `language` to `<Navbar />`, `<ToolsPage />`, `<AboutPage />` so all nav, toolbox, and about text switch with the Language Switcher.

- **Navbar redesign** ([frontend/src/components/Navbar.jsx](frontend/src/components/Navbar.jsx)):
  - **Layout:** Left (CyberSentinel logo), Center (Home, Tools, About), Right (Language Switcher, GitHub icon, Ethics button). Glassmorphism (`backdrop-blur-md`, `bg-black/60`, `border-white/10`), sticky `z-50`.
  - All labels from `translations[language].nav`. Mobile: hamburger + same right section (Lang, GitHub, Ethics). Ethics opens controlled EthicsModal with `hideTrigger`.

- **Security News Ticker – SOC style** ([frontend/src/components/tools/SecurityNewsTicker.jsx](frontend/src/components/tools/SecurityNewsTicker.jsx)):
  - Slim bar (`h-9`), `bg-black/80`, `border-b border-gray-800`. Left label: “🔴 THREAT INTEL:” with monospace/small text; scrolling ticker from `/tools/news`. Placed **globally** in [App.jsx](frontend/src/App.jsx) immediately below Navbar so it appears on every page.

- **Tools page – single-column layout** ([frontend/src/pages/ToolsPage.jsx](frontend/src/pages/ToolsPage.jsx)):
  - Replaced 3-column grid with **single-column list**. `max-w-4xl`; each tool (Breach Checker, Link Expander, Password Generator) in a **feature card** with icon, title, and description from `translations[language].tools`. Card style: `bg-gray-900/50`, `border-gray-700`, `rounded-xl`, `p-6`. Descriptions in Vietnamese/English as per translations.

- **About page revamp** ([frontend/src/pages/AboutPage.jsx](frontend/src/pages/AboutPage.jsx)):
  - **Hero:** Title, subtitle, and project description from `translations[language].about`.
  - **Mission** block with glassmorphism card and cyan border glow.
  - **Contact grid:** Author (Mai Quoc Bao), Email (mailto), Phone (tel), Telegram (@darius_baoz), GitHub (sudo-baoz/phishing-detector). Each row with lucide icon; “View on GitHub” / “Xem trên GitHub” button. All contact strings fixed; labels/buttons use i18n.

- **About route:** New route `/about` and “About” link in Navbar; [AboutPage.jsx](frontend/src/pages/AboutPage.jsx) placeholder replaced by the new design.

#### Changed

- **EthicsModal** ([frontend/src/components/EthicsModal.jsx](frontend/src/components/EthicsModal.jsx)):
  - Supports controlled usage (`open`, `onClose`, `hideTrigger`) for Navbar. When `language` is not passed, uses `useTranslation()` so Scanner footer modal also shows the current app language (en/vi).
  - Policy cards content moved from hardcoded `POLICY_CARDS` to `translations[language].ethics.cards`.

- **LanguageSwitcher** ([frontend/src/components/LanguageSwitcher.jsx](frontend/src/components/LanguageSwitcher.jsx)):
  - New `embedded` prop: when `true`, wrapper uses `relative flex` instead of `fixed` positioning so it fits inside the Navbar and no longer overlaps.

- **Tool components** (BreachChecker, LinkExpander, PasswordGenerator): Outer wrappers already `w-full bg-transparent`; ToolsPage provides card chrome and translated title/description from `translations[language].tools`.

#### Files Touched

- **Backend:** app/routers/tools.py
- **Frontend:** frontend/src/App.jsx, frontend/src/constants/translations.js (new), frontend/src/components/Navbar.jsx, frontend/src/components/EthicsModal.jsx, frontend/src/components/LanguageSwitcher.jsx, frontend/src/components/tools/SecurityNewsTicker.jsx, frontend/src/pages/ToolsPage.jsx, frontend/src/pages/AboutPage.jsx

---

## [1.6.2] - 2026-02-06

### 🔐 Turnstile, Captcha, Proxy, Legitimacy & Forensics

This release fixes Turnstile token reuse, adds multi-provider captcha (Strategy Pattern), proxy and legitimacy checks, OSINT-driven AI, XHR/Fetch exfiltration detection, and full-page dual-device screenshots with a tabbed forensics viewer.

#### Added

- **Captcha Solver (Strategy Pattern)**:
  - [app/services/solvers/base.py](app/services/solvers/base.py): Abstract `BaseCaptchaSolver` with `solve(page, sitekey, url)`.
  - [app/services/solvers/strategies.py](app/services/solvers/strategies.py): `StealthClickSolver` (free, Playwright click), `TwoCaptchaSolver`, `CapSolverSolver` (paid APIs).
  - [app/services/captcha_manager.py](app/services/captcha_manager.py): `CaptchaFactory.get_solver()` from `CAPTCHA_PROVIDER` (FREE / 2CAPTCHA / CAPSOLVER) and `CAPTCHA_API_KEY` in `.env`.
  - Vision scanner runs captcha bypass after soft-block detection; config in [app/config.py](app/config.py) and [.env.example](.env.example).

- **Legitimacy Checker (False Positive Fix)**:
  - [app/services/logic_analyzer.py](app/services/logic_analyzer.py): `OFFICIAL_BRANDS` (Google, Facebook, Microsoft, Netflix, PayPal, Amazon, Apple, etc.) and `LegitimacyChecker.is_authorized(url, detected_brand)`.
  - Scan flow and [app/services/response_builder.py](app/services/response_builder.py): When AI detects a brand, if the scanned URL is an official domain for that brand → verdict overridden to SAFE (e.g. google.com no longer flagged as impersonation).

- **OSINT for AI (Evidence-Based Verdicts)**:
  - [app/services/osint_analyzer.py](app/services/osint_analyzer.py): `DeepAnalyst.analyze_domain(url)` — WHOIS (age, registrar), SSL issuer, risk factors (new domain, DV cert).
  - [app/core/prompts.py](app/core/prompts.py): God Mode system prompt updated to use OSINT (domain age, SSL) with Scenario A/B (e.g. “Facebook look + 3-day domain + Let’s Encrypt → PHISHING”).
  - [app/services/chat_agent.py](app/services/chat_agent.py): Injects OSINT JSON into the analysis prompt before Gemini call.

- **Network Traffic Capture & Exfiltration Analysis**:
  - [app/services/vision_scanner.py](app/services/vision_scanner.py): Captures XHR/Fetch requests (URL, method, post_data) during scan; `result['network_logs']` and `result['network_analysis']`.
  - [app/services/network_forensics.py](app/services/network_forensics.py): `NetworkAnalyzer.analyze_traffic(requests_list)` — flags POSTs to Telegram bot, Discord webhooks, formsubmit.co, .php, etc. as HIGH RISK; `exfiltration_detected` and `high_risk_findings`; sets evasion when exfiltration is detected.

- **Full-Page Dual-Device Screenshots**:
  - [app/services/vision_scanner.py](app/services/vision_scanner.py): `_capture_single_device`, `_capture_dual_screenshots` — parallel desktop (1920×1080) and mobile (iPhone 13 Pro) full-page JPEG screenshots; `result['desktop_b64']`, `result['mobile_b64']` (data URI).
  - [ForensicsViewer.jsx](frontend/src/components/ForensicsViewer.jsx): Tabbed “🖥️ Desktop View” / “📱 Mobile View”; scrollable container (`max-h-[600px]`); mobile image centered with `max-w-sm`.
  - [AnalysisReport.jsx](frontend/src/components/AnalysisReport.jsx): Content Forensics section shows `<ForensicsViewer>` when `vision_analysis.desktop_b64` or `vision_analysis.mobile_b64` exist; fallback to legacy screenshot or “Screenshot Unavailable”.

- **Vision Scanner Proxy & Soft-Block Bypass**:
  - [app/config.py](app/config.py), [.env.example](.env.example): `PROXY_SERVER`, `PROXY_USERNAME`, `PROXY_PASSWORD` for residential proxy.
  - [app/services/vision_scanner.py](app/services/vision_scanner.py): Browser context uses proxy when set; on connection/timeout error, retries with direct connection (no proxy).
  - Soft-block detection (e.g. “Just a moment”, challenges.cloudflare.com) and smart wait-and-click bypass (iframe checkbox hover + click); 10s timeout then snapshot anyway.

#### Changed

- **Turnstile: Single Verification (No Double Consume)**:
  - [app/routers/scan.py](app/routers/scan.py): Removed duplicate Turnstile check; verification only inside stream `event_generator` and once at start of non-stream scan; `_perform_scan` no longer verifies (caller does once).
  - [app/security/turnstile.py](app/security/turnstile.py): `SKIP_TURNSTILE=true` in env skips verification (debug); docstring notes token is one-time-use.

- **Frontend Turnstile (Zombie Token Fix)**:
  - [Scanner.jsx](frontend/src/components/Scanner.jsx): Snapshot token then `setTurnstileToken(null)` and `setLoading(true)` at submit start; `key={widgetKey}` on `<Turnstile />` and `setWidgetKey(prev => prev + 1)` in `finally` to force remount; `handleTurnstileError` / `handleTurnstileExpire` also remount widget.
  - [api.js](frontend/src/services/api.js): On non-OK response, parses JSON body and sets `error.isTokenExpired` when backend returns `error: "token_expired"`.

- **CSP**: [frontend/index.html](frontend/index.html) — `script-src` extended with `https://static.cloudflareinsights.com` for Cloudflare analytics.

#### Files Touched

- **Backend:** app/config.py, app/security/turnstile.py, app/routers/scan.py, app/services/vision_scanner.py, app/services/response_builder.py, app/services/captcha_manager.py, app/services/solvers/base.py, app/services/solvers/strategies.py, app/services/logic_analyzer.py, app/services/osint_analyzer.py, app/services/network_forensics.py, app/services/chat_agent.py, app/core/prompts.py, .env.example
- **Frontend:** frontend/index.html, frontend/src/components/Scanner.jsx, ForensicsViewer.jsx (new), AnalysisReport.jsx, frontend/src/services/api.js

---

## [1.6.1] - 2026-02-06

### 🔬 Phishing Kit Fingerprinting & Cyberpunk UI

This release adds a **Phishing Kit Fingerprinting** module (forensic signatures) on the backend and three **cyberpunk-style** UI components for the scan result page.

#### Added

- **Phishing Kit Fingerprinting (Backend)**:
  - [app/core/kit_signatures.py](app/core/kit_signatures.py): Signature library for known phishing kits (16Shop, Z118, Kr3pto, NextGen, HeartBleed, Anti-Bot, Ex-Robots, Manuscrape, Dolphin, Ankos, Greatness, Yahoo, Phenix) — keywords and regex.
  - [app/services/kit_detector.py](app/services/kit_detector.py): `KitDetector.detect(html_content, url_path)` — matches HTML and URL path against signatures; returns `detected`, `kit_name`, `confidence` (Low/High), `matched_signatures`.
  - Integration in [app/routers/scan.py](app/routers/scan.py): Runs after deep scan when `raw_html` is available; passes `kit_result` into God Mode context and API response; boosts confidence and sets `threat_type` when a kit is detected.
  - [app/services/deep_scan.py](app/services/deep_scan.py): Returns `raw_html` (capped at 512KB) in scan result for Kit Detector and YARA.
  - Schema and response: [app/schemas/scan_new.py](app/schemas/scan_new.py) and [app/services/response_builder.py](app/services/response_builder.py) add `phishing_kit` field.

- **Cyberpunk UI Components (Frontend)**:
  - [ScanTerminal.jsx](frontend/src/components/ScanTerminal.jsx): **Live Terminal Loader** — replaces spinner while scanning; black background, green monospace text, fake log lines (God Mode, network, Z118/16Shop, redirect, SSL, RAG, YARA, OSINT…); `useEffect` + `setInterval`.
  - [TrustGauge.jsx](frontend/src/components/TrustGauge.jsx): **Trust Score Gauge** — semi-circle SVG gauge; color by score: 80–100 Safe (green/cyan), 50–79 Suspicious (orange/yellow), 0–49 High Risk (red/glow); no chart library.
  - [ForensicBadge.jsx](frontend/src/components/ForensicBadge.jsx): **Forensic Evidence Card** — only shown when `phishing_kit.detected === true`; yellow/black diagonal stripe border, Fingerprint icon, "Phishing Kit Detected" headline, kit name, confidence, matched signatures.

#### Changed

- [Scanner.jsx](frontend/src/components/Scanner.jsx): When `loading`, shows `<ScanTerminal />` in the result area; Scan button no longer shows spinner, only "Scanning...".
- [AnalysisReport.jsx](frontend/src/components/AnalysisReport.jsx): Replaced old circular gauge with `<TrustGauge score={score} />`; added `<ForensicBadge kit={phishing_kit} />` right below verdict; destructure `phishing_kit` from `data`.

#### Files Touched

- **Backend:** app/core/kit_signatures.py (new), app/services/kit_detector.py (new), app/services/deep_scan.py, app/routers/scan.py, app/services/response_builder.py, app/schemas/scan_new.py
- **Frontend:** frontend/src/components/ScanTerminal.jsx (new), TrustGauge.jsx (new), ForensicBadge.jsx (new), Scanner.jsx, AnalysisReport.jsx, tailwind.config.js (blink animation)

---

## [1.6.0] - 2026-02-06

### 🌐 Browser Console Fixes & Backend Venv Documentation

Release focused on fixing browser console errors (404, CSP) and documenting that the backend must run inside a virtual environment.

#### Fixed

- **404 / "normal?lang=auto" console error**:
  - Cause: Cloudflare Turnstile widget with placeholder/test key still calls Cloudflare and triggers 404.
  - Frontend **does not load** the Turnstile widget when site key is placeholder or empty (dev mode) → no request sent → 404 eliminated.

- **"script-src was not explicitly set" (CSP) warning**:
  - Added `Content-Security-Policy` meta in [index.html](frontend/index.html): allow `script-src` and `frame-src` for `https://challenges.cloudflare.com` so Turnstile loads correctly in production.

#### Added

- **Turnstile dev mode** ([Scanner.jsx](frontend/src/components/Scanner.jsx)):
  - When `VITE_CLOUDFLARE_SITE_KEY` is placeholder (`1x00000000000000000000AA`) or empty: shows "Dev mode — verification skipped", does not render widget; scan sends request without token (backend must have `TURNSTILE_ENABLED=false`).

- **README: Backend must run in venv**:
  - States that the backend **must** run inside a virtual environment; activation: Windows `.venv\Scripts\activate`, Linux/macOS `source .venv/bin/activate`.
  - Dev note: set `TURNSTILE_ENABLED=false` and use placeholder key to avoid 404/console noise; frontend skips the widget when key is placeholder.

#### Files Modified

- [frontend/index.html](frontend/index.html) — CSP meta for Turnstile
- [frontend/src/components/Scanner.jsx](frontend/src/components/Scanner.jsx) — Dev mode (hide Turnstile when placeholder key)
- [README.md](README.md) — Venv requirement, dev Turnstile note

---

## [1.5.3] - 2026-02-05

### ⚡ Performance Optimization & Timeout Fixes

This release fixes scan timeout issues and dramatically improves scan speed through parallel execution.

#### Fixed

- **Timeout Mismatch Issue**:
  - **Root Cause**: Frontend timeout (30s) was shorter than backend (60s), causing "Cannot reach server" errors while scan was still processing
  - Increased frontend axios timeout: 30s → 90s
  - Increased nginx proxy timeout: 60s → 90s
  - Better error message for timeout vs connection errors

- **Duplicate Deep Scan Removed** ([scan.py](app/routers/scan.py)):
  - Deep Analysis was running twice per scan (wasted ~10 seconds)
  - Removed duplicate code block in STEP 3.5

#### Changed

- **Parallel Execution Phase 1** - Network + AI + DeepScan:
  - Previously: Sequential (Network → AI → DeepScan) = ~15-20 seconds
  - Now: Parallel with `asyncio.gather()` = ~5-7 seconds
  - Saves **10-15 seconds** per scan

- **Parallel Execution Phase 2** - OSINT + Vision Scanner:
  - Previously: Sequential (OSINT → Vision) = ~10-15 seconds
  - Now: Parallel with `asyncio.gather()` = ~5-8 seconds
  - Saves **5-10 seconds** per scan

- **Total Performance Gain**: Scans now complete **15-25 seconds faster**

#### Files Modified

- [frontend/src/services/api.js](frontend/src/services/api.js) - Timeout 30s → 90s, better error handling
- [app/routers/scan.py](app/routers/scan.py) - Parallel execution, removed duplicate
- [nginx-cors.conf](nginx-cors.conf) - Proxy timeout 60s → 90s

---

## [1.5.2] - 2026-02-05

### 🛡️ API Quota Protection & Syntax Fix

This release adds graceful handling for AI API quota limits and fixes a critical syntax error.

#### Fixed

- **Report Generator Syntax Error** ([report_generator.py](app/services/report_generator.py)):
  - Fixed `SyntaxError: unexpected character after line continuation character`
  - Corrected malformed escape sequences in null-safety validation code
  - Server now starts correctly

#### Added

- **AI Quota Limit Handling** ([chat_agent.py](app/services/chat_agent.py)):
  - Automatic detection of quota/rate limit errors from Google Gemini API
  - When quota is exceeded, God Mode is disabled gracefully (no crashes)
  - Returns structured `QUOTA_EXCEEDED_RESPONSE` with bilingual message:
    - Vietnamese: "Tính năng phân tích AI tạm thời không khả dụng do giới hạn API"
    - English: "AI analysis feature temporarily unavailable due to API limits"
  - New helper functions: `is_quota_exceeded()`, `get_quota_status()`

- **Frontend Quota Warning** ([AnalysisReport.jsx](frontend/src/components/AnalysisReport.jsx)):
  - God Mode section turns amber/yellow when quota is exceeded
  - Shows warning icon with "AI Service Temporarily Unavailable" message
  - Displays recommendation to use ML/heuristics analysis instead
  - Normal purple styling when AI is working

---

## [1.5.1] - 2026-02-05

### 🔧 Backend Reliability & Stability Fixes

This release addresses critical stability issues including server hangs, crash protection, and log noise reduction.

#### Fixed

- **Report Generator Null Safety** ([report_generator.py](app/services/report_generator.py)):
  - Added defensive null checks to `_get_threat_summary()` and `_get_evidence_list()`
  - `generate_abuse_report()` now validates all inputs before processing
  - Returns graceful error dict instead of crashing when VisionScanner returns None
  - Fixed `'NoneType' object has no attribute 'lower'` crash

- **Turnstile Token Expiry Handling** ([turnstile.py](app/security/turnstile.py)):
  - `timeout-or-duplicate` error now returns `HTTP 400 Bad Request` (user error)
  - Clear message: "Captcha expired or already used. Please refresh the page and try again."
  - No longer logged as ERROR (was polluting logs) - now WARNING level
  - Prevents database session errors from cascading

- **Vision Scanner Graceful Failure** ([vision_scanner.py](app/services/vision_scanner.py)):
  - Browser launch wrapped in try/catch to handle missing system dependencies
  - Returns valid fallback object `{'evasion': {}, 'connections': {}, 'error': '...'}` on failure
  - Prevents crash propagation to ReportGenerator and other downstream services
  - Logs error but doesn't crash the entire scan

#### Changed

- **Smart Logging "Quiet Mode"** ([logger.py](app/core/logger.py)):
  - Root logger set to WARNING (blocks 3rd party INFO/DEBUG noise)
  - Silenced 30+ noisy loggers: httpx, chromadb, uvicorn.access, etc.
  - Application logs: `debug()` for routine, `warning()` for threats, `error()` for failures
  - Clean startup banner always visible via CRITICAL level

- **Request Throttling & Timeout** ([main.py](app/main.py), [scan.py](app/routers/scan.py)):
  - Global semaphore limits to 3 concurrent heavy scans
  - 60-second hard timeout per scan via `asyncio.wait_for()`
  - `503 Service Unavailable` when all slots taken (fail-fast)
  - `408 Request Timeout` when scan exceeds limit

---

## [1.5.0] - 2026-02-05

### 🎨 Frontend SOC Dashboard Upgrade

This release transforms the scan results view into a comprehensive Security Operations Center (SOC) dashboard with interactive visualizations.

#### Added

- **Zero-Day Alert Banner** ([AnalysisReport.jsx](frontend/src/components/AnalysisReport.jsx)):
  - Prominent flashing red banner with `animate-pulse` effect
  - Displays when `is_zeroday` or `threat_type === 'zero_day_phishing'`
  - AlertOctagon + Radiation icons for maximum visibility
  - Shows "CertStream" as detection source

- **God Mode AI Intelligence Section**:
  - Purple-themed card displaying `god_mode_analysis.summary`
  - Impersonation target badge (e.g., "Impersonating: PayPal")
  - Bullet-point list of AI-detected risk factors
  - Actionable recommendation display

- **YARA Pattern Matches Display**:
  - Shows triggered YARA rules as tags
  - Crypto wallet address detection display
  - Red-themed warning card

- **Visual Threat Graph Modal** ([ThreatGraphModal.jsx](frontend/src/components/ThreatGraphModal.jsx)):
  - Full-screen React Flow powered graph visualization
  - Color-coded nodes: User (blue), URL (red), IP (purple), ASN (amber), Registrar (green)
  - Animated edges with labels
  - Zoomable, pannable, with MiniMap and Controls
  - Legend bar for node type identification

- **Deep Forensics Accordion Sections**:
  - **Technical & Network Facts**: SSL age, domain age, hosting provider, server IP
  - Conditional coloring (red for <24h, yellow for <7 days, green otherwise)
  - Security gaps display (missing headers)
  - **Raw Analysis Data**: JSON viewer for expert debugging

- **Attack Chain Graph Button**:
  - Gradient cyan-to-blue button with hover effects
  - Shows node count badge
  - Opens ThreatGraphModal on click

#### Changed

- Enhanced icon imports from `lucide-react` (AlertOctagon, Target, ChevronDown, ChevronUp, Radiation, GitBranch, ShieldX)
- Added state management for accordion sections (`expandedSections`)
- Integrated all new backend SOC data fields into frontend

#### Dependencies

- Added `reactflow` for threat graph visualization (`npm install reactflow`)

---

## [1.4.0] - 2026-02-05

### 🏢 Enterprise SOC Platform (Backend)

This release adds enterprise-grade Security Operations Center features to the backend.

#### Added

- **Visual Threat Graph Builder** ([app/services/graph_builder.py](app/services/graph_builder.py)):
  - React Flow compatible output format with `nodes` and `edges` arrays
  - Node types: User, URL, IP, ASN, Registrar with distinct styling
  - Edge types: Redirect chains, hosting relationships, ASN/registrar links
  - Automatic position calculation for graph layout

- **YARA Rules Engine** ([app/services/yara_scanner.py](app/services/yara_scanner.py)):
  - 13+ detection rules covering:
    - Crypto wallet patterns (Bitcoin, Ethereum, Monero)
    - Phishing kit signatures (16shop, z118, Kr3pto, U-Admin, Ex-Robotos)
    - JavaScript obfuscation (packer, base64 eval, hex encoding)
    - Credential harvesters (form action patterns)
    - Anti-bot/Cloudflare detection
  - Fallback regex mode when yara-python unavailable

- **Automated Takedown Report Generator** ([app/services/report_generator.py](app/services/report_generator.py)):
  - Extracts registrar abuse email from WHOIS data
  - 20+ known registrar/hosting abuse emails database
  - Professional formatted abuse report with:
    - Unique Report ID and timestamp
    - Threat summary with evidence list
    - Formal takedown request language
  - Fallback recipient suggestions

- **SOC Integration in Scan Router** ([app/routers/scan.py](app/routers/scan.py)):
  - Added Step 3.9 with all 3 SOC features
  - Threat graph built for every scan
  - YARA scan runs on page HTML content
  - Abuse report auto-generated for confirmed phishing (≥75% confidence)

- **New Schema Fields** ([app/schemas/scan_new.py](app/schemas/scan_new.py)):
  - `threat_graph`: React Flow graph data
  - `yara_analysis`: YARA rule matches
  - `abuse_report`: Takedown report with recipient/subject/body

#### Dependencies

- Added `yara-python` to requirements.txt

---

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

## [1.2.1] - 2026-02-05

### Fixed
- **Deep Scan**: Resolved issue where sensitive keywords (paypal, login, secure...) were not detected in URL strings.
- **Reporting**: Fixed `Code Entropy` display showing as 0 in frontend analysis report.
- **Scoring**: Adjusted technical risk weighting to include keyword detection (+25 points).

## [1.2.0] - 2026-02-05

### Added
- **SOC Analyst Dashboard**: Redesigned UI with glassmorphism, dedicated sections for "Threat Intelligence", "Digital Forensics", and "Risk Factors".
- **Deep Tech Analysis**: Backend logic to calculate SSL Certificate Age, Code Entropy (Obfuscation detection), and Redirect Hops.
- **RAG Integration**: Visualization of similar phishing kits from Threat Intelligence database with % similarity match.
- **JSON Viewer**: "View Raw Data" toggle for security analysts to inspect the full API response payload.
- **Vietnamese Localization (i18n)**:
  - 100% UI translation (Analysis Report, Scanner, Chat).
  - Backend AI generation (Risk Factors & Conclusion) now supports the requested language.
  - Strict language enforcement for Chatbot (Sentinel AI speaks Vietnamese when selected).

### Changed
- **Score Visualization**: New circular gauge with color-coded risk levels (Critical/High/Medium/Low).
- **Frontend-Backend Sync**: `Scanner.jsx` now explicitly sends the selected language code (`vi`/`en`) to the API.
- **AI Logic**: Updated `chat_agent.py` to enforce language instructions in the System Prompt.

### Fixed
- **API 422 Error**: Fixed type mismatch for `scan_result_id` in Chat API.
- **Backend Crash**: Resolved `RecursionError` and `SyntaxError` in `scan.py` argument passing.
- **Frontend Crash**: Restored missing `useState` and `useEffect` imports in `AnalysisReport.jsx`.
- **Duplicate Keys**: Cleaned up `vi.json` and `en.json` localization files.

### Security
- **Strict Parsing**: Enhanced input validation for Chat API to prevent type confusion attacks.

---

## [1.1.1] - 2026-02-05

### Added
- **URL Normalization**: Auto-prepend `https://` for protocol-less URLs (frontend & backend)
- **Markdown Support**: AI chat messages now render with full Markdown formatting
  - Bold text, lists, code blocks, tables, blockquotes
  - Syntax highlighting for code with dark theme
  - GitHub Flavored Markdown (GFM) support via `remark-gfm`
- **Backend URL Validator**: Pydantic `@field_validator` for robust URL sanitization
- **License Headers**: GPL-3.0 copyright headers added to all source files (39 files)

### Changed
- **Scanner Input**: Changed from `type="url"` to `type="text"` for custom validation
- **Turnstile Widget**: Improved styling with dark theme, centered layout, and `min-h-[65px]`
- **ChatWidget**: Increased z-index to `z-60` to prevent overlap with language switcher
- **LanguageSwitcher**: Hidden on mobile (`hidden sm:flex`) to avoid UI conflicts
- **Close Button**: Enhanced with safe area padding and 44px touch target

### Fixed
- **Chatbot 422 Error**: Added missing `language` field to `SentinelChatRequest` schema
- **Mobile Chat Overlap**: Language switcher no longer covers chat close button
- **URL Validation**: Both frontend and backend now handle domains without protocols
- **Turnstile Styling**: Widget blends with glassmorphism UI instead of grey block
- **Invalid URL Handling**: Shows user-friendly error instead of API failure

### Documentation
- Updated `README.md` with GPL-3.0 license badge and sections
- Created `LICENSE_COMPLIANCE.md` summary document
- Removed `SETUP.md` (merged into README.md)

### Security
- All source files now include GPL-3.0 license headers
- URL sanitization prevents malformed input from reaching scanner

---

## [1.1.0] - 2026-02-05

### Added
- Mobile-first responsive design optimization across all components
- Full-screen chat widget on mobile devices with safe area support
- Matrix Rain background animation effect
- Tailwind v4 syntax support with modern gradient classes
- Touch-optimized UI with 44px minimum touch targets
- Safe area insets for iOS notched devices
- Smooth touch scrolling for mobile browsers
- Auto-prevent zoom on input focus for iOS

### Changed
- **Scanner Component**: Responsive text sizes (`text-2xl sm:text-3xl md:text-5xl lg:text-6xl`)
- **Scanner Component**: Mobile-optimized padding and spacing
- **AnalysisReport Component**: Responsive circular gauge sizing
- **AnalysisReport Component**: Mobile-friendly grid layouts with proper gaps
- **AnalysisReport Component**: Text overflow handling with `line-clamp`
- **ChatWidget Component**: Full-screen mode on mobile (`w-full h-full`)
- **ChatWidget Component**: Responsive button sizes (`w-12 h-12 sm:w-14 sm:h-14 md:w-16 md:h-16`)
- **LanguageSwitcher Component**: Adjusted z-index to prevent overlap with chat widget
- Updated all gradient classes from `bg-gradient-to-*` to `bg-linear-to-*` (Tailwind v4)
- Replaced `flex-shrink-0` with `shrink-0` for consistency
- Replaced `break-words` with `wrap-break-word` (Tailwind v4)

### Fixed
- Matrix Rain animation not working due to missing keyframe definitions
- Content Security Policy (CSP) warnings related to animations
- Debug console logs cluttering browser console
- Language switcher overlapping with chat widget header on mobile
- Input fields causing unwanted zoom on iOS devices
- Horizontal overflow issues on mobile viewports
- Duplicate flex classes in AnalysisReport component

### Performance
- Optimized animation performance with CSS keyframes
- Improved touch scrolling with `-webkit-overflow-scrolling: touch`
- Reduced console noise by removing debug statements

### UI/UX
- Enhanced mobile user experience with larger touch targets
- Better visual hierarchy on small screens
- Improved readability with responsive font sizes
- Smoother animations and transitions

---

## [1.0.0] - 2026-02-04

### Added
- Phishing URL detector with ML model
- React frontend with mobile-first UI
- FastAPI backend
- Chat widget support
- Scanner component
- Analysis Report component
- Cloudflare Turnstile integration
- Multi-language support (i18n)
- Real-time threat analysis
- AI-powered chat assistant

### Security
- Cloudflare Turnstile bot protection
- URL sanitization and validation
- Secure API communication

---

[1.3.0]: https://github.com/sudo-baoz/phishing-detector/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/sudo-baoz/phishing-detector/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/sudo-baoz/phishing-detector/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/sudo-baoz/phishing-detector/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/sudo-baoz/phishing-detector/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/sudo-baoz/phishing-detector/releases/tag/v1.0.0
