# Changelog

All notable changes to this project will be documented in this file.

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
- Phishing URL detector với ML model
- Frontend React với giao diện mobile-first
- Backend FastAPI
- Chat widget hỗ trợ
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
