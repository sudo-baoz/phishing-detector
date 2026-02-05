# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.1.1]: https://github.com/sudo-baoz/phishing-detector/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/sudo-baoz/phishing-detector/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/sudo-baoz/phishing-detector/releases/tag/v1.0.0
