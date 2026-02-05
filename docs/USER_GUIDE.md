# User Guide

Welcome to **Phishing Detector**, your AI-powered companion for analyzing suspicious links. This guide helps you navigate the interface and understand the security reports.

## 1. Getting Started

### Accessing the Scanner
Navigate to `http://localhost:5173` (or your deployed domain) in your web browser. You will see the **Sentinel Scanner** interface.

### Scanning a URL
1.  **Enter URL**: Paste the suspicious link into the main input field (e.g., `http://verify-paypal-secure.com`).
2.  **Verify Humanity**: Click the "Cloudflare Turnstile" checkbox to prove you are human.
3.  **Start Scan**: Click the **"ANALYZE / QUÉT NGAY"** button.
    *   *Note: Deep Analysis takes 5-10 seconds as it performs real-time forensics.*

### Changing Language
Use the **Language Switcher** in the top-right corner to toggle between:
*   🇬🇧 **English (EN)**
*   🇻🇳 **Tiếng Việt (VI)**

## 2. Understanding the Report

Once the scan is complete, you will see a detailed **Analysis Report**.

### The Verdict (Risk Score)
The most important part is the **Risk Score** (0-100) displayed in the circular gauge.

*   🟢 **SAFE (0-20)**: No threats detected. The site is likely legitimate.
*   🟡 **SUSPICIOUS (21-65)**: Some indicators are concerning (e.g., fresh domain, HTTP only). Exercise caution.
*   🔴 **PHISHING (66-100)**: **DANGER!** High confidence of a phishing attack. Do not enter credentials.
*   🟣 **CRITICAL**: Known malware or blacklisted site.

### Threat Intelligence Cards
If the URL matches a known threat in our database (RAG), you will see a **Red Alert Card**:
*   **Target**: The brand being impersonated (e.g., "Facebook Users").
*   **Similarity**: How closely it matches known phishing kits (e.g., "98% Match").

### Technical Forensics (Deep Scan)
New in v1.2.0, this section provides "Under the Hood" metrics:
1.  **SSL Age**: How long ago the security certificate was created.
    *   *Warning*: < 48 hours is highly suspicious (Phishers create sites and abandon them quickly).
2.  **Code Entropy**: Measures the "randomness" of the website's code.
    *   *Score > 5.5*: Indicates **Obfuscation** (Hidden code) often used to hide malicious scripts.
3.  **Redirect Chain**: Shows the path the URL took.
    *   *Risk*: Multiple redirects (> 3 hops) or use of shorteners (bit.ly) to hide the final destination.

## 3. Using Sentinel AI Chatbot

The **Sentinel AI** assistant is always available in the bottom-right corner.

### Features
*   **Context Aware**: It knows the scan results you are looking at.
*   **Ask "Why?"**: You can ask *"Tại sao trang này bị đánh dấu là lừa đảo?"* and it will explain technical jargon in simple terms.
*   **Actionable Advice**: It provides steps on what to do if you accidentally clicked the link.

### Example Interactions
> **User**: "Is this site safe for online banking?"
> **Sentinel**: "No. I detected a fresh SSL certificate (2 hours old) and keywords 'secure-banking' in the URL. This is typical of a phishing attack targeting bank users."

## 4. Troubleshooting

*   **"Analysis Failed"**: Check your internet connection. Ensure the URL is valid (starts with `http` or `https`).
*   **"Turnstile Error"**: Refresh the page and try the CAPTCHA again.
*   **Wrong Language**: Toggle the language switch or ask the Chatbot to speak your language.
