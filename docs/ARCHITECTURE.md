# System Architecture

## Overview

**Phishing Detector** is a state-of-the-art Threat Intelligence System that combines deterministic forensic analysis with probabilistic AI modeling. It is designed to detect sophisticated phishing attacks, including zero-day threats, obfuscated code, and brand impersonation.

![System Architecture](https://mermaid.ink/img/pako:eNptk01v2zAMhv8KoVMO863Z3g4Dut2GAgW67bAdincxoms7sS1FlpOkMQz996HsJmn70A0BBEs--fCRH-lKq6wixfK9_FiRVdIVvFda-x1aK0_QOXB9B969A-c6aN_vQRv0j_1Ovyf9B_2e02_f910H_YF7H44G9n04HrpO0O846H9w78Mh_O_dO3B81zW_T9o4sFzS8oVWX1R1VZVbWpXk_JCWdVPWRSM5Z23W8J2W9VnL5rIqK86L8rIsK7oWH2hVbWl907Ki2TKa84yW1Yr_yUf6zBnt6Y_qE3P6hK90QWuaL3h5QdNN1db8nK-b_IrmfEPz11K-0vJVc5ZvyvoL7SjndFO80_KaFk1VlfyDli_5uinn4v0aP9OyutCcl231npaM0bzi60q-bMv3VfWBFvV5u-Y5zfl5VVWbUj4WnNFF_rE880_b35aWtfioRcv4DznN-bpY8TWty3Vd8lW5pvm82G5peV4VfM0f6F3FmEcsYwEhiBAiCGLEEcGIEIwxxpRSwpRgHBFKMEYYsogFjFnIGcOEc0oIo4RxRpgQ-HuEEeGE8IBFjHhIBKGUBUwY91hIIggNmAxhwALGCQsZ85iFMBLCkBDOQog8FhkLAvZfhBEnPGAhIZT7LGIhYfw_YYQ9FhJGCCFf8_0V_3-j1X-j3X-j_X_jo3_j43_jE3_jU3_jM3_jc3_j538B5u6b_Q)

## Core Components

The system is composed of two main layers: the **FastAPI Backend** and the **React Frontend**.

### 1. Backend Layer (Python/FastAPI)

The backend exposes a REST API that orchestrates the scanning process. It follows a Service-Oriented Architecture (SOA) where each module handles a specific aspect of threat detection.

#### Key Services (`app/services/`)

*   **Request & Orchestration (`scan.py`)**:
    *   Accepts user URLs.
    *   Validates Turnstile Cloudflare tokens.
    *   Orchestrates parallel execution of OSINT, Deep Scan, and RAG services.

*   **Deep Scanner (`deep_scan.py`)**:
    *   **SSL Analysis**: Checks certificate age (< 48h risk), issuer, and validity.
    *   **Digital Forensics**: Calculates Shannon Entropy of JavaScript code to detect obfuscation (Entropy > 5.5).
    *   **Redirect Tracing**: Follows HTTP redirect chains to uncover hidden destinations (e.g., bit.ly -> phishing).
    *   **Keyword Detection**: Scans for suspicious keywords (`paypal`, `login`, `secure`) in URLs.

*   **Semantic RAG (`knowledge_base.py`)**:
    *   **Vector Database**: Uses ChromaDB (local persistence) to store embeddings of known phishing kits (from PhishTank).
    *   **Embeddings**: Uses `sentence-transformers/all-MiniLM-L6-v2` to vectorize input URLs.
    *   **Search**: Performs Cosine Similarity search to find "look-alike" or identical threats.

*   **OSINT Engine (`osint.py`)**:
    *   **Whois**: Fetches domain registrar, creation date, and abuse contact.
    *   **DNS**: Resolves A, MX, NS records.
    *   **GeoIP**: Locates server hosting country.

*   **AI Engine (`ai_engine.py` & `chatbot.py`)**:
    *   **Generative Model**: Google Gemini Pro.
    *   **Prompt Engineering**: dynamically builds prompts injecting OSINT + Deep Scan + RAG data.
    *   **Sentinel AI**: A specialized persona ("Sentinel") that answers follow-up questions in strict Vietnamese or English.

*   **Response Builder (`response_builder.py`)**:
    *   Aggregates data from all services.
    *   Calculates the final **Risk Score (0-100)** based on weighted heuristics.
    *   Generates the narrative conclusion ("This site is likely phishing because...").

### 2. Frontend Layer (React/Vite)

The frontend is a modern, responsive Single Page Application (SPA) designed for analysts.

*   **Tech Stack**: React 19, Tailwind CSS, Framer Motion, Lucide Icons.
*   **Key Components**:
    *   `Scanner`: Main input interface with Turnstile protection.
    *   `AnalysisReport`: Visualizes results (Circular Gauge, Threat Intelligence Cards, Technical Details).
    *   `ChatWidget`: Interaction interface for Sentinel AI.
    *   `LanguageSwitcher`: Toggles between English (`en`) and Vietnamese (`vi`) using `i18next`.

---

## Data Flow

1.  **User Submission**: User submits URL -> Frontend normalizes it -> Calls `POST /api/scan`.
2.  **Parallel Execution**:
    *   `OSINT Service` queries Whois/DNS servers.
    *   `Deep Scanner` fetches page content, checks SSL, traces redirects.
    *   `RAG Service` embeds URL and queries ChromaDB.
3.  **Aggregation**: Backend combines all findings.
4.  **AI Analysis**:
    *   Prompt created: "Analyze this URL. Context: SSL is 2 hours old, Entropy is 6.1. Is it phishing?"
    *   Gemini returns verdict and explanation.
5.  **Scoring**:
    *   Base Score (from AI).
    *   Heuristic Boosts: +30 for Fresh SSL, +25 for Obfuscation, +25 for Keywords.
6.  **Response**: JSON payload sent to Frontend for rendering.

## Fault Tolerance & Graceful Degradation

### API Quota Handling

The system is designed to continue functioning even when external AI services become unavailable:

*   **Quota Detection**: The `GodModeAnalyzer` class detects rate limit errors from Google Gemini API (429, quota exceeded, resource exhausted).
*   **Automatic Disable**: When quota is hit, the service sets `_quota_exceeded = True` and stops making API calls.
*   **Fallback Response**: Returns `QUOTA_EXCEEDED_RESPONSE` with bilingual warning:
    *   🇻🇳 "Tính năng phân tích AI tạm thời không khả dụng do giới hạn API"
    *   🇺🇸 "AI analysis feature temporarily unavailable due to API limits"
*   **ML Continues**: The ML model (`ai_engine.py`) and heuristic analysis continue to work independently.
*   **Frontend Display**: The God Mode section turns amber/yellow with a clear warning instead of crashing.

### Service Isolation

Each service is designed to fail gracefully without crashing the entire scan:

*   **VisionScanner**: Returns fallback `{'evasion': {}, 'connections': {}}` if browser unavailable.
*   **ReportGenerator**: Validates all inputs with null-safety before processing.
*   **Semaphore Throttling**: Max 3 concurrent scans to prevent resource exhaustion.

## Directory Structure

```
├── app/
│   ├── main.py              # App entry point
│   ├── core/
│   │   └── logger.py        # Smart "Quiet Mode" logging
│   ├── services/            # Core logic
│   │   ├── deep_scan.py     # Heuristics
│   │   ├── ai_engine.py     # Gemini Integration
│   │   ├── chat_agent.py    # God Mode AI (quota-aware)
│   │   ├── knowledge_base.py# RAG / ChromaDB
│   │   ├── vision_scanner.py# Browser forensics (graceful failure)
│   │   └── ...
│   ├── routers/             # API Endpoints
│   └── schemas/             # Pydantic Models
├── frontend/
│   ├── src/
│   │   ├── components/      # UI Components
│   │   ├── services/        # API Client
│   │   └── locales/         # i18n JSON files
│   └── vite.config.js
└── scripts/                 # Utility scripts (Ingestion, Training)
```
