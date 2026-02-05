# Contributing Guide

Thank you for your interest in improving **Phishing Detector**!

## 1. Development Setup

### Backend (Python)
We use `python-3.11` and `venv`.

```bash
# Setup
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run
uvicorn app.main:app --reload
```

### Frontend (React)
We use Vite.

```bash
cd frontend
npm install
npm run dev
```

## 2. Project Structure

*   `app/services/deep_scan.py`: Contains heuristic logic (SSL, Entropy).
*   `app/services/ai_engine.py`: Google Gemini integration.
*   `frontend/src/locales/`: Translation files.

## 3. Adding Translations (i18n)

We support **English** (`en`) and **Vietnamese** (`vi`).
To add a new language or update text:

1.  Edit `frontend/src/locales/en.json` (Source of Truth).
2.  Edit `frontend/src/locales/vi.json`.
3.  Use the key in React components:
    ```javascript
    const { t } = useTranslation();
    return <h1>{t('analysis.title')}</h1>;
    ```

## 4. Code Style

*   **Python**: Follow PEP 8. Add type hints (`typing`).
*   **JavaScript**: Use ES6+ features. Airbnb style guide preferred.
*   **Headers**: All files must start with:
    ```
    Phishing Detector - AI-Powered Threat Intelligence System
    Copyright (c) 2026 BaoZ
    ```

## 5. Pull Requests

1.  Fork the repo.
2.  Create a branch (`feature/my-feature`).
3.  Commit changes.
4.  Open a PR describing your changes.
