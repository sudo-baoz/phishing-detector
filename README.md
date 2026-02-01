# Phishing URL Detection API

🛡️ FastAPI-based REST API for detecting phishing URLs using machine learning.

## ✨ Features

- 🔍 **Real-time URL Scanning** - Analyze URLs for phishing threats
- 🤖 **Machine Learning Detection** - RandomForest classifier with 12 features
- 📊 **Confidence Scoring** - Get probability scores for predictions
- 🗄️ **Multi-Database Support** - MySQL, PostgreSQL, or SQLite
- 👤 **User Authentication** - Register and login with secure password hashing
- 📝 **Scan History** - Track all scanned URLs with timestamps
- 🚀 **Production Ready** - Async support, logging, health checks
- 📚 **Interactive API Docs** - Automatic OpenAPI/Swagger documentation

## 📁 Project Structure

```
phishing-detector/
├── app/                     # FastAPI application
│   ├── main.py             # Application entry point with ML model loading
│   ├── config.py           # Settings configuration (Pydantic)
│   ├── database.py         # Async database connection & pooling
│   ├── models/             # SQLAlchemy models
│   │   ├── user.py         # User model
│   │   └── scan_history.py # Scan history model
│   ├── routers/            # API endpoints
│   │   ├── health.py       # Health check endpoints
│   │   ├── scan.py         # URL scanning endpoints
│   │   └── auth.py         # Authentication endpoints
│   └── schemas/            # Pydantic schemas
│       ├── user.py         # User schemas
│       └── scan.py         # Scan schemas
├── frontend/               # React frontend
│   └── src/services/
│       └── api.js          # Axios API service with interceptors
├── scripts/                # Utility scripts
│   ├── init_db.py         # Database initialization
│   ├── model_train.py     # ML model training script
│   └── test_api.py        # API testing script
├── models/                 # Trained ML models
│   ├── phishing_model.pkl  # Trained RandomForest model
│   └── .gitkeep
├── database/               # Database schemas
│   └── schema.sql          # MySQL schema
├── logs/                   # Application logs
│   └── app.log            # Main application log
├── requirements.txt        # Python dependencies
├── .env.example           # Environment template
├── .env                   # Environment variables
└── README.md
```

## 🚀 Quick Start

1. **Tạo virtual environment:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

2. **Cài đặt dependencies:**
```bash
pip install -r requirements.txt
```

3. **Cấu hình .env:**
```bash
# Mặc định dùng SQLite, không cần thay đổi gì
```

4. **Train ML model:**
```bash
python scripts/model_train.py
```

5. **Khởi tạo database:**
```bash
python scripts/init_db.py
```

6. **Chạy server:**
```bash
uvicorn app.main:app --reload --port 8000
```

7. **Chạy frontend:**
```bash
cd frontend
npm install
npm run dev
```

## 🗄️ Database Configuration

Supports **MySQL**, **PostgreSQL**, and **SQLite**. Configure in `.env`:

```env
# SQLite (Default - easiest for development)
DB_TYPE=sqlite
SQLITE_DB=phishing.db

# MySQL (Recommended for production)
DB_TYPE=mysql
MYSQL_USER=phishing_user
MYSQL_PASSWORD=your_secure_password
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_DATABASE=phishing_detector

# PostgreSQL
DB_TYPE=postgresql
POSTGRES_USER=phishing_user
POSTGRES_PASSWORD=your_secure_password
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DATABASE=phishing_detector

# CORS (for React frontend)
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
```

## 📡 API Endpoints

### Health & Info
- `GET /` - Root endpoint with API info
- `GET /health` - Health check
- `GET /health/db` - Database health check
- `GET /model/info` - ML model information
- `GET /docs` - Interactive API documentation (Swagger UI)
- `GET /redoc` - Alternative API documentation (ReDoc)

### Authentication
- `POST /auth/register` - Register new user
- `POST /auth/login` - Login and get access token
- `GET /auth/me` - Get current user info (requires auth)
- `POST /auth/logout` - Logout user

### URL Scanning
- `POST /scan` - Scan URL for phishing
- `GET /scan/history` - Get scan history (with pagination)
- `GET /scan/{scan_id}` - Get specific scan result
- `DELETE /scan/{scan_id}` - Delete scan record

## 🧪 Testing

Run automated tests:
```bash
# Make sure server is running first
python -m uvicorn app.main:app --port 8000

# In another terminal
python scripts/test_api.py
```

Manual testing with curl:
```bash
# Health check
curl http://localhost:8000/health

# Register user
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass123"}'

# Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass123"}'

# Scan URL
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://www.google.com"}'

# Get scan history
curl http://localhost:8000/scan/history?limit=10
```

## 🔧 Scripts

**Database:**
```bash
python scripts/init_db.py          # Tạo tables
python scripts/init_db.py reset    # Reset database
```

**ML Model:**
```bash
python scripts/model_train.py      # Train model
```

**Testing:**
```bash
python scripts/test_api.py         # Test API
```

## 📝 License

MIT
