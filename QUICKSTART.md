# Quick Start Guide - Phishing Detector

Get up and running in 5 minutes!

## Prerequisites

- Python 3.9 or higher installed
- Terminal/Command Prompt

## 1️⃣ Clone or Download Project

```bash
# If using Git
git clone <your-repo-url>
cd phishing-detector

# Or download and extract ZIP file
```

## 2️⃣ Run Startup Script

### Windows

Open PowerShell in the project directory:

```powershell
# Make sure you're in the project root
cd phishing-detector

# Run the startup script
.\start.ps1
```

### Linux / macOS

Open Terminal in the project directory:

```bash
# Make script executable
chmod +x start.sh

# Run the startup script
./start.sh
```

That's it! The script will:
- ✅ Create virtual environment
- ✅ Install dependencies
- ✅ Train ML model
- ✅ Initialize database
- ✅ Start the server

## 3️⃣ Access the Application

Once the server is running:

- **API Server:** http://localhost:8000
- **API Documentation:** http://localhost:8000/docs
- **Health Check:** http://localhost:8000/health

## 4️⃣ Test the API

### Option 1: Use the Web Interface

Open http://localhost:8000/docs in your browser to test endpoints interactively.

### Option 2: Use curl

```bash
# Check health
curl http://localhost:8000/health

# Scan a URL
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://www.google.com"}'
```

### Option 3: Run Automated Tests

Open a new terminal:

```bash
# Windows
.venv\Scripts\activate
python scripts\test_api.py

# Linux/macOS
source .venv/bin/activate
python scripts/test_api.py
```

## 5️⃣ Connect Frontend

If you have the React frontend:

```bash
cd frontend
npm install

# Create .env file
echo "VITE_API_URL=http://localhost:8000" > .env

# Start frontend
npm run dev
```

Frontend will be available at: http://localhost:5173

## 🔧 Configuration (Optional)

The default configuration uses SQLite database. To change settings:

1. Edit `.env` file in the project root
2. Restart the server

### Switch to MySQL

```env
DB_TYPE=mysql
MYSQL_USER=your_user
MYSQL_PASSWORD=your_password
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_DATABASE=phishing_detector
```

### Switch to PostgreSQL

```env
DB_TYPE=postgresql
POSTGRES_USER=your_user
POSTGRES_PASSWORD=your_password
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DATABASE=phishing_detector
```

## 🛑 Stop the Server

Press `Ctrl+C` in the terminal where the server is running.

## 🔄 Restart the Server

Just run the startup script again:

```bash
# Windows
.\start.ps1

# Linux/macOS
./start.sh
```

## ❓ Troubleshooting

### "Python not found"

Install Python 3.9+ from https://www.python.org/downloads/

### "Port 8000 already in use"

Stop the process using port 8000:

```bash
# Windows
netstat -ano | findstr :8000
taskkill /PID <process_id> /F

# Linux/macOS
lsof -ti:8000 | xargs kill -9
```

### "Module not found" errors

Reinstall dependencies:

```bash
# Activate virtual environment first
# Windows: .venv\Scripts\activate
# Linux: source .venv/bin/activate

pip install -r requirements.txt
```

### Database errors

Reset the database:

```bash
python scripts/init_db.py reset
```

## 📚 Next Steps

- Read [README.md](README.md) for detailed documentation
- Read [DEPLOYMENT.md](DEPLOYMENT.md) for production deployment
- Explore API at http://localhost:8000/docs
- Test all endpoints with `python scripts/test_api.py`

## 🎉 You're Ready!

Your Phishing Detector API is now running locally. Happy coding! 🚀
