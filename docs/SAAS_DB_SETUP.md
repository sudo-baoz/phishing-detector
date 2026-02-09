# CyberSentinel SaaS – Database Setup

## Dependencies

Backend already uses `sqlalchemy`, `python-jose`, `passlib`, `bcrypt` (see `requirements.txt`).

## Database creation (no Alembic)

The app uses **SQLAlchemy `create_all()`** on startup:

1. Set `DB_TYPE=sqlite` in `.env` (or keep your existing MySQL/PostgreSQL).
2. Run the app once; `init_db()` in `app/database.py` will create all tables:
   - `users` (with columns: id, email, username, password_hash, role, api_key, created_at)
   - `scan_history` (existing)
   - `scan_logs` (new: id, user_id, url, verdict, score, timestamp, full_result_json)

```bash
# From project root
python -m uvicorn app.main:app --reload
```

On first run, `create_default_admin()` creates:

- **Email:** `admin@cybersentinel.com`
- **Password:** `password123`
- **Role:** `admin`

Use these to log in at **POST /auth/token** (or the frontend Login).

## If you already have a database (migration)

If the `users` table already exists **without** `email`, `role`, or `api_key`:

### Option A – SQLite (add columns)

```sql
ALTER TABLE users ADD COLUMN email VARCHAR(255) UNIQUE;
ALTER TABLE users ADD COLUMN role VARCHAR(32) DEFAULT 'user';
ALTER TABLE users ADD COLUMN api_key VARCHAR(64) UNIQUE;
-- Optional: make username nullable if you use email as main login
-- ALTER TABLE users ... (depends on your SQLite version)
```

Then create the new table:

```sql
CREATE TABLE scan_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  url TEXT NOT NULL,
  verdict VARCHAR(64) NOT NULL,
  score REAL NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  full_result_json TEXT
);
CREATE INDEX ix_scan_logs_user_id ON scan_logs(user_id);
CREATE INDEX ix_scan_logs_timestamp ON scan_logs(timestamp);
```

### Option B – Fresh SQLite file

1. Back up existing `*.db` if needed.
2. Delete or rename the old DB file.
3. Start the app again so `init_db()` creates all tables from scratch.

## Verifying

- **Health:** `GET /health/db`
- **Login:** `POST /auth/token` with form body `username=admin@cybersentinel.com&password=password123`
- **Share:** After a scan, use the returned `share_id` in `GET /share/{share_id}`
