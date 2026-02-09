# SaaS Fix Checklist – 5 Steps to a Stable Server

Run these in order so auth and frontend work.

---

## 1. Install `python-multipart`

`POST /auth/token` uses **OAuth2PasswordRequestForm**, which requires form data parsing.

```bash
pip install python-multipart
```

Without it, FastAPI can return **500** or **422** when parsing the login body.

---

## 2. Set `DEBUG=true` and CORS in `.env`

The app only adds **CORSMiddleware** when `DEBUG=true`. If the frontend runs on another origin (e.g. `http://localhost:5173`), CORS must be enabled.

In `.env`:

```env
DEBUG=true
CORS_ORIGINS=http://localhost:5173,http://localhost:5174,http://127.0.0.1:5173
```

So the backend allows the dev server origin. For production, use Nginx (or similar) for CORS and set `DEBUG=false` if desired.

---

## 3. Set JWT env vars in `.env`

Auth uses `JWT_SECRET` and `JWT_ALGORITHM` from `app.config`. Set at least:

```env
JWT_SECRET=your-long-random-secret-at-least-32-chars
JWT_ALGORITHM=HS256
```

Fallback in code is `JWT_SECRET=change-me-in-production-cybersentinel` and `JWT_ALGORITHM=HS256`; override in production.

---

## 4. Create DB tables (run server once)

Tables are created on startup via `init_db()` (which calls `Base.metadata.create_all`). No separate migration needed for a fresh install.

```bash
# From project root
python -m uvicorn app.main:app --reload
```

Stop after you see something like: `[OK] Database initialized successfully` and `[Auth] Default admin created` (or “already exists”). Then the `users` table exists and the default admin is there.

---

## 5. Point frontend at the API

In the frontend `.env` (or `.env.local`):

```env
VITE_API_URL=http://127.0.0.1:8000
```

So login and other requests go to your FastAPI server. Build/restart the frontend after changing this.

---

## Quick verification

- **Backend:** `GET http://127.0.0.1:8000/health` → 200.
- **Login:** From the frontend, use **Login** with `admin@cybersentinel.com` / `password123`. If it fails, the UI should show the backend message (e.g. “Invalid email or password”), not only “Failed to fetch”.
- **Navbar:** “About” and Language Switcher use theme-aware text (e.g. light: `text-gray-700` / `hover:text-blue-600`; dark: `text-gray-200` / `hover:text-blue-400`), and the nav bar uses `z-[50]` so it stays on top.
