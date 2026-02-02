# 🔒 Security Best Practices for GitHub

## ⚠️ **NEVER Commit These Files**

The following files contain sensitive information and should **NEVER** be committed to GitHub:

### 🚫 **Blocked by .gitignore:**
- `.env` (backend environment variables)
- `frontend/.env` (frontend environment variables)
- `.env.local`
- `*.db` (databases with user data)
- `models/*.pkl` (trained ML models may contain training data)
- `app.log` (may contain request logs)

---

## ✅ **What IS Safe to Commit**

### Safe Files:
- `.env.example` (templates with placeholder values)
- `nginx-cors.conf` (uses `YOUR_DOMAIN` placeholders)
- Source code (`.py`, `.js`, `.jsx`)
- Documentation (`.md` files)
- Configuration templates

---

## 🔐 **Sensitive Data Checklist**

Before pushing to GitHub, verify:

- [ ] `.env` is in `.gitignore`
- [ ] No API keys in code
- [ ] No real domains hardcoded
- [ ] No database credentials
- [ ] No Cloudflare secret keys
- [ ] No Gemini API keys
- [ ] `frontend/.env` gitignored

---

## 🛡️ **Environment Variable Strategy**

### Backend `.env` (DO NOT COMMIT):
```env
# Real production values (KEEP SECRET)
GEMINI_API_KEY=AIzaSy...REAL_KEY_HERE
CLOUDFLARE_SECRET_KEY=0x4AAAA...REAL_SECRET
CORS_ORIGINS=https://myfrontend.com,https://api.myfrontend.com
DB_PASSWORD=real_secure_password
```

### `.env.example` (Safe to commit):
```env
# Placeholder values for documentation
GEMINI_API_KEY=your_gemini_api_key_here
CLOUDFLARE_SECRET_KEY=your_cloudflare_secret_here
CORS_ORIGINS=https://yourfrontend.com,http://localhost:5173
DB_PASSWORD=your_db_password
```

---

## 📝 **Documentation Domain Strategy**

### ❌ Don't use:
```markdown
Deploy to: https://ai.baodarius.me
API URL: https://api.baodarius.me
```

### ✅ Use instead:
```markdown
Deploy to: https://your-frontend.vercel.app
API URL: https://api.example.com
```

---

## 🔍 **Pre-Commit Checklist**

Run before `git push`:

```bash
# 1. Check for exposed secrets
git diff | grep -i "api.*key\|secret\|password"

# 2. Verify .env is ignored
git status | grep ".env"  # Should show nothing!

# 3. Check .gitignore
cat .gitignore | grep ".env"  # Should see .env entries

# 4. Scan for real domains
git diff | grep -i "baodarius.me\|real-domain.com"
```

---

## 🚨 **Already Committed Secrets?**

If you accidentally committed sensitive data:

### Option 1: Remove from last commit
```bash
git reset --soft HEAD~1
# Remove sensitive files
# Add them to .gitignore
git add .gitignore
git commit -m "Add security improvements"
```

### Option 2: Remove from history (use with caution)
```bash
# Remove file from all history
git filter-branch --index-filter \
  "git rm -rf --cached --ignore-unmatch .env" HEAD

# Force push (WARNING: Rewrites history)
git push origin --force --all
```

### Option 3: Rotate all secrets
1. Revoke all exposed API keys immediately
2. Generate new keys
3. Update `.env` with new secrets
4. Remove old secrets from git history

---

## 📋 **GitHub Repository Setup**

### 1. Create `.env.example` templates:
```bash
# Backend
cp .env .env.example
# Then manually replace all real values with placeholders

# Frontend
cp frontend/.env frontend/.env.example
# Same process
```

### 2. Update README with setup instructions:
```markdown
## Environment Setup

1. Copy environment templates:
   ```bash
   cp .env.example .env
   cp frontend/.env.example frontend/.env
   ```

2. Edit `.env` files with your actual values
3. Never commit `.env` files to git
```

### 3. Add GitHub Secrets (for CI/CD):
- Go to: Repository → Settings → Secrets and variables → Actions
- Add secrets:
  - `GEMINI_API_KEY`
  - `CLOUDFLARE_SECRET_KEY`
  - `DATABASE_URL`

---

## ✅ **Files Ready for GitHub**

After these changes, your repository is safe to push publicly:

**Safe:**
- ✅ Source code (with no hardcoded secrets)
- ✅ `.env.example` (placeholder values only)
- ✅ `nginx-cors.conf` (generic domains)
- ✅ Documentation with example.com domains
- ✅ `.gitignore` (comprehensive)

**Blocked:**
- 🚫 `.env` (gitignored)
- 🚫 `frontend/.env` (gitignored)
- 🚫 `*.db` files (gitignored)
- 🚫 `app.log` (gitignored)

---

## 🎯 **Quick Verification**

Before pushing:
```bash
# Should return ONLY .env.example
git ls-files | grep "\.env"

# Should return nothing (404)
cat .env 2>&1 | head -n 1
```

---

**Your repository is now secure for public GitHub hosting!** 🔐
