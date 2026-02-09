# Build-time Versioning

Version info is generated at build time from Git and injected via env vars.

## Variables

- **VITE_APP_VERSION** – Latest git tag (e.g. `v1.2.0`), or `0.0.0` if no tag.
- **VITE_COMMIT_HASH** – Short git SHA (e.g. `a1b2c3d`), or `dev` if not a git repo.
- **VITE_BUILD_TIME** – Build timestamp (ISO).

## How to test locally

1. **From repo root (recommended):**
   ```bash
   cd frontend
   npm run version:generate
   npm run dev
   ```
   Or in one go: `npm run dev` (script runs automatically).

2. **Check generated env:**
   - Open `frontend/.env.local` (and/or `.env.production.local`).
   - You should see `VITE_APP_VERSION=...`, `VITE_COMMIT_HASH=...`, `VITE_BUILD_TIME=...`.

3. **Check UI:**
   - Footer shows **Model &lt;version&gt; (&lt;commit&gt;)**.
   - Hover the badge to see **Built at: &lt;ISO time&gt;**.

4. **Without git / no tag:**
   - Run from a non-git folder or before any tag: version will be `0.0.0`, commit `dev`.
   - Script does not fail; it uses these defaults.

## CI/CD (GitHub Actions)

The script runs `git describe --tags` and `git rev-parse --short HEAD`. In CI, **tags are not fetched by default**.

- Use **`fetch-depth: 0`** in `actions/checkout` so tags (and full history) are available:
  ```yaml
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0
  ```
- Then `npm run build` in the frontend will see the correct tag and commit and embed them in the app.
