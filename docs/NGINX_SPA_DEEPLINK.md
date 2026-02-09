# Nginx: SPA Deep Linking & API Proxy

## Problem

- Direct links (e.g. `https://ai.baodarius.me/share/3`) or refresh return **404** because Nginx looks for a file at `/share/3` and doesn't find it. The React app (client-side routes) only works when the initial request serves `index.html`.

## Fix: SPA Fallback

Serve `index.html` for any path that isn't a real file. Put this in your **server** block (or in the `location /` that serves the React build).

### 1. Where to put it

- **If you serve the SPA from the root:** inside the same server block that has `server_name ai.baodarius.me;`, replace or add a `location /` block.
- **Typical layout:** one `location /` for the SPA (with `try_files`), and one `location /api/` that proxies to FastAPI.

### 2. Recommended configuration block

```nginx
# Root path: serve React SPA (allow deep links)
location / {
    root   /www/wwwroot/phishing-detector/dist;   # or your actual build folder
    index  index.html index.htm;
    try_files $uri $uri/ /index.html;
}

# API: proxy to FastAPI backend (so /api/share/3 hits the backend)
location /api/ {
    proxy_pass http://127.0.0.1:8000/;           # trailing slash strips /api
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

- **`try_files $uri $uri/ /index.html`**  
  Tries, in order: file for `$uri`, then directory `$uri/`, then **`/index.html`**. So `/share/3` returns `index.html`, React loads and shows the share page.

- **`root`**  
  Use the real path to your built frontend (e.g. `frontend/dist` or `dist`). Adjust `root` if your build output is elsewhere.

- **`location /api/`**  
  With `proxy_pass http://127.0.0.1:8000/;`, a request to `https://ai.baodarius.me/api/share/3` is sent to the backend as `http://127.0.0.1:8000/share/3`. So the backend route stays **GET /share/{scan_id}**; no prefix in FastAPI.

### 3. Frontend API base URL

Set the frontend env so it calls the API under `/api`:

- **Production:** `VITE_API_URL=https://ai.baodarius.me/api`  
  Then the app will request `https://ai.baodarius.me/api/share/3`, which Nginx proxies to the backend.

After changing Nginx config, run `nginx -t` then `nginx -s reload` (or your server’s reload command).
