# dmarc-saas

Web-based SaaS wrapper for `dmarc-agent`, built with FastAPI + static HTML/Tailwind frontend.

## Project Structure

```text
backend/
  main.py
  scanner.py
  emailer.py
  models.py
  requirements.txt
  .env.example
frontend/
  index.html
  results.html
  assets/
    style.css
    app.js
requirements.txt
README.md
```

## Local Development

1. Create and activate a virtual environment.
```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies.
```bash
pip install -r requirements.txt
```

3. Configure environment variables.
```bash
cp backend/.env.example .env
# then edit .env
```

4. Run the backend.
```bash
uvicorn backend.main:app --reload
```

5. Open the app.
- Landing page: `http://127.0.0.1:8000/`
- Results page: `http://127.0.0.1:8000/results.html?scan_id=<id>`
- Health: `http://127.0.0.1:8000/health`

## Environment Variables

- `RESEND_API_KEY`
- `FROM_EMAIL`
- `SCAN_CACHE_TTL_SECONDS` (default `3600`)
- `ALLOWED_ORIGINS` (comma-separated, `*` for MVP)

## API Endpoints

- `POST /api/scan`
- `GET /api/scan/{scan_id}`
- `POST /api/scan/{scan_id}/report`
- `GET /health`

## Railway Deployment

1. Push this repo to GitHub.
2. In Railway, create a new project from the repo.
3. Start command (or `Procfile`):
```bash
uvicorn backend.main:app --host 0.0.0.0 --port $PORT
```
4. Add environment variables from `backend/.env.example`.
5. Deploy and test `/health` then `/api/scan`.

## Notes

- MVP uses in-memory cache only (no database/Redis).
- No authentication in this version.
- `dmarc_agent` source is vendored in `dmarc_agent_src/` for deploy portability.
