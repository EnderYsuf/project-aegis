# Project Aegis Backend — starter

A local FastAPI server integrating the existing PCAP anomaly detector without changing its detection rules.

## Windows setup (from the cloned repository root)

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
.\.venv\Scripts\python.exe -m pytest backend/tests -v
# Install development dependencies (including tests)
.\.venv\Scripts\python.exe -m pip install -r backend\requirements-dev.txt
```

Open http://127.0.0.1:8000/docs and use the `POST /analyze` endpoint with `backend/samples/demo.pcap`. Also try `GET /health`.

To avoid tracking local data and Python caches, add to the *root* `.gitignore`:

```
.venv/
__pycache__/
*.py[cod]
*.pcap
*.pcapng
!backend/samples/demo.pcap
```

## What works

- `GET /health`: HTTP 200 with `{ "status": "ok" }`.
- `POST /analyze`: multipart form upload, field named `file`.
- Maximum size: 100 MiB. Reads uploads in chunks and uses a temporary file removed in a `finally` block.
- Checks filename extension and PCAP/PCAPNG magic header.
- Runs existing `dpkt` detector and returns JSON fields matching `src/app/page.tsx`'s `AnalysisResult` type.
- Allows browser requests from localhost:3000 for eventual frontend integration.

## Notes

- The original sanitizer is **not** called: it clears payload bytes required for some detection rules. Discuss the privacy and sanitization design before enabling it.
- This is a **local demo**, not a hardened public service. Authentication, upload-rate limiting, enforced body limits at the proxy, parser robustness, resource isolation and additional tests are needed before public deployment.
- The `backend/detector.py` file is a minimally adapted copy from `public/python/detector.py`. Changes: return structured dict instead of JavaScript code, raise an error on invalid input, and fix the zero-time duration check. Detection thresholds unchanged.
- Consider removing `public/python` once your team agrees to migrate the detector; anything inside Next.js `public` may be served to visitors.
- The Next.js frontend is connected to the FastAPI backend.
- Uploaded PCAP/PCAPNG files are analyzed using rule-based detection.
- The frontend displays real analysis results returned by POST /analyze.
- Heuristic detection can produce false positives; never present it as proof of malicious activity.

## Frontend Integration

The Next.js frontend is connected to the FastAPI backend.

Run the backend from the repository root:

`.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload`

Open another terminal and run the frontend:

`npm install`

`npm run dev`

Frontend: http://localhost:3000

Backend API: http://127.0.0.1:8000

API Documentation: http://127.0.0.1:8000/docs

The frontend sends PCAP files to POST /analyze and displays
the analysis results returned by the backend.
