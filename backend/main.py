"""Project Aegis: small local HTTP API for PCAP analysis."""

import asyncio
import logging
import tempfile
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool

from .detector import analyze

app = FastAPI(title="Project Aegis API", version="0.1.0")

# The frontend runs separately on port 3000 during development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MiB
CHUNK_SIZE = 1024 * 1024  # Read up to 1 MiB into memory at a time

# PCAP supports both byte orders and microsecond/nanosecond timestamps.
# PCAPNG starts with its own section-header magic.
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
}

logger = logging.getLogger(__name__)

analysis_lock = asyncio.Lock()

async def limit_analyses():
    if analysis_lock.locked():
        raise HTTPException(status_code=429,detail="Another analysis is already running")

    async with analysis_lock:
        yield

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
async def analyze_file(
    file: UploadFile = File(...),
    _limit: None = Depends(limit_analyses)
):
    filename = (file.filename or "").replace("\\", "/").split("/")[-1]
    if not filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Upload a .pcap or .pcapng file")

    temp_path = None
    size = 0

    try:
        # Temporary copy exists only for this request and is always deleted.
        with tempfile.NamedTemporaryFile(mode="wb", suffix=Path(filename).suffix, delete=False) as temp:
            temp_path = Path(temp.name)

            while chunk := await file.read(CHUNK_SIZE):
                if size == 0 and chunk[:4] not in PCAP_MAGICS:
                    raise HTTPException(status_code=400, detail="Invalid PCAP header")

                size += len(chunk)
                if size > MAX_FILE_SIZE:
                    raise HTTPException(status_code=413, detail="PCAP exceeds 100 MiB limit")

                temp.write(chunk)

        if size == 0:
            raise HTTPException(status_code=400, detail="File is empty")

        # The existing detector works with a file path and returns a dict.
        raw = await run_in_threadpool(analyze, str(temp_path))

        # Convert snake_case detector fields into the frontend's format.
        levels = {"None": "Clean", "Low": "Warning", "Medium": "Warning", "Critical": "Critical"}
        return {
            "fileName": filename,
            "totalPackets": raw["total_packets"],
            "duration": raw["duration"],
            "threatLevel": levels.get(raw["threat_level"], "Warning"),
            "detectedAnomalies": [
                {
                    "id": item["id"],
                    "type": item["type"],
                    "severity": item["severity"],
                    "detail": item["description"],
                }
                for item in raw["anomalies"]
            ],
        }

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to analyze uploaded capture")
        raise HTTPException(status_code=500, detail="Analysis failed") from exc
    finally:
        try:
            await file.close()
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)