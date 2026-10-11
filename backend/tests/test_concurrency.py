import asyncio
import threading
from pathlib import Path

import httpx

from backend import main as backend_main
from backend.main import app


def test_second_analysis_is_rejected(monkeypatch):
    started = threading.Event()
    release = threading.Event()

    def fake_analyze(path):
        started.set()

        if not release.wait(timeout=5):
            raise RuntimeError("Test timeout")

        return {
            "total_packets": 1,
            "duration": "00:00:00.000",
            "threat_level": "None",
            "anomalies": []
        }

    monkeypatch.setattr(backend_main, "analyze", fake_analyze)

    sample = (
        Path(__file__).resolve().parents[1]
        / "samples"
        / "demo.pcap"
    ).read_bytes()

    async def scenario():
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test"
        ) as client:

            first = asyncio.create_task(
                client.post(
                    "/analyze",
                    files={"file": ("demo.pcap", sample)}
                )
            )

            try:
                assert await asyncio.to_thread(
                    started.wait, 3
                ), "First analysis did not start"

                second = await client.post(
                    "/analyze",
                    files={"file": ("demo.pcap", sample)}
                )

                assert second.status_code == 429

            finally:
                release.set()
                first_response = await first

            assert first_response.status_code == 200

    asyncio.run(scenario())