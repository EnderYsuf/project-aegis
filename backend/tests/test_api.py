from pathlib import Path
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "demo.pcap"


# Test 1 - Server health
def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# Test 2 - Valid PCAP
def test_valid_pcap():
    with SAMPLE.open("rb") as file:
        response = client.post(
            "/analyze",
            files={"file": ("demo.pcap", file)}
        )

    assert response.status_code == 200
    assert response.json()["totalPackets"] == 1


# Test 3 - Invalid file extension
def test_invalid_extension():
    response = client.post(
        "/analyze",
        files={"file": ("notes.txt", b"Hello world")}
    )

    assert response.status_code == 400


# Test 4 - Empty PCAP
def test_empty_pcap():
    response = client.post(
        "/analyze",
        files={"file": ("empty.pcap", b"")}
    )

    assert response.status_code == 400


# Test 5 - Corrupted PCAP
def test_corrupted_pcap():
    response = client.post(
        "/analyze",
        files={"file": ("broken.pcap", b"Invalid PCAP data")}
    )

    assert response.status_code == 400