# Project Aegis

## Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
- [How It Works](#how-it-works)
- [Detected Anomalies](#detected-anomalies)
- [API Endpoints](#api-endpoints)

## Overview
Project Aegis is a web application designed for network security analysis. It provides a user-friendly interface to upload and analyze packet capture (`.pcap`, `.pcapng`) files, identifying potential security threats and anomalies using a rule-based detection engine.

The application consists of a Next.js frontend and a FastAPI backend, which work together to deliver a seamless analysis experience. Users can upload a capture file and the system provides a detailed diagnostic report, including an overall threat level, a list of detected anomalies with severity scores, and key metrics about the capture.

## Key Features

- **Web-Based Analysis:** easy-to-use drag-and-drop interface for uploading `.pcap` and `.pcapng` files
- **Backend API:** a robust FastAPI server handles file processing, validation, and analysis
- **Rule-Based Anomaly Detection:** the Python-based analysis engine scans for a wide range of security issues
- **Threat Scoring:** each detected anomaly is assigned a score, contributing to an overall threat level for the capture file
- **Detailed Reporting:** the frontend presents a comprehensive report including capture duration, total packets, and a breakdown of each anomaly found
- **Concurrent Request Handling:** the API is designed to process one analysis at a time to ensure stability, queueing subsequent requests

## Technology Stack

- **Frontend:**
  - [Next.js](https://nextjs.org/)
  - [React](https://react.dev/)
  - [TypeScript](https://www.typescriptlang.org/)
- **Backend:**
  - [FastAPI](https://fastapi.tiangolo.com/) (Python)
- **Analysis Engine:**
  - [dpkt](https://github.com/kbandla/dpkt) for packet parsing

## Getting Started

Follow these instructions to set up and run the project locally.

### Prerequisites

- [Node.js](https://nodejs.org/) (v20 or later)
- [Python](https://www.python.org/) (v3.8 or later) and `venv`

### 1. Backend Setup

First, set up and run the Python backend server from the repository root.

```powershell
# Create a Python virtual environment
py -m venv .venv

# Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# Install required Python packages
pip install -r backend\requirements.txt

# Run FastAPI server
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

The backend API will be available at `http://127.0.0.1:8000`. You can view the API documentation at `http://127.0.0.1:8000/docs`.

### 2. Frontend Setup

In a separate terminal, set up and run the Next.js frontend from the repository root.

```bash
# Install Node.js dependencies
npm install

# Run the development server
npm run dev
```

The frontend application will be available at `http://localhost:3000`

## How It Works

1.  The user uploads a `.pcap` or `.pcapng` file through the web interface at `http://localhost:3000`
2.  The Next.js frontend sends the file to the `POST /analyze` endpoint of the FastAPI backend
3.  The backend validates the file's extension and magic header, ensuring it is a valid packet capture file. It also checks that the file size is within the 100 MB limit
4.  The file is streamed to a temporary location on the server
5.  The `detector.py` script is invoked to perform the analysis. It uses `dpkt` to parse packets and applies a set of rules to identify security anomalies
6.  The detector calculates scores for each anomaly and determines an overall threat level
7.  The backend formats the results into a JSON response and sends it back to the frontend
8.  The frontend displays the diagnostic report, detailing the findings

## Detected Anomalies

The analysis engine is capable of detecting the following types of anomalies:

- **DNS Tunneling:** high frequency of DNS TXT queries from a single source
- **SYN Flood (DoS/DDoS):** large number of SYN packets to a single target, indicative of a denial-of-service attack
- **Cleartext Credential Transmission:** passwords or authorization data sent over unencrypted protocols
- **Large ICMP Payload:** unusually large ICMP packets, which can be used for data exfiltration
- **Suspicious TCP Flags:** use of reconnaissance techniques like Null or Xmas scans
- **Port Scanning:** a single host targeting a large number of unique ports on another host
- **Suspicious DNS Request:** DNS queries for unusually long domain names, often associated with Domain Generation Algorithms (DGA).
- **Insecure Protocol Usage:** use of legacy, unencrypted protocols like FTP and Telnet
- **UDP Flood (DoS/DDoS):** a high volume of UDP packets targeting a specific host and port
- **ICMP Flood (DoS/DDoS):** a high volume of ICMP requests ("ping flood") targeting a host.

## API Endpoints

- **`GET /health`**
  - Description: A health check endpoint to verify that the API server is running
  - Response: `{ "status": "ok" }`

- **`POST /analyze`**
  - Description: Analyzes a provided packet capture file
  - Request: `multipart/form-data` with a `file` field containing the `.pcap` or `.pcapng` file
  - Response: A JSON object containing the full analysis report

## Testing

To run the backend tests, first install the development dependencies and then use `pytest`

```powershell
# (With virtual environment activated)
# Install development dependencies
pip install -r backend\requirements-dev.txt

# Run tests
pytest backend/tests -v
```

## Authors
- Nechaev Yusuf ([EnderYsuf](https://github.com/EnderYsuf)) - frontend, analysis engine, corrections
- Musaibov Alisher ([musalisher](https://github.com/musalisher)) - backend, testing
