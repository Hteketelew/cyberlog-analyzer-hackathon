# CyberLog Analyzer — Hackathon Demo

A simple blue-team web application that uploads security logs and detects common suspicious patterns.

## Features
- Upload `.log` / `.txt` files
- Detect failed-login and possible brute-force activity
- Detect SQL injection indicators
- Detect suspicious PowerShell/curl/wget/nc commands
- Detect unauthorized-access indicators
- Show severity summary and source IPs
- FastAPI backend + browser dashboard
- Ready for Render deployment

## Run locally

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app:app --reload
```

Open http://127.0.0.1:8000

## Render

This repository includes `render.yaml`.

If deploying manually:
- Runtime: Python 3
- Root Directory: leave blank
- Build Command: `pip install -r requirements.txt`
- Start Command: `uvicorn app:app --host 0.0.0.0 --port $PORT`

The important difference from a multi-folder project is that `requirements.txt`, `app.py`, `static/`, and `render.yaml` are all at the repository root.

## Hackathon pitch

"CyberLog Analyzer helps small teams quickly turn raw security logs into actionable alerts. A user uploads a log file, and the system identifies suspicious authentication activity, possible brute force, injection indicators, unauthorized access, and suspicious commands in seconds."
