from pathlib import Path

from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from collections import Counter
import re

app = FastAPI(title="CyberLog Analyzer", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "static" / "index.html"

PATTERNS = [
    ("Brute Force / Failed Login",
     r"(failed login|login failed|authentication failure|invalid password)", "High"),

    ("SQL Injection Attempt",
     r"(union\s+select|or\s+1=1|select\s+.*from|drop\s+table)", "Critical"),

    ("Suspicious Command",
     r"(powershell|cmd\.exe|wget\s+http|curl\s+http|nc\s+-e)", "High"),

    ("Unauthorized Access",
     r"(unauthorized|access denied|permission denied|forbidden)", "Medium"),

    ("Malware Indicator",
     r"(malware|trojan|ransomware|virus)", "Critical"),
]

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@app.get("/")
def home():
    return FileResponse(INDEX_FILE)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "CyberLog Analyzer"
    }


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8", errors="replace")

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]

    alerts = []
    ip_counter = Counter()

    for line_number, line in enumerate(lines, start=1):

        ips = IP_RE.findall(line)

        for ip in ips:
            ip_counter[ip] += 1

        lower = line.lower()

        for name, pattern, severity in PATTERNS:

            if re.search(pattern, lower):

                alerts.append({
                    "line": line_number,
                    "type": name,
                    "severity": severity,
                    "message": line,
                    "ip": ips[0] if ips else "Unknown"
                })

                break

    severity_counts = Counter(
        alert["severity"]
        for alert in alerts
    )

    return {
        "filename": file.filename,
        "total_lines": len(lines),
        "alerts": alerts,
        "summary": {
            "critical": severity_counts["Critical"],
            "high": severity_counts["High"],
            "medium": severity_counts["Medium"],
            "low": severity_counts["Low"],
        },
        "top_ips": [
            {
                "ip": ip,
                "count": count
            }
            for ip, count in ip_counter.most_common(10)
        ]
    }from flask import Flask, request, jsonify, render_template
from openai import OpenAI
import os

app = Flask(__name__)

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/api/chat", methods=["POST"])
def chat():
    try:
        data = request.get_json()
        message = data.get("message", "")

        if not message:
            return jsonify({"error": "Message is required"}), 400

        response = client.responses.create(
            model="gpt-5",
            input=message
        )

        return jsonify({
            "reply": response.output_text
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
