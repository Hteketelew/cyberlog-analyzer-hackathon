from pathlib import Path
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from openai import OpenAI
from collections import Counter
import re
import os

app = FastAPI(
title="CyberLog Analyzer",
version="1.0.0"
)

app.add_middleware(
CORSMiddleware,
allow_origins=["*"],
allow_credentials=True,
allow_methods=["*"],
allow_headers=["*"],
)

BASE_DIR = Path(**file**).resolve().parent

STATIC_DIR = BASE_DIR / "static"
INDEX_FILE = STATIC_DIR / "index.html"

app.mount(
"/static",
StaticFiles(directory=STATIC_DIR),
name="static"
)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

client = None

if OPENAI_API_KEY:
client = OpenAI(
api_key=OPENAI_API_KEY
)

PATTERNS = [
(
"Brute Force / Failed Login",
r"(failed login|login failed|authentication failure|invalid password)",
"High"
),
(
"SQL Injection Attempt",
r"(union\s+select|or\s+1=1|select\s+.*from|drop\s+table)",
"Critical"
),
(
"Suspicious Command",
r"(powershell|cmd.exe|wget\s+http|curl\s+http|nc\s+-e)",
"High"
),
(
"Unauthorized Access",
r"(unauthorized|access denied|permission denied|forbidden)",
"Medium"
),
(
"Malware Indicator",
r"(malware|trojan|ransomware|virus)",
"Critical"
)
]

IP_RE = re.compile(
r"\b(?:\d{1,3}.){3}\d{1,3}\b"
)

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
async def analyze(
file: UploadFile = File(...)
):
content = await file.read()

```
text = content.decode(
    "utf-8",
    errors="replace"
)

lines = [
    line.strip()
    for line in text.splitlines()
    if line.strip()
]

alerts = []
ip_counter = Counter()

for line_number, line in enumerate(
    lines,
    start=1
):
    ips = IP_RE.findall(line)

    for ip in ips:
        ip_counter[ip] += 1

    lower = line.lower()

    for name, pattern, severity in PATTERNS:
        if re.search(
            pattern,
            lower
        ):
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
        "low": severity_counts["Low"]
    },
    "top_ips": [
        {
            "ip": ip,
            "count": count
        }
        for ip, count in ip_counter.most_common(10)
    ]
}
```

@app.post("/api/chat")
async def chat(data: dict):
try:
message = data.get(
"message",
""
).strip()

```
    if not message:
        return {
            "error": "Message is required."
        }

    if client is None:
        return {
            "error": "OpenAI API key is not configured."
        }

    response = client.responses.create(
        model="gpt-5",
        instructions=(
            "You are the AI cybersecurity assistant "
            "for CyberLog Analyzer. "
            "Help users understand security logs, "
            "alerts, suspicious activity, network "
            "security, malware indicators, and "
            "defensive cybersecurity. "
            "Give clear and practical answers."
        ),
        input=message
    )

    return {
        "reply": response.output_text
    }

except Exception as e:
    return {
        "error": f"AI request failed: {str(e)}"
    }
```
