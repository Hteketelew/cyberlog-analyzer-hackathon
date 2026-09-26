from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
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
STATIC_DIR = BASE_DIR / "static"

PATTERNS = [
    ("Brute Force / Failed Login", r"(failed login|login failed|authentication failure|invalid password)", "High"),
    ("SQL Injection Attempt", r"(union\s+select|or\s+1=1|select\s+.*from|drop\s+table)", "Critical"),
    ("Suspicious Command", r"(powershell|cmd\.exe|wget\s+http|curl\s+http|nc\s+-e)", "High"),
    ("Unauthorized Access", r"(unauthorized|access denied|permission denied|forbidden)", "Medium"),
    ("Malware Indicator", r"(malware|trojan|ransomware|virus)", "Critical"),
]

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def analyze_logs(text: str):
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    alerts = []
    ip_counter = Counter()

    for line_no, line in enumerate(lines, start=1):
        ips = IP_RE.findall(line)
        for ip in ips:
            ip_counter[ip] += 1

        lower = line.lower()
        for name, pattern, severity in PATTERNS:
            if re.search(pattern, lower):
                alerts.append({
                    "line": line_no,
                    "type": name,
                    "severity": severity,
                    "message": line,
                    "ip": ips[0] if ips else "Unknown",
                })
                break

    # Repeated failed-login source IPs are elevated to a brute-force alert.
    for ip, count in ip_counter.items():
        if count >= 5:
            alerts.append({
                "line": 0,
                "type": "Possible Brute Force",
                "severity": "High",
                "message": f"{ip} appeared {count} times in the submitted logs.",
                "ip": ip,
            })

    severity_counts = Counter(a["severity"] for a in alerts)
    return {
        "total_lines": len(lines),
        "alerts": alerts,
        "summary": {
            "critical": severity_counts["Critical"],
            "high": severity_counts["High"],
            "medium": severity_counts["Medium"],
            "low": severity_counts["Low"],
        },
        "top_ips": [{"ip": ip, "count": count} for ip, count in ip_counter.most_common(10)],
    }


@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "CyberLog Analyzer"}


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8", errors="replace")
    result = analyze_logs(text)
    result["filename"] = file.filename
    return result
