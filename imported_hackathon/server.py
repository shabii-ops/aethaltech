import asyncio
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from google.antigravity import Agent, LocalAgentConfig

# ==========================================================
# 1. SQLite Database Setup & Helpers
# ==========================================================
DB_PATH = Path("c:/workspace/hackathon/threats.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            input_text TEXT NOT NULL,
            url TEXT,
            risk_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            indicators TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            ai_analysis TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def save_scan(input_text: str, url: str, heuristics: dict, ai_analysis: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    indicators_json = json.dumps(heuristics.get("indicators", []))

    cursor.execute("""
        INSERT INTO scan_history (timestamp, input_text, url, risk_score, severity, indicators, recommendation, ai_analysis)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now_iso,
        input_text,
        url,
        heuristics.get("risk_score", 0),
        heuristics.get("severity", "Unknown"),
        indicators_json,
        heuristics.get("recommendation", ""),
        ai_analysis
    ))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return {"id": scan_id, "timestamp": now_iso}

def get_history(limit: int = 50):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, input_text, url, risk_score, severity, indicators, recommendation, ai_analysis
        FROM scan_history
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()

    result = []
    for r in rows:
        result.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "input_text": r["input_text"],
            "url": r["url"],
            "risk_score": r["risk_score"],
            "severity": r["severity"],
            "indicators": json.loads(r["indicators"]),
            "recommendation": r["recommendation"],
            "ai_analysis": r["ai_analysis"]
        })
    return result

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE severity = 'Critical'")
    critical = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE severity = 'Warning'")
    warning = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE severity = 'Safe'")
    safe = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(risk_score) FROM scan_history")
    avg_score_raw = cursor.fetchone()[0]
    avg_score = round(avg_score_raw, 1) if avg_score_raw is not None else 0

    conn.close()
    return {
        "total_scans": total,
        "critical_threats": critical,
        "warning_threats": warning,
        "safe_scans": safe,
        "average_risk_score": avg_score
    }

init_db()


# ==========================================================
# 2. Advanced Cybersecurity Threat Detection Engine
# ==========================================================
class ThreatAnalysisEngine:
    TARGETED_BRANDS = [
        "paypal", "google", "microsoft", "apple", "amazon", 
        "netflix", "facebook", "instagram", "chase", "bankofamerica", "wellsfargo"
    ]
    
    LEET_MAP = {
        '1': 'l', '0': 'o', '5': 's', '3': 'e', '@': 'a', 'vv': 'w'
    }

    SUSPICIOUS_TLDS = [
        ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", 
        ".ru", ".buzz", ".live", ".work", ".click", ".fit"
    ]

    PHISHING_KEYWORDS = [
        "urgent", "verify account", "account suspended", "suspend", "password", 
        "bank", "immediate action", "compromised", "otp", "login", "reset credentials",
        "avoid termination", "action required", "billing update", "unusual activity"
    ]

    def _normalize_lookalikes(self, text: str) -> str:
        clean = text.lower()
        for k, v in self.LEET_MAP.items():
            clean = clean.replace(k, v)
        return clean

    def calculate_risk(self, url: str, message: str) -> dict:
        risk_score = 0
        indicators = []

        if url:
            try:
                test_url = url if (url.startswith("http://") or url.startswith("https://")) else "http://" + url
                parsed = urlparse(test_url)
                hostname = (parsed.hostname or "").lower()
                path = (parsed.path or "").lower()

                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
                    risk_score += 45
                    indicators.append(f"Raw IP address used instead of domain: '{hostname}'")

                if url.startswith("http://"):
                    risk_score += 20
                    indicators.append("Unencrypted connection (HTTP) exposes credentials")

                for tld in self.SUSPICIOUS_TLDS:
                    if hostname.endswith(tld):
                        risk_score += 25
                        indicators.append(f"High-risk top-level domain: '{tld}'")
                        break

                normalized_host = self._normalize_lookalikes(hostname)
                for brand in self.TARGETED_BRANDS:
                    if brand in normalized_host and brand not in hostname:
                        risk_score += 45
                        indicators.append(f"Typosquatting/lookalike domain targeting: '{brand.capitalize()}'")
                    elif brand in hostname and not (hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")):
                        risk_score += 35
                        indicators.append(f"Brand impersonation in untrusted host: '{brand.capitalize()}'")

                if any(x in path for x in ["/login", "/verify", "/update", "/signin", "/otp", "/secure"]):
                    risk_score += 15
                    indicators.append("Sensitive authentication path targeted")

            except Exception:
                risk_score += 10
                indicators.append("Malformed URL structure")

        msg_lower = message.lower()
        matched_keywords = [kw for kw in self.PHISHING_KEYWORDS if kw in msg_lower]
        if matched_keywords:
            risk_score += min(len(matched_keywords) * 15, 40)
            indicators.append(f"Urgency keywords detected: {', '.join(f'\"{kw}\"' for kw in matched_keywords)}")

        risk_score = min(risk_score, 100)
        if risk_score >= 70:
            severity = "Critical"
            recommendation = "CRITICAL: Block URL immediately and quarantine message. Malicious phishing detected."
        elif risk_score >= 40:
            severity = "Warning"
            recommendation = "WARNING: Flag message for review. Do not click links or submit credentials."
        else:
            severity = "Safe"
            recommendation = "SAFE: No high-risk threats detected. Proceed with standard caution."

        return {
            "risk_score": risk_score,
            "severity": severity,
            "indicators": indicators,
            "recommendation": recommendation
        }

def run_heuristic_scan(url: str, message: str) -> dict:
    scanner = ThreatAnalysisEngine()
    return scanner.calculate_risk(url, message)


# ==========================================================
# 3. FastAPI REST Service & Live Frontend
# ==========================================================
app = FastAPI(
    title="Antigravity Threat Intelligence Command Center",
    description="Live Cybersecurity Agent powered by Google Antigravity, Gemini, and SQLite"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    text: str

class ChatRequest(BaseModel):
    message: str
    context: str = ""

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "service": "Antigravity Threat Intelligence", "database": "connected"}

@app.post("/api/threat-scan")
async def threat_scan(request: ScanRequest):
    if not request.text.strip():
        raise HTTPException(status_code=400, detail="Input text cannot be empty.")

    urls = re.findall(r'(https?://[^\s]+|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s]*)?|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)', request.text)
    url_to_scan = urls[0] if urls else ""

    scanner = ThreatAnalysisEngine()
    heuristic_data = scanner.calculate_risk(url_to_scan, request.text)

    try:
        config = LocalAgentConfig(
            system_instructions=(
                "You are an elite Cybersecurity Threat Analysis Agent. "
                "Always use the `run_heuristic_scan` tool to analyze user inputs. "
                "Read the structured risk JSON and provide a clear, authoritative security briefing."
            ),
            api_key="AQ.Ab8RN6L26h4Pox19KUB8sO0hluNlWSv1XAwIVmZQJVxucZFWVg",
            model="gemini-3.5-flash-lite",
            tools=[run_heuristic_scan]
        )

        async with Agent(config) as agent:
            response = await agent.chat(request.text)
            ai_narrative = await response.text()
    except Exception as e:
        ai_narrative = f"Heuristic scan completed. Note: Agent narrative unavailable ({str(e)})"

    db_record = save_scan(
        input_text=request.text,
        url=url_to_scan,
        heuristics=heuristic_data,
        ai_analysis=ai_narrative
    )

    return {
        "id": db_record["id"],
        "timestamp": db_record["timestamp"],
        "url": url_to_scan,
        "heuristics": heuristic_data,
        "analysis": ai_narrative
    }

@app.post("/api/agent-chat")
async def agent_chat(request: ChatRequest):
    """Allows interactive follow-up questions with the Antigravity Agent."""
    if not request.message.strip():
        raise HTTPException(status_code=400, detail="Chat message cannot be empty.")

    prompt = (
        f"Context of the security incident being analyzed:\n{request.context}\n\n"
        f"User question/instruction:\n{request.message}"
    ) if request.context else request.message

    try:
        config = LocalAgentConfig(
            system_instructions=(
                "You are an active Cybersecurity Threat Intelligence Assistant. "
                "Provide expert security guidance, draft remediation steps or emails, explain vulnerabilities, and assist the user."
            ),
            api_key="AQ.Ab8RN6L26h4Pox19KUB8sO0hluNlWSv1XAwIVmZQJVxucZFWVg",
            model="gemini-3.5-flash-lite"
        )

        async with Agent(config) as agent:
            response = await agent.chat(prompt)
            reply = await response.text()
            return {"reply": reply}
    except Exception as e:
        return {"reply": f"Agent assist currently busy: {str(e)}"}

@app.get("/api/history")
async def fetch_history(limit: int = 50):
    return {"history": get_history(limit=limit)}

@app.get("/api/stats")
async def fetch_stats():
    return get_stats()

@app.delete("/api/history")
async def clear_history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history")
    conn.commit()
    conn.close()
    return {"status": "cleared", "message": "Scan history database reset successfully."}


# ==========================================================
# 4. Embedded Cyber Command Center with Interactive Agent Chat
# ==========================================================
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Antigravity Threat Intelligence Command Center</title>
  <meta name="description" content="AI-Powered Cybersecurity Threat Agent with Autonomous Phishing Heuristics and Real-Time Gemini Reasoning">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <!-- Markdown parser for rich AI output rendering -->
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
  <style>
    :root {
      --bg-base: #07090e;
      --bg-card: rgba(15, 21, 33, 0.78);
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-accent: rgba(0, 240, 255, 0.25);
      --neon-cyan: #00f0ff;
      --neon-emerald: #00ff88;
      --neon-rose: #ff3366;
      --neon-amber: #ffaa00;
      --text-main: #f0f4f8;
      --text-muted: #8a99ad;
      --font-ui: 'Outfit', sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-base);
      background-image: 
        radial-gradient(circle at 12% 12%, rgba(0, 240, 255, 0.08) 0%, transparent 40%),
        radial-gradient(circle at 88% 88%, rgba(255, 51, 102, 0.07) 0%, transparent 45%);
      color: var(--text-main);
      font-family: var(--font-ui);
      min-height: 100vh;
      padding: 24px;
      line-height: 1.6;
    }

    .container { max-width: 1400px; margin: 0 auto; }

    /* Header */
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 18px;
      border-bottom: 1px solid var(--border-subtle);
    }
    .brand { display: flex; align-items: center; gap: 14px; }
    .shield-logo {
      width: 44px; height: 44px;
      background: linear-gradient(135deg, #00f0ff, #ff3366);
      border-radius: 12px;
      display: flex; align-items: center; justify-content: center;
      font-size: 22px;
      box-shadow: 0 0 20px rgba(0, 240, 255, 0.35);
    }
    h1 { font-size: 24px; font-weight: 700; letter-spacing: -0.5px; }
    .badge-status {
      display: inline-flex; align-items: center; gap: 8px;
      padding: 6px 14px;
      background: rgba(0, 255, 136, 0.1);
      border: 1px solid rgba(0, 255, 136, 0.3);
      border-radius: 20px;
      color: var(--neon-emerald);
      font-size: 12px; font-weight: 600;
    }
    .pulse-dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: var(--neon-emerald);
      box-shadow: 0 0 10px var(--neon-emerald);
      animation: pulse 1.8s infinite;
    }
    @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.4; transform: scale(0.85); } }

    /* KPI Stats Bar */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .kpi-card {
      background: var(--bg-card);
      backdrop-filter: blur(16px);
      border: 1px solid var(--border-subtle);
      border-radius: 16px;
      padding: 16px 20px;
      transition: transform 0.2s, border-color 0.2s;
    }
    .kpi-card:hover { transform: translateY(-2px); border-color: var(--border-accent); }
    .kpi-title { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); font-weight: 600; margin-bottom: 4px; }
    .kpi-value { font-size: 28px; font-weight: 800; font-family: var(--font-mono); }
    .text-rose { color: var(--neon-rose); }
    .text-cyan { color: var(--neon-cyan); }
    .text-emerald { color: var(--neon-emerald); }
    .text-amber { color: var(--neon-amber); }

    /* Main Grid */
    .main-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 24px;
      margin-bottom: 28px;
    }
    @media (max-width: 1024px) { .main-grid { grid-template-columns: 1fr; } }

    /* Panel Card */
    .panel {
      background: var(--bg-card);
      backdrop-filter: blur(16px);
      border: 1px solid var(--border-subtle);
      border-radius: 20px;
      padding: 24px;
      box-shadow: 0 12px 36px rgba(0, 0, 0, 0.4);
      display: flex;
      flex-direction: column;
    }
    .panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
    .panel-title { font-size: 17px; font-weight: 600; display: flex; align-items: center; gap: 10px; }

    /* Quick Templates */
    .templates-bar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; }
    .chip {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-subtle);
      color: var(--text-muted);
      padding: 6px 12px;
      border-radius: 8px;
      font-size: 12px;
      cursor: pointer;
      font-weight: 500;
      transition: all 0.2s;
    }
    .chip:hover {
      background: rgba(0, 240, 255, 0.12);
      border-color: var(--neon-cyan);
      color: #fff;
    }

    textarea {
      width: 100%;
      height: 140px;
      background: rgba(10, 14, 22, 0.9);
      border: 1px solid var(--border-subtle);
      border-radius: 14px;
      padding: 16px;
      color: var(--text-main);
      font-family: var(--font-mono);
      font-size: 13.5px;
      resize: vertical;
      outline: none;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    textarea:focus {
      border-color: var(--neon-cyan);
      box-shadow: 0 0 16px rgba(0, 240, 255, 0.2);
    }

    .btn-scan {
      margin-top: 14px;
      width: 100%;
      padding: 15px;
      background: linear-gradient(135deg, #ff3366, #ff6b4a);
      border: none;
      border-radius: 14px;
      color: #fff;
      font-size: 15px;
      font-weight: 700;
      font-family: var(--font-ui);
      cursor: pointer;
      display: flex; align-items: center; justify-content: center; gap: 10px;
      transition: all 0.2s;
      box-shadow: 0 8px 24px rgba(255, 51, 102, 0.35);
    }
    .btn-scan:hover:not(:disabled) {
      transform: translateY(-2px);
      box-shadow: 0 12px 30px rgba(255, 51, 102, 0.5);
    }
    .btn-scan:disabled { opacity: 0.5; cursor: not-allowed; }

    /* Results */
    .result-placeholder {
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      min-height: 280px; text-align: center; color: var(--text-muted);
    }
    .result-content { display: none; }
    .verdict-header {
      display: flex; justify-content: space-between; align-items: center;
      padding: 16px 18px; border-radius: 14px; margin-bottom: 16px;
    }
    .verdict-critical { background: rgba(255, 51, 102, 0.15); border: 1px solid rgba(255, 51, 102, 0.4); }
    .verdict-warning { background: rgba(255, 170, 0, 0.15); border: 1px solid rgba(255, 170, 0, 0.4); }
    .verdict-safe { background: rgba(0, 255, 136, 0.15); border: 1px solid rgba(0, 255, 136, 0.4); }
    .score-badge { font-size: 32px; font-weight: 800; font-family: var(--font-mono); }
    .tag-container { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }
    .tag {
      background: rgba(255, 51, 102, 0.12);
      border: 1px solid rgba(255, 51, 102, 0.35);
      color: #ff99b0;
      padding: 4px 10px;
      border-radius: 8px;
      font-size: 12px;
      font-family: var(--font-mono);
    }

    .agent-box {
      background: rgba(10, 14, 22, 0.85);
      border: 1px solid var(--border-subtle);
      border-radius: 14px;
      padding: 18px;
      font-size: 13.5px;
      max-height: 280px;
      overflow-y: auto;
      line-height: 1.7;
    }
    .agent-box h1, .agent-box h2, .agent-box h3 { color: var(--neon-cyan); margin: 8px 0 4px; font-size: 15px; }
    .agent-box ul, .agent-box ol { padding-left: 18px; margin-bottom: 8px; }
    .agent-box table { width: 100%; border-collapse: collapse; margin: 8px 0; }
    .agent-box th, .agent-box td { border: 1px solid var(--border-subtle); padding: 6px 10px; font-size: 12px; }
    .agent-box code { font-family: var(--font-mono); background: rgba(255,255,255,0.08); padding: 2px 5px; border-radius: 4px; color: var(--neon-rose); }

    /* Interactive Agent Chat */
    .chat-section {
      margin-top: 18px;
      border-top: 1px solid var(--border-subtle);
      padding-top: 16px;
    }
    .chat-history {
      max-height: 180px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 10px;
      margin-bottom: 12px;
    }
    .chat-msg {
      padding: 10px 14px;
      border-radius: 12px;
      font-size: 13px;
      max-width: 85%;
      line-height: 1.5;
    }
    .msg-user {
      align-self: flex-end;
      background: rgba(0, 240, 255, 0.15);
      border: 1px solid rgba(0, 240, 255, 0.3);
      color: #fff;
    }
    .msg-agent {
      align-self: flex-start;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-subtle);
      color: var(--text-main);
    }
    .chat-input-bar {
      display: flex;
      gap: 8px;
    }
    .chat-input {
      flex: 1;
      background: rgba(10, 14, 22, 0.9);
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      padding: 10px 14px;
      color: var(--text-main);
      font-family: var(--font-ui);
      font-size: 13px;
      outline: none;
    }
    .chat-input:focus { border-color: var(--neon-cyan); }
    .btn-send {
      background: var(--neon-cyan);
      color: #000;
      border: none;
      padding: 10px 18px;
      border-radius: 10px;
      font-weight: 700;
      cursor: pointer;
      font-size: 13px;
      transition: all 0.2s;
    }
    .btn-send:hover { transform: scale(1.03); }

    /* History Table */
    .history-section {
      background: var(--bg-card);
      backdrop-filter: blur(16px);
      border: 1px solid var(--border-subtle);
      border-radius: 20px;
      padding: 24px;
    }
    table { width: 100%; border-collapse: collapse; margin-top: 14px; }
    th { text-align: left; padding: 12px 14px; color: var(--text-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid var(--border-subtle); }
    td { padding: 14px; border-bottom: 1px solid rgba(255, 255, 255, 0.04); font-size: 13px; font-family: var(--font-mono); }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }
    .table-url { color: var(--neon-cyan); max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .btn-secondary {
      background: rgba(255, 255, 255, 0.06);
      border: 1px solid var(--border-subtle);
      color: var(--text-main);
      padding: 8px 14px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-secondary:hover { background: rgba(255, 255, 255, 0.12); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <div class="shield-logo">🛡️</div>
        <div>
          <h1>Antigravity Threat Intelligence</h1>
          <p style="color: var(--text-muted); font-size: 13px;">Google Antigravity Agent • Gemini AI • SQLite Engine</p>
        </div>
      </div>
      <div class="badge-status">
        <span class="pulse-dot"></span>
        <span>AGENT ONLINE (PORT 8080)</span>
      </div>
    </header>

    <!-- KPI Stats Bar -->
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-title">Total Scans</div>
        <div class="kpi-value text-cyan" id="kpiTotal">0</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Critical Blocked</div>
        <div class="kpi-value text-rose" id="kpiCritical">0</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Warnings</div>
        <div class="kpi-value text-amber" id="kpiWarning">0</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Clean / Safe</div>
        <div class="kpi-value text-emerald" id="kpiSafe">0</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Avg Risk Score</div>
        <div class="kpi-value text-cyan" id="kpiAvgScore">0.0</div>
      </div>
    </div>

    <!-- Main Grid: Input & Live Analysis -->
    <div class="main-grid">
      <!-- Input Panel -->
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title"><span>⚡</span> Live Threat Input</div>
        </div>

        <div class="templates-bar">
          <span style="font-size: 12px; color: var(--text-muted); line-height: 28px;">Quick-load:</span>
          <button class="chip" onclick="loadTemplate('phish')">🚨 PayPal Typosquat</button>
          <button class="chip" onclick="loadTemplate('ip')">🌐 Raw IP Harvester</button>
          <button class="chip" onclick="loadTemplate('tld')">⚠️ Suspicious TLD</button>
          <button class="chip" onclick="loadTemplate('safe')">🛡️ Safe Query</button>
        </div>

        <textarea id="scanInput" placeholder="Paste email message, SMS text, or suspicious URL to analyze..."></textarea>

        <button id="scanBtn" class="btn-scan" onclick="performScan()">
          <span>🛡️ Analyze with Antigravity Agent</span>
        </button>

        <!-- Interactive Agent Chat Box -->
        <div class="chat-section">
          <div style="font-size: 13px; font-weight: 600; margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
            <span>💬</span> Ask Antigravity Agent:
          </div>
          <div class="templates-bar" style="margin-bottom: 8px;">
            <button class="chip" onclick="quickAsk('Draft a security warning email to employees about this link')">✉️ Draft Warning Email</button>
            <button class="chip" onclick="quickAsk('What firewall rule should our SOC team add?')">🧱 Firewall Rule</button>
          </div>
          <div id="chatHistory" class="chat-history"></div>
          <div class="chat-input-bar">
            <input type="text" id="chatInput" class="chat-input" placeholder="Ask follow-up (e.g. How to mitigate this attack?)..." onkeydown="if(event.key==='Enter') sendChat()">
            <button id="chatBtn" class="btn-send" onclick="sendChat()">Send</button>
          </div>
        </div>
      </div>

      <!-- Verdict Panel -->
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title"><span>📊</span> AI Agent Assessment</div>
        </div>

        <div id="resultPlaceholder" class="result-placeholder">
          <div style="font-size: 40px; margin-bottom: 12px;">🛡️</div>
          <div style="font-size: 16px; font-weight: 600;">System Armed & Ready</div>
          <div style="font-size: 13px; max-width: 320px; margin-top: 6px;">Enter text or load a template on the left to trigger the autonomous threat analysis agent.</div>
        </div>

        <div id="resultBox" class="result-content">
          <div id="verdictBanner" class="verdict-header verdict-critical">
            <div>
              <div id="verdictSeverity" style="font-size: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: 1px;">CRITICAL THREAT</div>
              <div id="verdictTarget" style="font-size: 13px; font-family: var(--font-mono); opacity: 0.9;"></div>
            </div>
            <div class="score-badge" id="verdictScore">100</div>
          </div>

          <div style="margin-bottom: 12px;">
            <div style="font-size: 12px; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.5px;">Identified Indicators:</div>
            <div id="verdictIndicators" class="tag-container"></div>
          </div>

          <div style="margin-bottom: 16px; padding: 12px; background: rgba(255,255,255,0.04); border-radius: 10px; font-size: 13px;">
            <strong style="color: var(--neon-cyan);">Recommendation:</strong>
            <span id="verdictRecommendation" style="margin-left: 6px;"></span>
          </div>

          <div>
            <div style="font-size: 12px; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.5px; margin-bottom: 6px;">Agent Intelligence Narrative:</div>
            <div id="verdictNarrative" class="agent-box"></div>
          </div>
        </div>
      </div>
    </div>

    <!-- Scan History Database -->
    <div class="history-section">
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div class="panel-title"><span>🗄️</span> Scan History Log (SQLite Database)</div>
        <div style="display: flex; gap: 8px;">
          <button class="btn-secondary" onclick="loadStatsAndHistory()">🔄 Refresh</button>
          <button class="btn-secondary" style="color: var(--neon-rose);" onclick="clearHistory()">🗑️ Clear</button>
        </div>
      </div>

      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Timestamp (UTC)</th>
            <th>Detected URL</th>
            <th>Risk Score</th>
            <th>Severity</th>
            <th>Input Preview</th>
          </tr>
        </thead>
        <tbody id="historyTableBody">
          <tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">No scan records yet. Run your first analysis above!</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <script>
    let currentIncidentContext = "";

    const TEMPLATES = {
      phish: "URGENT! Your PayPal account has been compromised. Verify immediately: http://paypa1-security.example/login",
      ip: "Immediate action required: Account suspended. Reset your PIN at http://192.168.1.50/verify",
      tld: "Action Required: Update your billing credentials today at http://billing-update.xyz/login to avoid termination.",
      safe: "Hello support, can you please assist me with checking the shipping status for order #94812?"
    };

    function loadTemplate(key) {
      document.getElementById('scanInput').value = TEMPLATES[key];
    }

    function quickAsk(prompt) {
      document.getElementById('chatInput').value = prompt;
      sendChat();
    }

    async function loadStatsAndHistory() {
      try {
        const statsRes = await fetch('/api/stats');
        const stats = await statsRes.json();
        document.getElementById('kpiTotal').innerText = stats.total_scans;
        document.getElementById('kpiCritical').innerText = stats.critical_threats;
        document.getElementById('kpiWarning').innerText = stats.warning_threats;
        document.getElementById('kpiSafe').innerText = stats.safe_scans;
        document.getElementById('kpiAvgScore').innerText = stats.average_risk_score.toFixed(1);

        const histRes = await fetch('/api/history?limit=15');
        const { history } = await histRes.json();
        const tbody = document.getElementById('historyTableBody');
        
        if (!history || history.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">No scan records yet. Run your first analysis above!</td></tr>';
          return;
        }

        tbody.innerHTML = history.map(h => `
          <tr>
            <td>#${h.id}</td>
            <td style="color: var(--text-muted);">${h.timestamp}</td>
            <td class="table-url">${h.url || '<span style="color:var(--text-muted)">None</span>'}</td>
            <td style="font-weight:700; color: ${h.risk_score >= 70 ? 'var(--neon-rose)' : h.risk_score >= 40 ? 'var(--neon-amber)' : 'var(--neon-emerald)'}">${h.risk_score}</td>
            <td>
              <span style="font-size: 11px; font-weight:700; padding: 3px 8px; border-radius: 6px; ${h.severity === 'Critical' ? 'background:rgba(255,51,102,0.2); color:var(--neon-rose);' : h.severity === 'Warning' ? 'background:rgba(255,170,0,0.2); color:var(--neon-amber);' : 'background:rgba(0,255,136,0.2); color:var(--neon-emerald);'}">
                ${h.severity}
              </span>
            </td>
            <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-muted);">${h.input_text}</td>
          </tr>
        `).join('');
      } catch (e) {
        console.error("Error loading stats/history:", e);
      }
    }

    async function performScan() {
      const input = document.getElementById('scanInput').value.trim();
      if (!input) return;

      const btn = document.getElementById('scanBtn');
      btn.disabled = true;
      btn.innerHTML = '<span>⚡ Antigravity Agent Analyzing Threat...</span>';

      try {
        const res = await fetch('/api/threat-scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: input })
        });
        const data = await res.json();

        currentIncidentContext = `URL: ${data.url}\nRisk Score: ${data.heuristics.risk_score}/100\nSeverity: ${data.heuristics.severity}\nIndicators: ${data.heuristics.indicators.join(', ')}\nReport: ${data.analysis}`;

        document.getElementById('resultPlaceholder').style.display = 'none';
        document.getElementById('resultBox').style.display = 'block';

        const banner = document.getElementById('verdictBanner');
        banner.className = 'verdict-header ' + (
          data.heuristics.severity === 'Critical' ? 'verdict-critical' :
          data.heuristics.severity === 'Warning' ? 'verdict-warning' : 'verdict-safe'
        );

        document.getElementById('verdictSeverity').innerText = data.heuristics.severity + ' RISK LEVEL';
        document.getElementById('verdictScore').innerText = data.heuristics.risk_score;
        document.getElementById('verdictTarget').innerText = data.url ? 'Target: ' + data.url : 'No target URL';
        document.getElementById('verdictRecommendation').innerText = data.heuristics.recommendation;

        const tagBox = document.getElementById('verdictIndicators');
        tagBox.innerHTML = (data.heuristics.indicators || []).map(ind => `<span class="tag">⚠️ ${ind}</span>`).join('');

        // Rich Markdown rendering
        if (typeof marked !== 'undefined') {
          document.getElementById('verdictNarrative').innerHTML = marked.parse(data.analysis);
        } else {
          document.getElementById('verdictNarrative').innerText = data.analysis;
        }

        loadStatsAndHistory();
      } catch (err) {
        alert("Scan failed: " + err.message);
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>🛡️ Analyze with Antigravity Agent</span>';
      }
    }

    async function sendChat() {
      const inputEl = document.getElementById('chatInput');
      const text = inputEl.value.trim();
      if (!text) return;

      const historyBox = document.getElementById('chatHistory');
      historyBox.innerHTML += `<div class="chat-msg msg-user"><strong>You:</strong> ${text}</div>`;
      inputEl.value = '';
      historyBox.scrollTop = historyBox.scrollHeight;

      const chatBtn = document.getElementById('chatBtn');
      chatBtn.disabled = true;
      chatBtn.innerText = '...';

      try {
        const res = await fetch('/api/agent-chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: text, context: currentIncidentContext })
        });
        const data = await res.json();
        
        const rendered = typeof marked !== 'undefined' ? marked.parse(data.reply) : data.reply;
        historyBox.innerHTML += `<div class="chat-msg msg-agent"><strong>Agent:</strong> ${rendered}</div>`;
        historyBox.scrollTop = historyBox.scrollHeight;
      } catch (e) {
        historyBox.innerHTML += `<div class="chat-msg msg-agent" style="color:var(--neon-rose)">Agent connection failed: ${e.message}</div>`;
      } finally {
        chatBtn.disabled = false;
        chatBtn.innerText = 'Send';
      }
    }

    async function clearHistory() {
      if (!confirm("Are you sure you want to clear the scan history database?")) return;
      await fetch('/api/history', { method: 'DELETE' });
      loadStatsAndHistory();
    }

    loadStatsAndHistory();
  </script>
</body>
</html>
"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
