import asyncio
import re
from urllib.parse import urlparse
from google.antigravity import Agent, LocalAgentConfig

# ==========================================================
# 1. Advanced Cybersecurity Threat Detection Engine
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

        # --- A. URL & Domain Analysis ---
        if url:
            try:
                test_url = url if (url.startswith("http://") or url.startswith("https://")) else "http://" + url
                parsed = urlparse(test_url)
                hostname = (parsed.hostname or "").lower()
                path = (parsed.path or "").lower()

                # 1. Raw IP Address check
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
                    risk_score += 45
                    indicators.append(f"Raw IP address used instead of domain: '{hostname}'")

                # 2. Insecure HTTP check
                if url.startswith("http://"):
                    risk_score += 20
                    indicators.append("Unencrypted connection (HTTP) exposes credentials")

                # 3. Suspicious TLD check
                for tld in self.SUSPICIOUS_TLDS:
                    if hostname.endswith(tld):
                        risk_score += 25
                        indicators.append(f"High-risk top-level domain: '{tld}'")
                        break

                # 4. Typosquatting / Lookalike Domain Detection
                normalized_host = self._normalize_lookalikes(hostname)
                for brand in self.TARGETED_BRANDS:
                    if brand in normalized_host and brand not in hostname:
                        risk_score += 45
                        indicators.append(f"Typosquatting/lookalike domain targeting: '{brand.capitalize()}'")
                    elif brand in hostname and not (hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")):
                        risk_score += 35
                        indicators.append(f"Brand impersonation: '{brand.capitalize()}' in untrusted host '{hostname}'")

                # 5. Sensitive authentication paths
                if any(x in path for x in ["/login", "/verify", "/update", "/signin", "/otp", "/secure"]):
                    risk_score += 15
                    indicators.append("Sensitive authentication path targeted")

            except Exception:
                risk_score += 10
                indicators.append("Malformed URL structure")

        # --- B. Message Text Urgency & Phishing Language ---
        msg_lower = message.lower()
        matched_keywords = [kw for kw in self.PHISHING_KEYWORDS if kw in msg_lower]
        if matched_keywords:
            risk_score += min(len(matched_keywords) * 15, 40)
            indicators.append(f"Urgency keywords detected: {', '.join(f'\"{kw}\"' for kw in matched_keywords)}")

        # --- C. Final Verdict Compilation ---
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
    """Analyzes a URL and message for phishing indicators and returns a risk report."""
    scanner = ThreatAnalysisEngine()
    return scanner.calculate_risk(url, message)

async def analyze_with_agent(text_input: str) -> dict:
    urls = re.findall(r'(https?://[^\s]+|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/[^\s]*)?|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)', text_input)
    target_url = urls[0] if urls else ""

    scanner = ThreatAnalysisEngine()
    heuristics = scanner.calculate_risk(target_url, text_input)

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

    try:
        async with Agent(config) as agent:
            response = await agent.chat(text_input)
            ai_narrative = await response.text()
    except Exception as e:
        ai_narrative = f"Heuristic scan completed. (Agent summary note: {str(e)})"

    return {
        "url": target_url,
        "heuristics": heuristics,
        "analysis": ai_narrative
    }

if __name__ == "__main__":
    import sys, io
    if sys.platform == "win32":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

    test_message = (
        " ".join(sys.argv[1:]) 
        if len(sys.argv) > 1 
        else "URGENT! Account suspended. Verify identity at http://paypa1-security.example/login"
    )

    print("==================================================")
    print(f"INPUT: {test_message}")
    print("==================================================\n")
    print("Analyzing with Antigravity Threat Agent...\n")

    result = asyncio.run(analyze_with_agent(test_message))

    print(f"🎯 RISK SCORE : {result['heuristics']['risk_score']} / 100")
    print(f"🚨 SEVERITY   : {result['heuristics']['severity']}")
    print(f"⚠️ INDICATORS : {result['heuristics']['indicators']}")
    print(f"🛡️ ACTION     : {result['heuristics']['recommendation']}\n")
    print("--- AGENT INTELLIGENCE REPORT ---")
    print(result["analysis"])
