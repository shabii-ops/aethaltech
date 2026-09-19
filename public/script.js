/**
 * Aethel Tech - Digital Threat Defense Engine
 * Real-time URL Detection, Message Analysis, and Risk Explanation
 */

// ==========================================================================
// 🔌 BACKEND API CONFIGURATION (PORT 3000 / DYNAMIC ORIGIN)
// ==========================================================================
const BACKEND_API_CONFIG = {
  BASE_URL: (typeof window !== "undefined" && window.location.origin && window.location.origin.startsWith("http"))
    ? window.location.origin
    : ((typeof localStorage !== "undefined" && localStorage.getItem("sentinel_backend_url")) || "http://localhost:3000"),
  ANALYZE_ENDPOINT: "/api/scan-and-save",
  FALLBACK_ENDPOINT: "/api/analyze",
  ENABLED: true
};

const TARGETED_BRANDS = [
    "paypal", "chase", "apple", "microsoft", "binance", "metamask",
    "coinbase", "netflix", "amazon", "google", "dhl", "fedex", "bank", "hdfc", "sbi",
    "wallet-connect", "walletconnect", "ledger", "phantom", "trezor", "trustwallet",
    "icici", "axis", "kotak", "pnb", "bob", "wellsfargo", "bankofamerica", "citi",
    "usps", "ups", "royalmail", "indiapost", "telegram", "whatsapp", "instagram",
    "facebook", "twitter", "dropbox", "onedrive", "adobe", "steam", "roblox"
];

const SUSPICIOUS_TLDS = [
    ".top", ".xyz", ".cc", ".buzz", ".work", ".click", ".link", ".support", ".cfd",
    ".monster", ".quest", ".icu", ".live", ".biz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".rest", ".fit", ".site", ".online", ".agency", ".lat", ".vip"
];

const FREE_HOSTING_PROVIDERS = [
    "firebaseapp.com", "web.app", "vercel.app", "netlify.app", "pages.dev",
    "ngrok-free.app", "glitch.me", "workers.dev", "github.io"
];

const KNOWN_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "cutt.ly", "rb.gy", "rebrand.ly"];

const PRESET_SAMPLES = [
    {
        title: "Executive Phishing",
        text: "URGENT: Corporate Single Sign-On session expired. Unauthorized login attempt detected from unrecognized external IP. Visit http://paypal-security.support.net/login?token=89102 immediately to verify your corporate credentials and prevent immediate account suspension within 2 hours."
    },
    {
        title: "Vendor Invoice .exe",
        text: "Dear Accounts Payable, corporate software license invoice #88902 is overdue. Download our verified encrypted viewer at http://192.168.1.104/secure/invoice.pdf.exe and enter SSO credentials to authorize clearance before end of business today or formal legal notice will be filed."
    },
    {
        title: "Account Takeover / OTP",
        text: "Security Alert: Corporate fund transfer of $1,499 initiated on departmental procurement card. Reply immediately with your registered mobile OTP and administrative PIN to freeze this transaction within 15 minutes."
    },
    {
        title: "Verified Customer Ticket",
        text: "Hello Customer Care, our order #ORD-77124 status has been stuck at 'Departed Distribution Hub' for 3 business days. Could your logistics team please provide an updated delivery timeframe? Thank you for your assistance!"
    }
];

function loadSample(index) {
    const input = document.getElementById("message-input");
    if (input && PRESET_SAMPLES[index]) {
        input.value = PRESET_SAMPLES[index].text;
        analyze();
    }
}

function clearInput() {
    const input = document.getElementById("message-input");
    const resultBox = document.getElementById("result-box");
    if (input) input.value = "";
    if (resultBox) resultBox.style.display = "none";
}

function analyze() {
    const input = document.getElementById("message-input");
    const resultBox = document.getElementById("result-box");
    const analyzeBtn = document.getElementById("analyze-btn");

    if (!input || !resultBox) return;

    const text = input.value.trim();
    if (!text) {
        alert("Please enter a suspicious message, text, or link to analyze.");
        return;
    }

    if (analyzeBtn) {
        analyzeBtn.innerHTML = "<span>⏳ Scanning Threat Vectors...</span>";
        analyzeBtn.style.opacity = "0.7";
    }

    setTimeout(async () => {
        let result = null;
        if (BACKEND_API_CONFIG.ENABLED) {
            try {
                let apiUrl = `${BACKEND_API_CONFIG.BASE_URL}${BACKEND_API_CONFIG.ANALYZE_ENDPOINT}`;
                let res = null;
                try {
                    res = await fetch(apiUrl, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ text: text, message: text })
                    });
                    if (!res.ok && res.status === 404 && BACKEND_API_CONFIG.FALLBACK_ENDPOINT) {
                        apiUrl = `${BACKEND_API_CONFIG.BASE_URL}${BACKEND_API_CONFIG.FALLBACK_ENDPOINT}`;
                        res = await fetch(apiUrl, {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ text: text, message: text })
                        });
                    }
                } catch (fetchErr) {
                    // Auto-fallback to local Sentinel backend if remote IP is unreachable
                    if (!apiUrl.includes("localhost:3000") && !apiUrl.includes("127.0.0.1:3000")) {
                        try {
                            const localUrl = "http://localhost:3000/api/scan-and-save";
                            res = await fetch(localUrl, {
                                method: "POST",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({ text: text, message: text })
                            });
                        } catch (localErr) {}
                    }
                    if (!res && BACKEND_API_CONFIG.FALLBACK_ENDPOINT) {
                        apiUrl = `${BACKEND_API_CONFIG.BASE_URL}${BACKEND_API_CONFIG.FALLBACK_ENDPOINT}`;
                        res = await fetch(apiUrl, {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ text: text, message: text })
                        });
                    } else if (!res) {
                        throw fetchErr;
                    }
                }
                if (!res || !res.ok) throw new Error(`HTTP ${res ? res.status : 'ERR'}`);
                result = await res.json();

                // Log team schema fields exactly as requested
                const riskScore = (result.heuristics && result.heuristics.risk_score !== undefined)
                    ? result.heuristics.risk_score
                    : (result.risk_score !== undefined ? result.risk_score : result.score);
                const aiAnalysis = result.analysis !== undefined
                    ? result.analysis
                    : (result.heuristics && result.heuristics.analysis !== undefined ? result.heuristics.analysis : "");

                console.log("Risk Score:", riskScore !== undefined ? riskScore : 0);
                console.log("AI Analysis:", aiAnalysis || "No analysis text.");
            } catch (e) {
                console.warn("Backend error, falling back to local threat pipeline:", e);
                result = runThreatPipeline(text);
            }
        } else {
            result = runThreatPipeline(text);
        }

        renderResult(result, text);

        if (analyzeBtn) {
            analyzeBtn.innerHTML = "<span>⚡ Analyze Now</span>";
            analyzeBtn.style.opacity = "1";
        }
    }, 280);
}

function runThreatPipeline(text) {
    const lowerText = text.toLowerCase();

    // 1. URL Extraction & Inspection
    const urlRegex = /(https?:\/\/[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(?:com|net|org|xyz|io|co|in|info|biz|ru|cn|top|support|live|cc|cfd|monster|quest|icu)[^\s]*)/gi;
    const rawUrls = text.match(urlRegex) || [];
    const extractedUrls = [];
    let urlScoreAdd = 0;

    rawUrls.forEach((raw) => {
        let cleanUrl = raw.replace(/[.,;!?)]+$/, "");
        let hostname = "";
        let isHttps = cleanUrl.startsWith("https://");
        let isIpAddress = false;
        let isShortener = false;
        let isSuspiciousTld = false;
        let isFreeHosting = false;
        let hasApk = cleanUrl.toLowerCase().endsWith(".apk") || cleanUrl.toLowerCase().includes(".apk.zip") || cleanUrl.toLowerCase().endsWith(".ipa");
        let lookalikeBrand = null;
        let flags = [];

        try {
            let parsed = new URL(cleanUrl.startsWith("http://") || cleanUrl.startsWith("https://") ? cleanUrl : `http://${cleanUrl}`);
            hostname = parsed.hostname.toLowerCase();
        } catch {
            hostname = cleanUrl.split('/')[0].toLowerCase();
        }

        if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(hostname)) {
            isIpAddress = true;
            urlScoreAdd += 32;
            flags.push("Raw IP address used instead of verified domain");
        }

        if (KNOWN_SHORTENERS.some(s => hostname.includes(s))) {
            isShortener = true;
            urlScoreAdd += 20;
            flags.push("URL shortener obfuscating real destination");
        }

        if (FREE_HOSTING_PROVIDERS.some(h => hostname.endsWith(h) || hostname === h)) {
            isFreeHosting = true;
            urlScoreAdd += 24;
            flags.push(`Free cloud hosting service (${hostname})`);
        }

        if (SUSPICIOUS_TLDS.some(t => hostname.endsWith(t))) {
            isSuspiciousTld = true;
            urlScoreAdd += 26;
            flags.push(`High-abuse TLD (${hostname})`);
        }

        const hasAuthPath = /(login|signin|verify|auth|security|account|update|confirm|token|sso|password|otp|banking|support|portal)/i.test(cleanUrl);
        const hasSuspiciousKeywords = /(verify|security|update|login|support|secure|account|alert|banking)/i.test(hostname);

        TARGETED_BRANDS.forEach(brand => {
            if (hostname.includes(brand)) {
                const isLegit = hostname === `${brand}.com` || hostname.endsWith(`.${brand}.com`);
                if (!isLegit) {
                    lookalikeBrand = brand;
                    urlScoreAdd += 80;
                    flags.push(`Deceptive typosquatting impersonating '${brand}'`);
                }
            }
        });

        if (hasAuthPath) {
            urlScoreAdd += 35;
            flags.push("Authentication / credential target path");
        }

        if (hasSuspiciousKeywords && !lookalikeBrand) {
            urlScoreAdd += 42;
            flags.push("Deceptive domain formulation mimicking official portals");
        }

        if (!isHttps) {
            urlScoreAdd += 15;
            flags.push("Insecure HTTP protocol (unencrypted)");
        }

        if (cleanUrl.toLowerCase().endsWith(".exe") || cleanUrl.toLowerCase().includes(".pdf.exe")) {
            urlScoreAdd += 55;
            flags.push("Dangerous executable payload (.exe disguised as document)");
        }

        if (hasApk) {
            urlScoreAdd += 55;
            flags.push("Dangerous mobile APK package download");
        }

        const isSuspicious = isIpAddress || lookalikeBrand || isShortener || isFreeHosting || isSuspiciousTld || hasApk || hasAuthPath || hasSuspiciousKeywords || flags.length >= 2;

        extractedUrls.push({
            original: cleanUrl,
            domain: hostname,
            flags,
            isSuspicious,
            lookalikeBrand
        });
    });

    // 2. Comprehensive Multi-Vector Social Engineering Analysis (Cross-Source)
    const socialVectors = [];
    let socialScoreAdd = 0;

    if (/(urgent|immediately|within \d+ (hours|minutes)|critical|terminate|suspended|deadline|legal action|police|warrant|final warning|arrest warrant)/i.test(text)) {
        socialScoreAdd += 24;
        socialVectors.push({
            type: "Artificial Urgency & Intimidation",
            desc: "Forces hasty decisions under artificial time constraints or legal threats"
        });
    }
    if (/(otp|one time password|password|passcode|credential|sso login|verify account|enter credentials|pin|token|security key)/i.test(text)) {
        socialScoreAdd += 38;
        socialVectors.push({
            type: "Credential & Token Harvesting",
            desc: "Solicits private passwords, OTP tokens, or Single Sign-On credentials"
        });
    }
    if (/(kyc|pan card|aadhaar|debit card|credit card|account (blocked|suspended|frozen|restricted|locked|disabled)|unauthorized debit|atm card|netbanking|bank alert)/i.test(text)) {
        socialScoreAdd += 46;
        socialVectors.push({
            type: "Banking / KYC Account Coercion",
            desc: "Simulates financial institution alert claiming card freeze or KYC expiry"
        });
    }
    if (/(package|parcel|shipment|delivery|tracking|customs|undelivered|redelivery|courier|dispatch|usps|fedex|dhl|ups|held at warehouse|address incomplete)/i.test(text)) {
        socialScoreAdd += 36;
        socialVectors.push({
            type: "Postal / Delivery Smishing",
            desc: "Fabricates package delay or customs fee notification to bait clicks"
        });
    }
    if (/(electricity|power|bill overdue|service disconnection|disconnection tonight|power cutoff|sim (block|deactivate|upgrade)|bill unpaid)/i.test(text)) {
        socialScoreAdd += 42;
        socialVectors.push({
            type: "Utility Cutoff Pressure",
            desc: "Threatens immediate power or utility disconnection to cause panic"
        });
    }
    if (/(hi mom|hi dad|hello mom|hello dad|lost my phone|new number|emergency money|bail|in hospital|need urgent help|urgent cash)/i.test(text)) {
        socialScoreAdd += 45;
        socialVectors.push({
            type: "Family Distress Impersonation",
            desc: "Poses as family member with a broken phone or emergency needing cash"
        });
    }
    if (/(part[- ]time job|work from home|earn \d+|daily income|like youtube|review hotels|daily commission|telegram task|vip task|prepaid task)/i.test(text)) {
        socialScoreAdd += 34;
        socialVectors.push({
            type: "Employment / Task Advance Scam",
            desc: "Prompts fake task completion or daily earning leading to deposit traps"
        });
    }
    if (/(airdrop|claim token|seed phrase|recovery phrase|private key|connect wallet|mint nft|staking|permit2|setapprovalforall)/i.test(text)) {
        socialScoreAdd += 42;
        socialVectors.push({
            type: "Web3 Asset Drainer Lure",
            desc: "Promises free tokens or airdrops engineered to drain crypto wallets"
        });
    }
    if (/(refund of rs|prize|unclaimed|lottery|compensation|cash prize|free reward|transfer rs|\$\d+.*(won|winner|refund))/i.test(text)) {
        socialScoreAdd += 20;
        socialVectors.push({
            type: "Financial Baiting",
            desc: "Lures victim with false financial promises or fake billing claims"
        });
    }
    if (/(call|contact|reach|whatsapp|helpline|officer|manager|dial)\s*(?:at|on|:)?\s*(\+?\d[\d\s-]{7,}\d)/i.test(text)) {
        socialScoreAdd += 28;
        socialVectors.push({
            type: "Unverified Support / Officer Phone Lure",
            desc: "Directs victim to an unverified personal phone number or WhatsApp handle posing as an official authority"
        });
    }
    if (/(?:pay|send|transfer|deposit|upi|gpay|phonepe|paytm)\s*(?:to|at|:)?\s*([a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,})/i.test(text)) {
        socialScoreAdd += 32;
        socialVectors.push({
            type: "Direct Peer-to-Peer Payment / UPI Handle",
            desc: "Demands direct funds transfer to an individual UPI or mobile wallet address"
        });
    }
    if (/(\.(apk|apk\.zip|ipa)\b|download.*(app|apk))/i.test(text) && !extractedUrls.some(u => u.flags.some(f => f.includes("APK")))) {
        socialScoreAdd += 40;
        socialVectors.push({
            type: "External APK Application Binary",
            desc: "Prompts downloading an external APK file bypassing app store protection"
        });
    }
    if (/(scan (the )?qr|qr code to (receive|pay|verify)|scan to accept payment)/i.test(text)) {
        socialScoreAdd += 28;
        socialVectors.push({
            type: "Quishing: Coerced QR Payment Trapping",
            desc: "Directs victim to scan QR code under the pretext of receiving money"
        });
    }
    if (/(security alert|corporate payroll|law firm|police|director|audit)/i.test(text) && socialVectors.length === 0) {
        socialScoreAdd += 20;
        socialVectors.push({
            type: "Authority Impersonation",
            desc: "Falsely portrays security, IT admin, or executive authority"
        });
    }

    // Compute Base Score
    let computedScore = Math.min(Math.max(5 + urlScoreAdd + socialScoreAdd, 5), 98);
    if (urlScoreAdd === 0 && socialScoreAdd === 0) {
        computedScore = 6;
    }
    if (extractedUrls.some(u => u.lookalikeBrand || u.hasApk || u.hasExe || u.isIpAddress || (u.flags && u.flags.some(f => f.includes("typosquatting") || f.includes("credential"))))) {
        computedScore = Math.max(computedScore, 94);
    }

    // 3. Risk Level Determination
    let riskLevel = "Safe";
    let threatTitle = "No Active Threat Detected";
    let explanation = "The analyzed text demonstrates standard operational patterns without indicators of phishing, credential harvesting, or deceptive redirects.";
    let actionGuide = "Safe to review standard communications. Exercise routine security vigilance.";

    if (computedScore >= 70) {
        riskLevel = "Critical";
        threatTitle = "High-Consequence Phishing & Credential Theft Vector";
        explanation = "Combines high-urgency psychological coercion, credential harvesting lures, or deceptive destinations engineered for unauthorized account access.";
        actionGuide = "DO NOT CLICK ANY LINKS. Do NOT enter passwords, OTPs, or transfer funds. Block the sender and report immediately.";
    } else if (computedScore >= 40) {
        riskLevel = "High";
        threatTitle = "Untrusted Communication Vector Flagged";
        explanation = "The content contains suspicious external web destinations, unverified contact numbers, or psychological manipulation triggers.";
        actionGuide = "Avoid interacting with links or calling untrusted numbers. Verify sender legitimacy through official out-of-band channels.";
    }

    return {
        score: computedScore,
        riskLevel,
        threatTitle,
        explanation,
        actionGuide,
        extractedUrls,
        socialVectors
    };
}

function renderResult(res, originalText = "") {
    const resultBox = document.getElementById("result-box");
    if (!resultBox || !res) return;

    // Run local pipeline on originalText for hybrid defense-in-depth
    const local = runThreatPipeline(originalText || "");

    // 1. Intelligent backend score extraction
    let rawScoreVal = null;
    const candidateKeys = [
        res?.heuristics?.risk_score,
        res?.heuristics?.score,
        res?.riskAssessment?.riskScore,
        res?.riskAssessment?.score,
        res?.securityAnalysis?.threatScore,
        res?.securityAnalysis?.score,
        res?.record?.riskAssessment?.riskScore,
        res?.heuristics?.probability,
        res?.heuristics?.confidence,
        res?.risk_score,
        res?.riskScore,
        res?.score,
        res?.threat_score,
        res?.phishing_score,
        res?.probability,
        res?.confidence,
        res?.data?.risk_score,
        res?.data?.score,
        res?.result?.risk_score,
        res?.result?.score,
        res?.analysis?.risk_score
    ];

    for (const c of candidateKeys) {
        if (c !== undefined && c !== null && c !== "") {
            const num = Number(c);
            if (!isNaN(num)) {
                rawScoreVal = num;
                break;
            }
        }
    }

    let backendScore = null;
    if (rawScoreVal !== null) {
        if (rawScoreVal > 0 && rawScoreVal <= 1.0) {
            backendScore = Math.round(rawScoreVal * 100);
        } else {
            backendScore = Math.round(rawScoreVal);
        }
    }

    // Categorical tags
    const pred = String(
        res?.prediction || res?.label || res?.classification || res?.verdict || 
        res?.category || res?.status || res?.result || res?.threatLevel || 
        res?.risk_level || res?.riskLevel || ""
    ).toLowerCase();

    const isExplicitThreat = res?.is_phishing === true || res?.is_threat === true || 
                            res?.threat === true || res?.malicious === true || 
                            res?.threat_detected === true || res?.isPhishing === true;

    const isPhishTag = isExplicitThreat || 
                       pred.includes("phish") || pred.includes("malicious") || pred.includes("threat") || 
                       pred.includes("smish") || pred.includes("fraud") || pred.includes("spam") || 
                       pred.includes("danger") || pred.includes("scam") || pred.includes("suspicious") ||
                       pred === "critical" || pred === "high";

    const isSafeTag = (res?.is_phishing === false || res?.threat === false) ||
                      (pred.includes("safe") || pred.includes("clean") || pred.includes("ham") || 
                       pred.includes("legit") || pred.includes("benign") || pred === "low");

    if (isPhishTag) {
        backendScore = Math.max(backendScore !== null ? backendScore : 0, 85);
    } else if (isSafeTag && backendScore === null) {
        backendScore = 8;
    }

    // 2. Hybrid Defense-in-Depth Scoring
    let score = local.score;
    if (backendScore !== null) {
        if (local.score <= 15 && isSafeTag && backendScore <= 20) {
            score = Math.min(backendScore, local.score);
        } else {
            score = Math.max(backendScore, local.score);
        }
    }
    score = Math.min(Math.max(score, 5), 98);

    const isDanger = score >= 70;
    const isWarning = score >= 40 && score < 70;
    const riskLevel = isDanger ? "Critical" : isWarning ? "High" : "Safe";
    const threatTitle = res.threatTitle || res.headline || local.threatTitle || (isDanger ? "Critical Threat Detected" : isWarning ? "Suspicious Activity Flagged" : "Verified Clean");
    const explanation = res.analysis || res.explanation || res.summary || (res.heuristics && res.heuristics.analysis) || local.explanation || "Analyzed safely by threat detection engine.";
    const actionGuide = res.actionGuide || res.action_guide || (res.heuristics && res.heuristics.action_guide) || local.actionGuide || (
        isDanger ? "DO NOT CLICK ANY LINKS. Do NOT enter passwords, OTPs, or transfer funds. Block the sender and report immediately."
        : isWarning ? "Avoid interacting with links or calling untrusted numbers. Verify sender legitimacy through official out-of-band channels."
        : "Safe to review standard communications. Exercise routine vigilance."
    );

    // Merge extractedUrls and socialVectors
    let extractedUrls = Array.isArray(res.extractedUrls) ? [...res.extractedUrls] : [];
    let socialVectors = Array.isArray(res.socialVectors) ? [...res.socialVectors] : [];

    // Deduplicate and merge local heuristics
    local.extractedUrls.forEach(lu => {
        if (!extractedUrls.some(eu => eu.domain === lu.domain)) {
            extractedUrls.push(lu);
        }
    });
    local.socialVectors.forEach(lv => {
        if (!socialVectors.some(sv => sv.type === lv.type)) {
            socialVectors.push(lv);
        }
    });

    let boxClass = "clean";
    if (riskLevel === "Critical") boxClass = "critical";
    else if (riskLevel === "High" || riskLevel === "Medium") boxClass = "high";

    resultBox.className = `result-box ${boxClass}`;
    resultBox.style.display = "block";

    resultBox.innerHTML = `
        <div class="result-header">
            <div>
                <span class="risk-level-badge">${riskLevel} Risk (${score}/100)</span>
                <span class="threat-name" style="margin-left: 0.5rem;">${threatTitle}</span>
            </div>
            <span style="font-size: 0.75rem; color: var(--text-dim); font-weight: 600;">Neural Verified</span>
        </div>

        <p style="font-size: 0.9rem; color: var(--text-main); margin-bottom: 0.85rem; line-height: 1.5;">
            <strong>AI Threat Analysis:</strong> ${explanation}
        </p>

        <div style="background: rgba(255,255,255,0.85); border-left: 4px solid ${riskLevel === 'Critical' ? '#e11d48' : riskLevel === 'High' ? '#d97706' : '#059669'}; padding: 0.65rem 1rem; border-radius: 4px; font-size: 0.85rem; margin-bottom: 1rem;">
            <strong>Recommended Action:</strong> ${actionGuide}
        </div>

        ${(res?.customerIntelligence || res?.category || res?.priority) ? `
        <div style="background: rgba(240, 244, 255, 0.95); border: 1px solid #c7d2fe; border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 1rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
                <span style="font-weight: 700; font-size: 0.8rem; color: #1e1b4b; text-transform: uppercase; letter-spacing: 0.5px;">🏢 Enterprise Customer Intelligence &amp; SLA</span>
                <span style="font-size: 0.72rem; background: #e0e7ff; color: #3730a3; padding: 2px 8px; border-radius: 999px; font-weight: 700;">Priority: ${(res?.priority || res?.customerIntelligence?.priority || 'NORMAL').toUpperCase()}</span>
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.4rem; font-size: 0.8rem; margin-bottom: 0.4rem;">
                <div><span style="color: var(--text-dim);">Ticket Category:</span> <strong style="color: #1e1b4b;">${res?.category || res?.customerIntelligence?.category || 'General Support'}</strong></div>
                <div><span style="color: var(--text-dim);">Sentiment:</span> <strong style="color: ${(res?.sentiment || res?.customerIntelligence?.sentiment || '').toLowerCase().includes('neg') ? '#e11d48' : '#059669'};">${res?.sentiment || res?.customerIntelligence?.sentiment || 'Neutral'}</strong></div>
                <div><span style="color: var(--text-dim);">SLA Routing:</span> <strong style="color: #1e1b4b;">${res?.sla || res?.customerIntelligence?.sla || 'Standard 4h Response'}</strong></div>
            </div>
            <div style="font-size: 0.8rem; color: #334155; line-height: 1.4;">
                <strong>Ticket Summary:</strong> ${res?.customerIntelligence?.summary || res?.summary || 'Inbound communication classified.'}
            </div>
        </div>
        ` : ''}

        <div class="result-columns">
            <!-- URL Detection Card -->
            <div class="result-card-inner">
                <h4>🔗 URL Detection (${extractedUrls.length})</h4>
                ${extractedUrls.length > 0 ? `
                    <ul>
                        ${extractedUrls.map(u => `
                            <li style="margin-bottom: 0.35rem;">
                                <strong style="color: ${u.isSuspicious ? '#e11d48' : '#059669'};">${u.domain}</strong>
                                <div style="font-size: 0.72rem; color: var(--text-dim); word-break: break-all;">${u.original}</div>
                                ${u.flags && u.flags.length > 0 ? `
                                    <div style="color: #e11d48; font-size: 0.72rem; margin-top: 2px;">
                                        ⚠️ ${u.flags.join(", ")}
                                    </div>
                                ` : ''}
                            </li>
                        `).join('')}
                    </ul>
                ` : `<p style="color: var(--text-dim); font-style: italic;">No hyperlinks found in message.</p>`}
            </div>

            <!-- Message Analysis Card -->
            <div class="result-card-inner">
                <h4>💬 Message Analysis (${socialVectors.length})</h4>
                ${socialVectors.length > 0 ? `
                    <ul>
                        ${socialVectors.map(v => `
                            <li style="margin-bottom: 0.35rem;">
                                <strong style="color: #d97706;">${v.type}</strong>
                                <div style="font-size: 0.72rem; color: var(--text-dim);">${v.desc}</div>
                            </li>
                        `).join('')}
                    </ul>
                ` : `<p style="color: var(--text-dim); font-style: italic;">No coercive or manipulative language detected.</p>`}
            </div>
        </div>
    `;

    // Smooth scroll into view
    resultBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// Keyboard shortcut support (Ctrl/Cmd + Enter to trigger analysis)
document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("message-input");
    if (input) {
        input.addEventListener("keydown", (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
                e.preventDefault();
                analyze();
            }
        });
    }
});
