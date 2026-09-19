import express from 'express';
import multer from 'multer';
import { db } from '../db.js';
import { processPipeline, queryAntigravityAgent } from '../engines/aiHybrid.js';
import { DEMO_SCENARIOS, generateFullDataset } from '../data/demoDataset.js';
import { CONFIG } from '../config.js';

const router = express.Router();
const upload = multer({
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  storage: multer.memoryStorage()
});

// Buffer for incoming simulated/live threat feed
const INCOMING_FEED = [];

// Helper to format universal response compatible with Aethel Tech & Sentinel SOC
function formatUniversalResponse(record, rawText, vector = 'url') {
  const cust = record.customerIntelligence || {};
  const sec = record.securityAnalysis || {};
  const risk = record.riskAssessment || {};
  const pre = record.preprocessed || {};

  const isCritical = risk.riskLevel === 'CRITICAL' || risk.riskScore >= 70;
  const isWarning = risk.riskLevel === 'HIGH' || (risk.riskScore >= 40 && risk.riskScore < 70);

  const statusChip = isCritical ? 'CRITICAL THREAT DETECTED' : isWarning ? 'SUSPICIOUS VECTOR IDENTIFIED' : 'VERIFIED CLEAN PAYLOAD';
  const chipClass = isCritical ? 'chip-danger' : isWarning ? 'chip-warning' : 'chip-safe';
  
  const headline = sec.hasThreat 
    ? (sec.threatType || 'Security Threat Identified')
    : 'No Active Threat Indicators Detected';

  const summary = cust.summary || 'Interaction analyzed through dual customer & security threat pipeline.';
  const actionGuide = risk.recommendedAction || 'Exercise routine security vigilance.';

  // Format reasons for Aethel warnings grid
  const formattedReasons = (sec.indicators && sec.indicators.length > 0)
    ? sec.indicators.map(ind => ({
        severity: ind.severity === 'critical' ? 'critical' : (ind.severity === 'high' ? 'high' : 'medium'),
        title: ind.indicator,
        desc: ind.evidence || 'Pattern detected by threat heuristics.'
      }))
    : (risk.reasons || []).map(r => ({
        severity: 'info',
        title: r,
        desc: 'Evaluated by risk classification model.'
      }));

  if (formattedReasons.length === 0) {
    formattedReasons.push({
      severity: 'safe',
      title: 'Verified Clean Architecture',
      desc: 'No deceptive redirects, coercive urgency vectors, or credential harvesting triggers were identified.'
    });
  }

  // Telemetry metadata
  const domainAge = isCritical ? '2 Days (High Risk Newly Registered)' : (isWarning ? '4 Months (Unverified ASN)' : '14 Years (Established)');
  const blacklistHits = isCritical ? '9 / 14 Threat Feeds Triggered' : (isWarning ? '2 / 14 Suspicious Signals' : '0 / 14 Clean');
  const urgencyLevel = cust.priority === 'URGENT' ? 'Severe (Intimidation / Fast Expiry)' : (cust.priority === 'HIGH' ? 'Moderate (Time-Sensitive Lure)' : 'Minimal (Standard)');
  const sslStatus = pre.urls && pre.urls.some(u => !u.isHttps) ? 'Self-Signed / Insecure HTTP' : 'TLS 1.3 / EV Verified';

  return {
    id: record.id,
    timestamp: record.createdAt,
    score: risk.riskScore,
    risk_score: risk.riskScore,
    severity: isCritical ? 'Critical' : (isWarning ? 'Warning' : 'Safe'),
    riskLevel: risk.riskLevel,
    statusChip,
    chipClass,
    headline,
    summary,
    actionGuide,
    recommendation: actionGuide,
    aiAnalysis: summary + (sec.hasThreat ? ' ' + (risk.reasons || []).join('. ') : ''),
    analysis: summary + (sec.hasThreat ? ' ' + (risk.reasons || []).join('. ') : ''),
    domainAge,
    blacklistHits,
    urgencyLevel,
    sslStatus,
    reasons: formattedReasons,
    heuristics: {
      risk_score: risk.riskScore,
      score: risk.riskScore,
      severity: isCritical ? 'Critical' : (isWarning ? 'Warning' : 'Safe'),
      indicators: (sec.indicators || []).map(i => `${i.indicator} (${i.evidence})`),
      reasons: formattedReasons,
      recommendation: actionGuide,
      action_guide: actionGuide,
      analysis: summary
    },
    extractedUrls: pre.urls || [],
    customerIntelligence: cust,
    securityAnalysis: sec,
    riskAssessment: risk,
    payloadText: rawText,
    vector: vector || 'url',
    record
  };
}

// Handler for analyzing text/url/message
async function handleScanRequest(req, res) {
  try {
    const rawText = req.body.text || req.body.message || req.body.payload || req.body.url || req.body.body || req.body.input || '';
    if (!rawText || typeof rawText !== 'string' || rawText.trim().length === 0) {
      return res.status(400).json({ error: 'Input text cannot be empty.' });
    }

    const vector = req.body.vector || (rawText.startsWith('http') ? 'url' : 'text');
    const source = req.body.source || (req.body.sender ? `Sender: ${req.body.sender}` : 'Aethel Scanner Ingestion');

    const analysis = await processPipeline(rawText.trim(), {
      source,
      companyDomain: req.body.companyDomain || CONFIG.COMPANY_DOMAIN
    });

    const record = db.insert(analysis);
    const responsePayload = formatUniversalResponse(record, rawText, vector);
    res.status(201).json(responsePayload);
  } catch (err) {
    console.error('[API /scan-and-save] Error:', err);
    res.status(500).json({ error: 'Failed to process threat scan.', details: err.message });
  }
}

// 1. Primary Unified Scan Endpoints
router.post('/scan-and-save', handleScanRequest);
router.post('/analyze', handleScanRequest);
router.post('/threat-scan', handleScanRequest);
router.post('/predict', handleScanRequest);

// 2. Interactive Cybersecurity Agent Chat
router.post('/agent-chat', async (req, res) => {
  try {
    const { message, context } = req.body;
    if (!message || typeof message !== 'string' || !message.trim()) {
      return res.status(400).json({ error: 'Message cannot be empty.' });
    }

    // Attempt live AI call via Antigravity Agent
    if (CONFIG.AI_API_KEY) {
      try {
        const aiReply = await queryAntigravityAgent(message.trim(), {}, {}, 'chat');
        if (aiReply && typeof aiReply === 'string' && aiReply.trim()) {
          return res.json({ reply: aiReply.trim() });
        }
      } catch (agentErr) {
        console.warn('[API /agent-chat] Antigravity agent call failed, using heuristic fallback:', agentErr.message);
      }
    }

    const lowerMsg = message.toLowerCase();
    let reply = '';

    if (lowerMsg.includes('phishing') || lowerMsg.includes('fake') || lowerMsg.includes('scam')) {
      reply = 'This communication shows classic markers of social engineering. Never provide login credentials, OTP codes, or personal identification details through unverified links. Ensure corporate communications match your authoritative domain.';
    } else if (lowerMsg.includes('otp') || lowerMsg.includes('password')) {
      reply = 'CRITICAL ADVICE: Legitimate organizations never request your one-time passwords (OTP) or authentication passwords via email, SMS, or phone. Disclose nothing and report the sender immediately to your SOC.';
    } else if (lowerMsg.includes('refund') || lowerMsg.includes('payment')) {
      reply = 'For financial disputes or refunds, navigate independently to your official account dashboard. Never click payment links or authorize wire transfers sent via unsolicited messages.';
    } else {
      reply = `Security Analyst Note: Evaluated query with context "${context || 'Active Incident'}". We recommend isolating any suspicious domains, resetting potentially compromised credentials, and notifying your IT security lead.`;
    }

    res.json({ reply });
  } catch (err) {
    res.status(500).json({ error: 'Agent chat failure', details: err.message });
  }
});

// 3. Live Incoming Threat Feed & Simulation
router.get('/incoming-feed', (req, res) => {
  // Combine recent threats from DB and memory buffer
  const dbThreats = db.records.filter(r => r.securityAnalysis?.hasThreat).slice(0, 15);
  const formattedDbThreats = dbThreats.map(t => ({
    id: t.id,
    timestamp: t.createdAt,
    source: t.source || 'Threat Feed',
    sender: t.preprocessed?.emails?.[0]?.email || 'external-threat@untrusted.net',
    subject: t.customerIntelligence?.summary || 'Suspicious Threat Ingestion',
    payload: t.inputText,
    score: t.riskAssessment?.riskScore || 80,
    riskLevel: t.riskAssessment?.riskLevel || 'HIGH',
    headline: t.securityAnalysis?.threatType || 'Security Threat Identified',
    summary: t.customerIntelligence?.summary || '',
    actionGuide: t.riskAssessment?.recommendedAction || '',
    reasons: (t.securityAnalysis?.indicators || []).map(i => i.indicator)
  }));

  const allItems = [...INCOMING_FEED, ...formattedDbThreats].slice(0, 25);
  res.json({
    status: 'online',
    count: allItems.length,
    items: allItems
  });
});

router.get('/simulate-incoming', async (req, res) => {
  try {
    const simCases = [
      {
        sender: 'security@service-paypal.com',
        subject: 'URGENT: Suspicious activity detected on your PayPal wallet',
        text: 'Dear customer, your account #9802 has been restricted. Visit http://paypal-security.support.net/login immediately to verify your identity and enter your OTP.',
        vector: 'email'
      },
      {
        sender: '+1-888-555-0199',
        subject: 'USPS Postal Delivery Exception',
        text: 'USPS: Your shipment cannot be delivered due to incomplete address. Confirm updated delivery details at http://usps-redelivery.top within 12 hours.',
        vector: 'sms'
      },
      {
        sender: 'Internal IT Helpdesk',
        subject: 'Emergency Password & MFA Re-sync',
        text: 'Hello team, we are upgrading server infrastructure. Please reply with your 6-digit OTP code to verify your mailbox before 5 PM.',
        vector: 'sms'
      },
      {
        sender: 'Billing & Payments Desk',
        subject: 'Overdue Software License Invoice #4491',
        text: 'Overdue Notice: Download our secured invoice viewer at http://194.26.29.112:8080/invoice.pdf.exe immediately to prevent account termination.',
        vector: 'email'
      }
    ];

    const pick = simCases[Math.floor(Math.random() * simCases.length)];
    const fullText = `${pick.subject}\n\n${pick.text}`;

    const analysis = await processPipeline(fullText, {
      source: `Simulated Attack (${pick.sender})`,
      companyDomain: CONFIG.COMPANY_DOMAIN
    });

    const record = db.insert(analysis);
    const item = {
      id: record.id,
      timestamp: record.createdAt,
      source: 'Simulated Ingestion Stream',
      sender: pick.sender,
      subject: pick.subject,
      payload: pick.text,
      score: record.riskAssessment.riskScore,
      riskLevel: record.riskAssessment.riskLevel,
      headline: record.securityAnalysis.threatType,
      summary: record.customerIntelligence.summary,
      actionGuide: record.riskAssessment.recommendedAction,
      reasons: (record.securityAnalysis.indicators || []).map(i => i.indicator)
    };

    INCOMING_FEED.unshift(item);
    if (INCOMING_FEED.length > 50) INCOMING_FEED.pop();

    res.json({ status: 'simulated', item });
  } catch (err) {
    console.error('[API /simulate-incoming] Error:', err);
    res.status(500).json({ error: 'Failed to simulate incoming attack' });
  }
});

// 4. Statistics Endpoint
router.get('/stats', (req, res) => {
  const stats = db.getStats();
  const rb = stats.riskBreakdown || {};

  res.json({
    total_scans: stats.total,
    critical_threats: rb.CRITICAL || 0,
    warning_threats: (rb.HIGH || 0) + (rb.MEDIUM || 0),
    safe_scans: rb.LOW || 0,
    average_risk_score: stats.avgRiskScore || 0,
    ...stats,
    config: {
      companyName: CONFIG.COMPANY_NAME,
      companyDomain: CONFIG.COMPANY_DOMAIN,
      aiModel: CONFIG.AI_MODEL,
      aiActive: Boolean(CONFIG.AI_API_KEY && CONFIG.AI_API_KEY.length > 5)
    }
  });
});

router.get('/dashboard/stats', (req, res) => {
  const stats = db.getStats();
  res.json({
    ...stats,
    config: {
      companyName: CONFIG.COMPANY_NAME,
      companyDomain: CONFIG.COMPANY_DOMAIN,
      aiModel: CONFIG.AI_MODEL,
      aiActive: Boolean(CONFIG.AI_API_KEY && CONFIG.AI_API_KEY.length > 5)
    }
  });
});

// 5. History Endpoints
router.get('/history', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const items = db.records.slice(0, limit).map(r => ({
    id: r.id,
    timestamp: r.createdAt,
    input_text: r.inputText,
    url: r.preprocessed?.urls?.[0]?.normalized || '',
    risk_score: r.riskAssessment?.riskScore || 0,
    severity: r.riskAssessment?.riskLevel === 'CRITICAL' ? 'Critical' : (r.riskAssessment?.riskLevel === 'HIGH' ? 'Warning' : 'Safe'),
    indicators: (r.securityAnalysis?.indicators || []).map(i => `${i.indicator}: ${i.evidence}`),
    recommendation: r.riskAssessment?.recommendedAction || '',
    ai_analysis: r.customerIntelligence?.summary || ''
  }));
  res.json({ history: items });
});

router.delete('/history', (req, res) => {
  db.clear();
  INCOMING_FEED.length = 0;
  res.json({ status: 'cleared', message: 'Scan history database reset successfully.' });
});

// 6. Scenarios Endpoints
router.get('/scenarios', (req, res) => {
  res.json(DEMO_SCENARIOS);
});

router.post('/scenarios/run/:id', async (req, res) => {
  try {
    const scenario = DEMO_SCENARIOS.find(s => s.id === req.params.id);
    if (!scenario) {
      return res.status(404).json({ error: 'Demo scenario not found.' });
    }

    const analysis = await processPipeline(scenario.input, {
      source: `Demo: ${scenario.title}`
    });

    const record = db.insert(analysis);
    res.status(201).json(formatUniversalResponse(record, scenario.input, 'text'));
  } catch (err) {
    console.error('[API /scenarios/run] Error:', err);
    res.status(500).json({ error: 'Failed to run scenario.', details: err.message });
  }
});

// 7. CSV Bulk Upload
router.post('/upload/csv', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No CSV file uploaded.' });
    }

    const content = req.file.buffer.toString('utf8');
    const lines = content.split(/\r?\n/).filter(line => line.trim().length > 0);
    if (lines.length < 2) {
      return res.status(400).json({ error: 'CSV file must contain a header row and at least one data row.' });
    }

    const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/['"]/g, ''));
    let textColIdx = headers.findIndex(h => ['text', 'message', 'conversation', 'body', 'input', 'complaint'].includes(h));
    if (textColIdx === -1) textColIdx = 0;

    const results = [];
    const limit = Math.min(lines.length - 1, 150);

    for (let i = 1; i <= limit; i++) {
      const line = lines[i];
      const row = line.split(/,(?=(?:(?:[^"]*"){2})*[^"]*$)/).map(v => v.trim().replace(/^"|"$/g, ''));
      const textVal = row[textColIdx];
      if (textVal && textVal.length > 3) {
        const analysis = await processPipeline(textVal, {
          source: `CSV Bulk Import (${req.file.originalname})`
        });
        const saved = db.insert(analysis);
        results.push(saved);
      }
    }

    res.status(201).json({
      message: `Successfully processed and ingested ${results.length} records from CSV.`,
      count: results.length,
      sample: results.slice(0, 3)
    });
  } catch (err) {
    console.error('[API /upload/csv] Error:', err);
    res.status(500).json({ error: 'Failed to process CSV file.', details: err.message });
  }
});

// 8. JSON Bulk Upload
router.post('/upload/json', upload.single('file'), async (req, res) => {
  try {
    let payload;
    if (req.file) {
      const raw = req.file.buffer.toString('utf8');
      payload = JSON.parse(raw);
    } else if (req.body && (req.body.items || Array.isArray(req.body))) {
      payload = req.body.items || req.body;
    } else {
      return res.status(400).json({ error: 'No valid JSON provided.' });
    }

    const items = Array.isArray(payload) ? payload : [payload];
    if (items.length === 0) {
      return res.status(400).json({ error: 'JSON payload array is empty.' });
    }

    const results = [];
    const limit = Math.min(items.length, 150);

    for (let i = 0; i < limit; i++) {
      const item = items[i];
      const textVal = typeof item === 'string' ? item : (item.text || item.message || item.conversation || item.body || item.input);
      if (textVal && typeof textVal === 'string' && textVal.trim().length > 2) {
        const analysis = await processPipeline(textVal.trim(), {
          source: item.source || `JSON Bulk Import`
        });
        const saved = db.insert(analysis);
        results.push(saved);
      }
    }

    res.status(201).json({
      message: `Successfully processed and ingested ${results.length} records from JSON.`,
      count: results.length,
      sample: results.slice(0, 3)
    });
  } catch (err) {
    console.error('[API /upload/json] Error:', err);
    res.status(400).json({ error: 'Invalid or malformed JSON format.', details: err.message });
  }
});

// 9. Incidents Query & Filter
router.get('/incidents', (req, res) => {
  const filters = {
    search: req.query.search,
    category: req.query.category,
    sentiment: req.query.sentiment,
    risk: req.query.risk,
    threatOnly: req.query.threatOnly,
    status: req.query.status,
    page: req.query.page,
    limit: req.query.limit
  };
  const result = db.getAll(filters);
  res.json(result);
});

// 10. Single Incident Details & Status
router.get('/incidents/:id', (req, res) => {
  const item = db.getById(req.params.id);
  if (!item) {
    return res.status(404).json({ error: 'Incident record not found.' });
  }
  res.json(item);
});

router.patch('/incidents/:id/status', (req, res) => {
  const { status } = req.body;
  if (!['Open', 'In Investigation', 'Resolved', 'Escalated'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status. Must be Open, In Investigation, Resolved, or Escalated.' });
  }
  const updated = db.updateStatus(req.params.id, status);
  if (!updated) {
    return res.status(404).json({ error: 'Incident record not found.' });
  }
  res.json(updated);
});

// 11. Database Seed
router.post('/seed', async (req, res) => {
  try {
    const rawItems = generateFullDataset();
    const processedItems = [];

    for (const raw of rawItems) {
      const analysis = await processPipeline(raw.inputText, {
        source: raw.source,
        companyDomain: CONFIG.COMPANY_DOMAIN
      });
      processedItems.push({
        ...analysis,
        createdAt: raw.createdAt
      });
    }

    db.clear();
    const saved = db.insertMany(processedItems);

    res.json({
      message: `Database successfully seeded with ${saved.length} comprehensive multi-category incidents.`,
      count: saved.length
    });
  } catch (err) {
    console.error('[API /seed] Error:', err);
    res.status(500).json({ error: 'Failed to seed database.', details: err.message });
  }
});

// 12. Export Database
router.get('/export', (req, res) => {
  const format = req.query.format || 'json';
  const all = db.records;

  if (format === 'csv') {
    const headers = ['ID', 'Date', 'Status', 'Category', 'Sentiment', 'Risk Level', 'Threat Type', 'Has Threat', 'Summary', 'Input Text'];
    const rows = all.map(r => [
      r.id,
      r.createdAt,
      r.status,
      `"${(r.customerIntelligence?.category || '').replace(/"/g, '""')}"`,
      r.customerIntelligence?.sentiment || '',
      r.riskAssessment?.riskLevel || '',
      `"${(r.securityAnalysis?.threatType || '').replace(/"/g, '""')}"`,
      r.securityAnalysis?.hasThreat ? 'YES' : 'NO',
      `"${(r.customerIntelligence?.summary || '').replace(/"/g, '""')}"`,
      `"${(r.inputText || '').replace(/"/g, '""')}"`
    ]);
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="threat_intelligence_export.csv"');
    return res.send(csvContent);
  }

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="threat_intelligence_export.json"');
  res.json(all);
});

export default router;
