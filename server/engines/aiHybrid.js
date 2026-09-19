/**
 * Hybrid Intelligence Orchestrator
 * Integrates deterministic rules with optional LLM augmentation (Gemini/OpenAI)
 * with 100% resilient fallback and strict schema validation.
 */

import { CONFIG } from '../config.js';
import { preprocessInput } from './preprocessor.js';
import { analyzeSecurity } from './securityEngine.js';
import { analyzeCustomerIntelligence } from './customerIntelligence.js';
import { computeUnifiedRisk } from './riskEngine.js';

export async function processPipeline(inputText, metadata = {}) {
  // Step 1: Preprocessing & deterministic entity extraction
  const preprocessed = preprocessInput(inputText);

  // Step 2: Deterministic Security Engine
  const securityDeterministic = analyzeSecurity(preprocessed, {
    companyDomain: metadata.companyDomain || CONFIG.COMPANY_DOMAIN
  });

  // Step 3: Customer Intelligence Engine (NLP / Lexicon baseline)
  const customerDeterministic = analyzeCustomerIntelligence(preprocessed, securityDeterministic);

  // Step 4: Optional AI Enhancement if API key configured
  let aiUsed = false;
  let customerFinal = customerDeterministic;
  let securityFinal = securityDeterministic;

  if (CONFIG.AI_API_KEY && CONFIG.AI_API_KEY.trim().length > 5) {
    try {
      const aiResult = await queryLLM(preprocessed.cleanText, customerDeterministic, securityDeterministic);
      if (aiResult && validateAISchema(aiResult)) {
        // Merge AI semantic nuances with deterministic security guarantees
        customerFinal = {
          ...customerDeterministic,
          ...aiResult.customerIntelligence,
          // Always keep category as Account Security if deterministic detected critical credential/OTP theft
          category: (securityDeterministic.hasThreat && securityDeterministic.threatScore >= 50) 
            ? 'Account Security' 
            : (aiResult.customerIntelligence.category || customerDeterministic.category)
        };
        
        // Merge security indicators: never discard deterministic security indicators
        const mergedIndicators = [...securityDeterministic.indicators];
        if (Array.isArray(aiResult.securityAnalysis?.indicators)) {
          for (const ind of aiResult.securityAnalysis.indicators) {
            if (ind.indicator && !mergedIndicators.some(m => m.type === ind.type || m.indicator === ind.indicator)) {
              mergedIndicators.push({
                indicator: ind.indicator,
                evidence: ind.evidence || 'AI Semantic Ingestion',
                severity: ind.severity || 'medium',
                type: ind.type || 'ai_detected_threat'
              });
            }
          }
        }

        securityFinal = {
          ...securityDeterministic,
          hasThreat: securityDeterministic.hasThreat || Boolean(aiResult.securityAnalysis?.hasThreat),
          threatType: securityDeterministic.threatType !== 'None' ? securityDeterministic.threatType : (aiResult.securityAnalysis?.threatType || 'None'),
          indicators: mergedIndicators,
          indicatorsCount: mergedIndicators.length
        };
        aiUsed = true;
      }
    } catch (err) {
      console.warn('[AI Pipeline] LLM call failed or returned invalid output, falling back to deterministic engines:', err.message);
      // Clean fallback, no crash
    }
  }

  // Step 5: Unified Risk Engine (Deterministic, auditable, explainable)
  const riskAssessment = computeUnifiedRisk(customerFinal, securityFinal, preprocessed);

  // Step 6: Assemble unified analysis object
  return {
    inputText,
    source: metadata.source || 'Direct Input',
    engineMode: aiUsed ? 'AI Augmented (Hybrid)' : 'Deterministic High-Performance Rules',
    timestamp: new Date().toISOString(),
    preprocessed: {
      charCount: preprocessed.charCount,
      wordCount: preprocessed.wordCount,
      urlCount: preprocessed.urls.length,
      emailCount: preprocessed.emails.length,
      urls: preprocessed.urls,
      emails: preprocessed.emails
    },
    customerIntelligence: customerFinal,
    securityAnalysis: securityFinal,
    riskAssessment
  };
}

async function queryLLM(text, baselineCustomer, baselineSecurity) {
  // Safe timeout of 4.5 seconds
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 4500);

  try {
    const prompt = `You are a real-time SOC and Customer Intelligence Classifier.
Analyze this message:
"""
${text}
"""

Return ONLY a valid JSON object matching this schema:
{
  "customerIntelligence": {
    "category": "Account Security" | "Payment Failure" | "Refund Request" | "Delivery Issue" | "Account Access" | "Technical Support" | "General Inquiry",
    "sentiment": "Positive" | "Neutral" | "Negative" | "Frustrated",
    "sentimentScore": number between -1.0 and 1.0,
    "priority": "LOW" | "MEDIUM" | "HIGH" | "URGENT",
    "summary": "1-2 sentence executive summary",
    "extractedKeywords": ["keyword1", "keyword2"],
    "keyIssues": ["core issue 1", "core issue 2"]
  },
  "securityAnalysis": {
    "hasThreat": boolean,
    "threatType": "Credential & OTP Harvesting" | "Phishing" | "Social Engineering" | "Financial Fraud Attempt" | "Suspicious Link" | "None",
    "indicators": [
      {
        "indicator": "Description using non-sensational phrasing (Potential threat / Suspicious indicator)",
        "evidence": "Exact string or reason",
        "severity": "low" | "medium" | "high" | "critical",
        "type": "string"
      }
    ]
  }
}`;

    // Check if key is Google Antigravity SDK format (starts with AQ.)
    if (CONFIG.AI_API_KEY.startsWith('AQ.')) {
      clearTimeout(timeoutId);
      return await queryAntigravityAgent(text, baselineCustomer, baselineSecurity);
    }

    // Standard Gemini API format
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${CONFIG.AI_MODEL}:generateContent?key=${CONFIG.AI_API_KEY}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          response_mime_type: "application/json"
        }
      }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`LLM HTTP status ${response.status}`);
    }

    const data = await response.json();
    const candidateText = data.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!candidateText) throw new Error('No candidate content in AI response');

    // Safe JSON parse with cleanup
    const cleanJsonText = candidateText.replace(/^```json\s*/i, '').replace(/\s*```$/, '').trim();
    return JSON.parse(cleanJsonText);
  } catch (err) {
    clearTimeout(timeoutId);
    throw err;
  }
}

import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function queryAntigravityAgent(text, baselineCustomer, baselineSecurity, mode = 'analysis') {
  return new Promise((resolve, reject) => {
    const scriptPath = path.join(__dirname, 'antigravity_agent.py');
    const proc = spawn('python', [scriptPath], {
      env: {
        ...process.env,
        ANTIGRAVITY_API_KEY: CONFIG.AI_API_KEY,
        AI_MODEL: 'gemini-3.5-flash-lite'
      }
    });

    let stdout = '';
    let stderr = '';

    const timer = setTimeout(() => {
      proc.kill();
      reject(new Error('Antigravity Agent timed out after 4500ms'));
    }, 4500);

    proc.stdout.on('data', (d) => { stdout += d.toString(); });
    proc.stderr.on('data', (d) => { stderr += d.toString(); });

    proc.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0 || !stdout.trim()) {
        return reject(new Error(`Antigravity Agent exit code ${code}: ${stderr || 'no output'}`));
      }
      try {
        const parsed = JSON.parse(stdout.trim());
        if (parsed.success && parsed.text) {
          if (mode === 'chat') {
            return resolve(parsed.text);
          }
          // Return structured format augmenting baseline
          resolve({
            customerIntelligence: {
              ...baselineCustomer,
              summary: parsed.text
            },
            securityAnalysis: {
              ...baselineSecurity,
              aiAnalysis: parsed.text
            }
          });
        } else {
          reject(new Error(parsed.error || 'Agent returned unsuccessful result'));
        }
      } catch (err) {
        reject(err);
      }
    });

    proc.stdin.write(JSON.stringify({ mode, text }));
    proc.stdin.end();
  });
}

function validateAISchema(data) {
  if (!data || typeof data !== 'object') return false;
  if (!data.customerIntelligence || typeof data.customerIntelligence !== 'object') return false;
  if (!data.customerIntelligence.category || !data.customerIntelligence.sentiment) return false;
  return true;
}
