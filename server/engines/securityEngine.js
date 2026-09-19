/**
 * Deterministic Security Intelligence Engine
 * Evaluates URLs, emails, and textual indicators for phishing and social engineering.
 */

import { CONFIG } from '../config.js';

// Suspicious TLDs commonly abused in disposable phishing campaigns
const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'ru', 'cn', 'work', 'click', 'buzz', 'live', 'club', 'surf', 'loan', 'gq', 'cf', 'ml', 'ga', 'tk', 'support', 'cfd', 'quest', 'monster', 'icu'
]);

// Suspicious URL path keywords
const SENSITIVE_URL_KEYWORDS = [
  'login', 'signin', 'verify', 'account', 'update', 'banking', 'secure', 'wallet', 
  'confirm', 'password', 'credential', 'auth', 'security', 'session', 'token', 'otp'
];

// Major enterprise and financial brands targeted for credential phishing
const TARGETED_BRANDS = [
  'paypal', 'chase', 'apple', 'microsoft', 'binance', 'metamask',
  'coinbase', 'netflix', 'amazon', 'google', 'dhl', 'fedex', 'bank', 'hdfc', 'sbi',
  'wallet-connect', 'walletconnect', 'ledger', 'phantom', 'trezor', 'trustwallet',
  'icici', 'axis', 'kotak', 'pnb', 'bob', 'wellsfargo', 'bankofamerica', 'citi',
  'usps', 'ups', 'royalmail', 'indiapost', 'telegram', 'whatsapp', 'instagram',
  'facebook', 'twitter', 'dropbox', 'onedrive', 'adobe', 'steam', 'roblox'
];

export function analyzeSecurity(preprocessed, context = {}) {
  const { cleanText, urls, emails } = preprocessed;
  const companyDomain = (context.companyDomain || CONFIG.COMPANY_DOMAIN || 'novapay.io').toLowerCase();
  const companyKeywords = CONFIG.COMPANY_KEYWORDS || ['novapay'];
  
  const indicators = [];
  const lowerText = cleanText.toLowerCase();

  // 1. URL Analysis
  for (const u of urls) {
    if (u.invalid) {
      indicators.push({
        indicator: 'Malformed URL detected',
        evidence: u.original,
        severity: 'low',
        type: 'url_syntax'
      });
      continue;
    }

    // IP-based URL
    if (u.isIP) {
      indicators.push({
        indicator: 'Suspicious indicator: IP-based host address instead of domain',
        evidence: u.normalized,
        severity: 'high',
        type: 'suspicious_url'
      });
    }

    // Insecure HTTP when path asks for auth/security
    if (!u.isHttps && !u.isIP) {
      const hasAuthPath = SENSITIVE_URL_KEYWORDS.some(k => u.pathname.includes(k));
      indicators.push({
        indicator: hasAuthPath 
          ? 'Potential threat: Unencrypted HTTP protocol requesting sensitive actions' 
          : 'Suspicious indicator: Insecure HTTP protocol',
        evidence: u.normalized,
        severity: hasAuthPath ? 'high' : 'medium',
        type: 'unencrypted_transport'
      });
    }

    // URL Shortener hiding destination
    if (u.isShortener) {
      indicators.push({
        indicator: 'Suspicious indicator: Obfuscated destination via URL shortening service',
        evidence: u.hostname,
        severity: 'medium',
        type: 'url_shortener'
      });
    }

    // Excessive URL Length
    if (u.totalLength > 85) {
      indicators.push({
        indicator: 'Suspicious indicator: Abnormally long URL containing potential payload or obfuscation',
        evidence: `Length: ${u.totalLength} chars (${u.original.substring(0, 45)}...)`,
        severity: 'low',
        type: 'url_length'
      });
    }

    // Suspicious TLD
    const parts = u.hostname.split('.');
    const tld = parts[parts.length - 1];
    if (SUSPICIOUS_TLDS.has(tld)) {
      indicators.push({
        indicator: `Suspicious indicator: High-risk top-level domain (.${tld})`,
        evidence: u.hostname,
        severity: 'medium',
        type: 'suspicious_tld'
      });
    }

    // Punycode / Homograph check
    if (u.hasPunycode) {
      indicators.push({
        indicator: 'Potential threat: Punycode character encoding detected (possible homograph impersonation)',
        evidence: u.hostname,
        severity: 'high',
        type: 'homograph_domain'
      });
    }

    // Lookalike / Typosquatting of company brand OR major targeted institutions
    const isExactCompany = u.hostname === companyDomain || u.hostname.endsWith(`.${companyDomain}`);
    const mentionsBrand = companyKeywords.some(bk => u.hostname.includes(bk));
    
    let impersonatedBrand = null;
    if (!isExactCompany && mentionsBrand) {
      impersonatedBrand = companyDomain;
    } else {
      for (const brand of TARGETED_BRANDS) {
        if (u.hostname.includes(brand)) {
          const isLegit = u.hostname === `${brand}.com` || u.hostname.endsWith(`.${brand}.com`);
          if (!isLegit) {
            impersonatedBrand = brand;
            break;
          }
        }
      }
    }

    if (impersonatedBrand) {
      indicators.push({
        indicator: `Possible phishing: Lookalike domain impersonating '${impersonatedBrand}'`,
        evidence: `Extracted host "${u.hostname}" references brand but does not match authoritative domain`,
        severity: 'critical',
        type: 'lookalike_domain'
      });
    }

    // Executable payload detection
    const isExecutable = u.pathname.toLowerCase().endsWith('.exe') || u.pathname.toLowerCase().includes('.pdf.exe') || u.pathname.toLowerCase().endsWith('.scr');
    const isApk = u.pathname.toLowerCase().endsWith('.apk') || u.pathname.toLowerCase().includes('.apk.zip');
    if (isExecutable || isApk) {
      indicators.push({
        indicator: `Critical threat: Malicious executable or APK package payload (${isExecutable ? '.exe' : '.apk'})`,
        evidence: u.normalized,
        severity: 'critical',
        type: 'malicious_payload'
      });
    }

    // Suspicious Path or Sensitive Action combined with unknown domain
    const matchedPathKeywords = SENSITIVE_URL_KEYWORDS.filter(k => u.pathname.includes(k) || u.search.includes(k));
    if (matchedPathKeywords.length > 0 && !isExactCompany) {
      indicators.push({
        indicator: 'Possible phishing: Unverified external domain hosting credential/auth path',
        evidence: `Keywords detected in path: [${matchedPathKeywords.join(', ')}] on ${u.hostname}`,
        severity: 'high',
        type: 'phishing_path'
      });
    }
  }

  // 2. Email Analysis & Domain Mismatch
  for (const em of emails) {
    const isCompany = em.domain === companyDomain || em.domain.endsWith(`.${companyDomain}`);
    const mentionsBrandInUserOrDomain = companyKeywords.some(k => em.email.includes(k));
    
    if (mentionsBrandInUserOrDomain && !isCompany) {
      indicators.push({
        indicator: 'Potential impersonation: Sender email references company identity from external domain',
        evidence: `${em.email} vs authoritative domain ${companyDomain}`,
        severity: 'high',
        type: 'email_domain_mismatch'
      });
    }

    const domainParts = em.domain.split('.');
    const emTld = domainParts[domainParts.length - 1];
    if (SUSPICIOUS_TLDS.has(emTld)) {
      indicators.push({
        indicator: `Suspicious indicator: Email originating from high-risk TLD (.${emTld})`,
        evidence: em.email,
        severity: 'medium',
        type: 'suspicious_email_tld'
      });
    }
  }

  // 3. Social Engineering & Urgency Triggers
  const urgencyPatterns = [
    /\b(urgent|urgently|immediately|immediate action|within 24 hours|within 12 hours|act now|account (has been )?suspended|account (has been )?compromised|immediate response required|your account will be terminated)\b/i
  ];
  for (const pattern of urgencyPatterns) {
    const match = cleanText.match(pattern);
    if (match) {
      indicators.push({
        indicator: 'Suspicious indicator: Manufactured urgency and psychological coercion',
        evidence: `Flagged trigger phrase: "${match[0]}"`,
        severity: 'high',
        type: 'social_engineering_urgency'
      });
      break;
    }
  }

  // 4. Credential Harvesting Triggers
  const credentialPatterns = [
    { regex: /\b(enter|provide|submit|verify|confirm)\s+(your\s+)?(username|password|credentials|login details|passcode)\b/i, name: 'Direct credential harvesting' },
    { regex: /\b(username\s*(?:,|and|\/)\s*password)\b/i, name: 'Username/password pairing request' },
    { regex: /\b(reset\s+your\s+password\s+(?:immediately|here|below))\b/i, name: 'Forced password reset incentive' }
  ];
  for (const cp of credentialPatterns) {
    const match = cleanText.match(cp.regex);
    if (match) {
      indicators.push({
        indicator: `Potential threat: ${cp.name}`,
        evidence: `Matched: "${match[0]}"`,
        severity: 'critical',
        type: 'credential_harvesting'
      });
      break;
    }
  }

  // 5. OTP / Multi-Factor Authentication Capture
  const otpPatterns = [
    /\b(otp|one[-\s]?time[-\s]?password|verification code|security code|2fa code|6[-\s]?digit code|sms code)\b/i
  ];
  for (const op of otpPatterns) {
    const match = cleanText.match(op);
    if (match) {
      indicators.push({
        indicator: 'Potential threat: OTP / 2FA verification code solicitation',
        evidence: `Explicit request for security token: "${match[0]}"`,
        severity: 'critical',
        type: 'otp_harvesting'
      });
      break;
    }
  }

  // 6. Impersonation & Authority Fabrication
  const impersonationPatterns = [
    /\b(it support|security team|compliance officer|fraud prevention department|administrator|support executive|helpdesk agent|cyber security team|legal department)\b/i
  ];
  for (const ip of impersonationPatterns) {
    const match = cleanText.match(ip);
    if (match) {
      // Check if it appears with external links or credentials
      const hasSecurityIndicators = indicators.length > 0;
      indicators.push({
        indicator: hasSecurityIndicators 
          ? 'Potential impersonation: Claims corporate authority while initiating high-risk requests'
          : 'Suspicious indicator: Unverified claim of authority or administrative role',
        evidence: `Authority title invoked: "${match[0]}"`,
        severity: hasSecurityIndicators ? 'high' : 'medium',
        type: 'authority_impersonation'
      });
      break;
    }
  }

  // 7. Financial Extortion & Manipulation
  const financialPatterns = [
    /\b(wire transfer|western union|gift card|crypto|bitcoin|btc|eth|usdt|unauthorized transaction|refund fee|security deposit)\b/i
  ];
  for (const fp of financialPatterns) {
    const match = cleanText.match(fp);
    if (match) {
      const hasUrgencyOrThreat = indicators.some(i => i.type.includes('urgency') || i.severity === 'high' || i.severity === 'critical');
      indicators.push({
        indicator: hasUrgencyOrThreat 
          ? 'Potential threat: Irreversible or non-standard payment mechanism with coercive pressure'
          : 'Suspicious indicator: Non-standard payment or transaction method mentioned',
        evidence: `Payment instrument: "${match[0]}"`,
        severity: hasUrgencyOrThreat ? 'high' : 'medium',
        type: 'financial_manipulation'
      });
      break;
    }
  }

  // Categorize Primary Threat Type & Confidence
  const severities = indicators.map(i => i.severity);
  const hasCritical = severities.includes('critical');
  const hasHigh = severities.includes('high');
  const hasMedium = severities.includes('medium');
  const hasThreat = indicators.length > 0 && (hasCritical || hasHigh || indicators.length >= 2);

  let threatType = 'None';
  if (indicators.some(i => i.type === 'credential_harvesting' || i.type === 'otp_harvesting')) {
    threatType = 'Credential & OTP Harvesting';
  } else if (indicators.some(i => i.type === 'lookalike_domain' || i.type === 'phishing_path')) {
    threatType = 'Phishing';
  } else if (indicators.some(i => i.type === 'social_engineering_urgency' || i.type === 'authority_impersonation')) {
    threatType = 'Social Engineering';
  } else if (indicators.some(i => i.type === 'financial_manipulation')) {
    threatType = 'Financial Fraud Attempt';
  } else if (indicators.some(i => i.type === 'suspicious_url' || i.type === 'suspicious_tld')) {
    threatType = 'Suspicious Link';
  } else if (indicators.length > 0) {
    threatType = 'Suspicious Activity';
  }

  // Calculate Security Score (0 to 100)
  let threatScore = 0;
  for (const ind of indicators) {
    if (ind.severity === 'critical') threatScore += 35;
    else if (ind.severity === 'high') threatScore += 20;
    else if (ind.severity === 'medium') threatScore += 10;
    else threatScore += 5;
  }
  threatScore = Math.min(threatScore, 100);

  return {
    hasThreat,
    threatType,
    threatScore,
    indicatorsCount: indicators.length,
    indicators,
    urlCount: urls.length,
    emailCount: emails.length
  };
}
