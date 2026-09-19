/**
 * Unified Risk Assessment & Decision Engine
 * Computes transparent, explainable risk score and actionable next steps.
 */

export function computeUnifiedRisk(customerIntel, securityAnalysis, preprocessed) {
  let score = 0;
  const reasons = [];

  // 1. Security Indicators Breakdown
  let hasCredentialRequest = false;
  let hasOtpRequest = false;
  let hasSocialEngineering = false;
  let hasPhishingLink = false;
  let hasLookalikeDomain = false;
  let hasMaliciousPayload = false;
  let hasSuspiciousUrl = false;

  for (const ind of securityAnalysis.indicators) {
    if (ind.type === 'credential_harvesting') {
      hasCredentialRequest = true;
      score += 40;
      reasons.push(`Direct credential harvesting attempt detected (${ind.evidence})`);
    } else if (ind.type === 'otp_harvesting') {
      hasOtpRequest = true;
      score += 45;
      reasons.push(`OTP / Two-Factor Authentication token harvesting attempt detected (${ind.evidence})`);
    } else if (ind.type === 'lookalike_domain') {
      hasLookalikeDomain = true;
      score += 70;
      reasons.push(`Corporate impersonation / lookalike domain identified (${ind.evidence})`);
    } else if (ind.type === 'malicious_payload') {
      hasMaliciousPayload = true;
      score += 85;
      reasons.push(`Malicious executable binary or APK file download vector (${ind.evidence})`);
    } else if (ind.type === 'social_engineering_urgency') {
      hasSocialEngineering = true;
      score += 25;
      reasons.push(`Psychological coercion / manufactured urgency detected (${ind.evidence})`);
    } else if (ind.type === 'phishing_path' || ind.type === 'suspicious_url') {
      hasPhishingLink = true;
      score += 25;
      reasons.push(`Suspicious URL or unverified auth path detected (${ind.evidence})`);
    } else if (ind.type === 'authority_impersonation') {
      score += 20;
      reasons.push(`Unverified authority claim or corporate executive impersonation (${ind.evidence})`);
    } else if (ind.type === 'financial_manipulation') {
      score += 25;
      reasons.push(`Irreversible financial transaction or pressure tactics identified (${ind.evidence})`);
    } else if (ind.type === 'homograph_domain') {
      score += 30;
      reasons.push(`Punycode / Homograph domain character spoofing (${ind.evidence})`);
    } else if (ind.type === 'unencrypted_transport') {
      score += 15;
      reasons.push(`Insecure unencrypted transmission (HTTP)`);
    } else if (ind.type === 'url_shortener') {
      score += 15;
      reasons.push(`Obfuscated destination via URL shortener service`);
    }
  }

  // 2. Customer Priority & Sentiment Contribution
  if (customerIntel.priority === 'URGENT') {
    score += 20;
    reasons.push('Customer priority flagged as URGENT');
  } else if (customerIntel.priority === 'HIGH') {
    score += 10;
  }

  if (customerIntel.sentiment === 'Frustrated') {
    score += 10;
    reasons.push('Extreme customer frustration and escalation sentiment detected');
  }

  if (customerIntel.category === 'Account Security') {
    score += 15;
    reasons.push('Ticket involves Account Security compromise');
  }

  if (hasLookalikeDomain || hasMaliciousPayload) {
    score = Math.max(score, 92);
  }

  // Bound score between 0 and 100
  const finalScore = Math.min(100, Math.max(0, score));

  // Determine Risk Tier
  let riskLevel = 'LOW';
  if (finalScore >= 80 || hasLookalikeDomain || hasMaliciousPayload || (hasCredentialRequest && hasOtpRequest) || (hasOtpRequest && hasSocialEngineering) || (hasLookalikeDomain && hasCredentialRequest)) {
    riskLevel = 'CRITICAL';
  } else if (finalScore >= 55 || hasCredentialRequest || hasPhishingLink || hasSocialEngineering) {
    riskLevel = 'HIGH';
  } else if (finalScore >= 30 || customerIntel.priority === 'HIGH' || customerIntel.sentiment === 'Negative') {
    riskLevel = 'MEDIUM';
  }

  if (reasons.length === 0) {
    reasons.push('Standard low-risk customer interaction with no threat indicators observed.');
  }

  // 3. Recommended Action Synthesis
  const recommendedAction = generateRecommendedAction(riskLevel, {
    hasCredentialRequest,
    hasOtpRequest,
    hasSocialEngineering,
    hasPhishingLink,
    hasLookalikeDomain,
    category: customerIntel.category,
    sentiment: customerIntel.sentiment,
    indicators: securityAnalysis.indicators
  });

  return {
    riskLevel,
    riskScore: finalScore,
    reasons,
    recommendedAction
  };
}

function generateRecommendedAction(riskLevel, context) {
  const { hasCredentialRequest, hasOtpRequest, hasPhishingLink, hasSocialEngineering, category, sentiment } = context;

  // Exact recommended action for phishing / credential / OTP attack
  if (riskLevel === 'CRITICAL' || (hasCredentialRequest && hasOtpRequest) || (hasOtpRequest && hasSocialEngineering)) {
    return 'Escalate to security team and avoid following the suspicious link or disclosing credentials.';
  }

  if (riskLevel === 'HIGH') {
    if (hasPhishingLink || context.hasLookalikeDomain) {
      return 'Quarantine message, block referenced domain on gateway firewall, and notify user not to submit login credentials.';
    }
    if (category === 'Account Security') {
      return 'Lock affected account temporarily, initiate out-of-band identity verification, and force credential reset.';
    }
    return 'Assign high-priority specialist to review transaction logs and contact customer via authenticated phone channel.';
  }

  if (riskLevel === 'MEDIUM') {
    if (category === 'Payment Failure') {
      return 'Route ticket to Billing Department with transaction audit logs; request customer verify bank authorization without sharing card numbers.';
    }
    if (category === 'Refund Request') {
      return 'Verify transaction reference against payment processor records and process refund per standard SLA guidelines.';
    }
    if (sentiment === 'Frustrated') {
      return 'Expedite ticket to Tier-2 Customer Support supervisor with empathy response protocol within 2 hours.';
    }
    return 'Review account status and provide standardized troubleshooting guide.';
  }

  // LOW
  return 'Standard queue handling. Provide automated knowledge base resolution or routine customer assistance.';
}
