import { preprocessInput } from '../server/engines/preprocessor.js';
import { analyzeSecurity } from '../server/engines/securityEngine.js';
import { analyzeCustomerIntelligence } from '../server/engines/customerIntelligence.js';
import { computeUnifiedRisk } from '../server/engines/riskEngine.js';

export function runRiskEngineTests() {
  console.log('🧪 Testing Unified Risk Engine...');
  let passed = 0;
  let total = 0;

  function assert(condition, message) {
    total++;
    if (condition) {
      passed++;
      console.log(`  ✅ ${message}`);
    } else {
      console.error(`  ❌ FAIL: ${message}`);
    }
  }

  // Test 1: Low-risk routine inquiry
  const lowText = 'Hi, where can I download our monthly invoice PDF?';
  const p1 = preprocessInput(lowText);
  const s1 = analyzeSecurity(p1);
  const c1 = analyzeCustomerIntelligence(p1, s1);
  const r1 = computeUnifiedRisk(c1, s1, p1);
  assert(r1.riskLevel === 'LOW', `Routine inquiry classified as LOW risk (got: ${r1.riskLevel})`);

  // Test 2: Critical Phishing & Credential Attack
  const critText = 'URGENT! Your account has been compromised. Click this link immediately and enter your username, password and OTP.';
  const p2 = preprocessInput(critText);
  const s2 = analyzeSecurity(p2);
  const c2 = analyzeCustomerIntelligence(p2, s2);
  const r2 = computeUnifiedRisk(c2, s2, p2);

  assert(r2.riskLevel === 'CRITICAL', `Mandatory E2E threat classified as CRITICAL (got: ${r2.riskLevel})`);
  assert(r2.reasons.length >= 3, `Provides multiple transparent reasons (got: ${r2.reasons.length})`);
  assert(
    r2.recommendedAction.includes('Escalate to security team') && 
    r2.recommendedAction.includes('avoid following the suspicious link or disclosing credentials'),
    `Recommended action matches security mandate: "${r2.recommendedAction}"`
  );

  console.log(`Unified Risk Engine Tests: ${passed}/${total} passed.\n`);
  return { passed, total };
}
