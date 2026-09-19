import { preprocessInput } from '../server/engines/preprocessor.js';
import { analyzeSecurity } from '../server/engines/securityEngine.js';

export function runSecurityTests() {
  console.log('🧪 Testing Security Engine (Deterministic Rules)...');
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

  // Test 1: URL extraction and IP detection
  const ipText = 'Access your invoice here: http://192.168.1.50:8080/login';
  const p1 = preprocessInput(ipText);
  assert(p1.urls.length === 1, 'Extracted 1 URL');
  assert(p1.urls[0].isIP === true, 'Detected IP-based host address');
  
  const s1 = analyzeSecurity(p1, { companyDomain: 'novapay.io' });
  assert(s1.hasThreat === true, 'Flagged IP URL as threat');
  assert(s1.indicators.some(i => i.type === 'suspicious_url'), 'Generated suspicious_url indicator');

  // Test 2: Lookalike domain detection
  const lookalikeText = 'Verify your NovaPay account at https://novapay-security-verify.com/login';
  const p2 = preprocessInput(lookalikeText);
  const s2 = analyzeSecurity(p2, { companyDomain: 'novapay.io' });
  assert(s2.indicators.some(i => i.type === 'lookalike_domain'), 'Detected corporate lookalike domain impersonation');
  assert(s2.indicators.some(i => i.severity === 'critical'), 'Lookalike domain flagged as critical severity');

  // Test 3: Credential and OTP harvesting detection
  const credText = 'Please enter your username, password and OTP immediately.';
  const p3 = preprocessInput(credText);
  const s3 = analyzeSecurity(p3);
  assert(s3.indicators.some(i => i.type === 'credential_harvesting'), 'Detected direct credential harvesting');
  assert(s3.indicators.some(i => i.type === 'otp_harvesting'), 'Detected OTP verification code solicitation');
  assert(s3.indicators.some(i => i.type === 'social_engineering_urgency'), 'Detected urgency psychological coercion');

  // Test 4: Benign text produces no false threat
  const benignText = 'Hi support, could you clarify when our next invoice will be issued? Thanks!';
  const p4 = preprocessInput(benignText);
  const s4 = analyzeSecurity(p4);
  assert(s4.hasThreat === false, 'Benign text does not trigger threat flag');
  assert(s4.threatType === 'None', 'Benign text threatType is None');

  console.log(`Security Engine Tests: ${passed}/${total} passed.\n`);
  return { passed, total };
}
