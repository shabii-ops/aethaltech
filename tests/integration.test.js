import { processPipeline } from '../server/engines/aiHybrid.js';
import { db } from '../server/db.js';

export async function runIntegrationTests() {
  console.log('🧪 Testing Integration & End-to-End Pipeline...');
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

  // =========================================================================
  // MANDATORY HACKATHON END-TO-END TEST
  // =========================================================================
  const mandateInput = "URGENT! Your account has been compromised. Click this link immediately and enter your username, password and OTP.";
  
  console.log('  Executing Mandatory E2E Test Case:');
  console.log(`  Input: "${mandateInput}"`);

  const e2eResult = await processPipeline(mandateInput, { source: 'E2E Test Runner' });

  // 1. Customer Intelligence checks
  assert(e2eResult.customerIntelligence.category === 'Account Security', 
    `Category is Account Security (got: ${e2eResult.customerIntelligence.category})`);
  
  assert(['Negative', 'Frustrated'].includes(e2eResult.customerIntelligence.sentiment), 
    `Sentiment is Negative/Frustrated (got: ${e2eResult.customerIntelligence.sentiment})`);

  assert(['HIGH', 'URGENT'].includes(e2eResult.customerIntelligence.priority), 
    `Customer Priority is High/Urgent (got: ${e2eResult.customerIntelligence.priority})`);

  // 2. Security Intelligence checks
  const indTypes = e2eResult.securityAnalysis.indicators.map(i => i.type);
  assert(indTypes.includes('credential_harvesting'), 'Security Engine flags Credential Request');
  assert(indTypes.includes('otp_harvesting'), 'Security Engine flags OTP Request');
  assert(indTypes.includes('social_engineering_urgency'), 'Security Engine flags Social Engineering / Urgency');
  assert(e2eResult.securityAnalysis.hasThreat === true, 'Security Engine marks hasThreat = true');

  // 3. Risk Engine checks
  assert(e2eResult.riskAssessment.riskLevel === 'CRITICAL', 
    `Risk Engine evaluates to CRITICAL (got: ${e2eResult.riskAssessment.riskLevel}, score: ${e2eResult.riskAssessment.riskScore})`);

  assert(
    e2eResult.riskAssessment.recommendedAction === 'Escalate to security team and avoid following the suspicious link or disclosing credentials.',
    `Recommended Action matches exact requirement: "${e2eResult.riskAssessment.recommendedAction}"`
  );

  // 4. Database Persistence & Retrieval
  const initialCount = db.records.length;
  const saved = db.insert(e2eResult);
  assert(Boolean(saved.id), `Record persisted to database with ID: ${saved.id}`);
  assert(db.records.length === initialCount + 1, 'Database record count increased');

  const retrieved = db.getById(saved.id);
  assert(retrieved && retrieved.inputText === mandateInput, 'Retrieved exact record from database');

  // 5. Update Status
  const updated = db.updateStatus(saved.id, 'Escalated');
  assert(updated && updated.status === 'Escalated', 'Successfully updated status to Escalated');

  // 6. Dashboard Statistics Generation
  const stats = db.getStats();
  assert(typeof stats.total === 'number' && stats.total > 0, `Stats accurately counts total records (${stats.total})`);
  assert(stats.riskBreakdown.CRITICAL >= 1, `Stats accurately includes CRITICAL risk count (${stats.riskBreakdown.CRITICAL})`);
  assert(typeof stats.threatRate === 'number', `Stats computes dynamic threat percentage (${stats.threatRate}%)`);

  // 7. URL Direct Ingestion
  const urlResult = await processPipeline('http://185.220.101.5/billing/update.php?user=admin');
  assert(urlResult.securityAnalysis.hasThreat === true, 'URL ingestion directly detects threat');
  assert(urlResult.preprocessed.urlCount === 1, 'URL count in preprocessed is 1');

  // 8. Email Direct Ingestion
  const emailResult = await processPipeline('Contact phishing-support@novapay-fraud-center.xyz regarding urgent wire transfer');
  assert(emailResult.preprocessed.emailCount === 1, 'Email extracted');
  assert(emailResult.securityAnalysis.indicators.length > 0, 'Email triggers indicators');

  console.log(`Integration & E2E Tests: ${passed}/${total} passed.\n`);
  return { passed, total };
}
