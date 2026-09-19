import { preprocessInput } from '../server/engines/preprocessor.js';
import { analyzeCustomerIntelligence } from '../server/engines/customerIntelligence.js';

export function runCustomerIntelTests() {
  console.log('🧪 Testing Customer Intelligence Engine...');
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

  // Test 1: Payment Failure classification
  const paymentText = 'Our credit card was declined and payment failed with error ERR_502 on checkout.';
  const p1 = preprocessInput(paymentText);
  const c1 = analyzeCustomerIntelligence(p1);
  assert(c1.category === 'Payment Failure', `Correctly classified as Payment Failure (got: ${c1.category})`);

  // Test 2: Refund Request classification
  const refundText = 'I want a full refund for my subscription renewal under your money back policy.';
  const p2 = preprocessInput(refundText);
  const c2 = analyzeCustomerIntelligence(p2);
  assert(c2.category === 'Refund Request', `Correctly classified as Refund Request (got: ${c2.category})`);

  // Test 3: Frustrated sentiment detection
  const frustText = 'THIS IS UNACCEPTABLE!! I AM LIVID!! You stole our money and your service is completely useless!';
  const p3 = preprocessInput(frustText);
  const c3 = analyzeCustomerIntelligence(p3);
  assert(c3.sentiment === 'Frustrated', `Correctly detected Frustrated sentiment (got: ${c3.sentiment})`);
  assert(c3.sentimentScore < -0.3, `Sentiment polarity is negative (${c3.sentimentScore})`);

  // Test 4: Positive sentiment
  const posText = 'Thank you so much for the swift help! The resolution was great and fast.';
  const p4 = preprocessInput(posText);
  const c4 = analyzeCustomerIntelligence(p4);
  assert(c4.sentiment === 'Positive', `Correctly detected Positive sentiment (got: ${c4.sentiment})`);

  // Test 5: Keyword and summary generation
  assert(Array.isArray(c1.extractedKeywords) && c1.extractedKeywords.length > 0, 'Extracted salient keywords');
  assert(typeof c1.summary === 'string' && c1.summary.length > 10, 'Generated informative summary');

  console.log(`Customer Intelligence Tests: ${passed}/${total} passed.\n`);
  return { passed, total };
}
