import { runSecurityTests } from './securityEngine.test.js';
import { runCustomerIntelTests } from './customerIntelligence.test.js';
import { runRiskEngineTests } from './riskEngine.test.js';
import { runIntegrationTests } from './integration.test.js';

async function main() {
  console.log('===========================================================');
  console.log('🏁 RUNNING FULL AUTOMATED TEST SUITE');
  console.log('===========================================================\n');

  let totalPassed = 0;
  let totalTests = 0;

  const s = runSecurityTests();
  totalPassed += s.passed;
  totalTests += s.total;

  const c = runCustomerIntelTests();
  totalPassed += c.passed;
  totalTests += c.total;

  const r = runRiskEngineTests();
  totalPassed += r.passed;
  totalTests += r.total;

  const i = await runIntegrationTests();
  totalPassed += i.passed;
  totalTests += i.total;

  console.log('===========================================================');
  if (totalPassed === totalTests) {
    console.log(`🎉 ALL TESTS PASSED: ${totalPassed}/${totalTests} (100% GREEN)`);
    console.log('===========================================================');
    process.exit(0);
  } else {
    console.error(`⚠️ SOME TESTS FAILED: ${totalPassed}/${totalTests}`);
    console.log('===========================================================');
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Fatal Test Runner Error:', err);
  process.exit(1);
});
