// pss/backend/tests/knn.test.ts
import { classifySecurityTarget } from "../src/ml/knnClassifier.js";

function runTest() {
  console.log("--------------------------------------------------");
  console.log("🧪 RUNNING KNN SECURITY RISK CLASSIFIER TEST SUITE");
  console.log("--------------------------------------------------");

  // Test Case 1: SPL Token Program (Simulated Safe profile)
  // 450 KB bytecode, 800 transactions, 1000 SOL balance, 0 failed checks
  const safeProfile = classifySecurityTarget(450, 800, 1000, 0);
  console.log("\nCase 1: Well-known Secure Contract (SPL Token Style)");
  console.log(`- Severity: ${safeProfile.severity} (Expected: SAFE)`);
  console.log(`- Risk Score: ${safeProfile.riskScore}%`);
  console.log(`- Probabilities: Safe=${safeProfile.probabilities.SAFE * 100}%, Warning=${safeProfile.probabilities.WARNING * 100}%, Critical=${safeProfile.probabilities.CRITICAL * 100}%`);
  
  if (safeProfile.severity !== "SAFE") {
    console.error("❌ Test Case 1 Failed!");
    process.exit(1);
  }

  // Test Case 2: PDA Mutation Vulnerable Contract (Simulated Warning profile)
  // 120 KB bytecode, 250 transactions, 50 SOL balance, 3 failed checks
  const warningProfile = classifySecurityTarget(120, 250, 50, 3);
  console.log("\nCase 2: Moderate Risk Contract (3 failed security checks)");
  console.log(`- Severity: ${warningProfile.severity} (Expected: WARNING)`);
  console.log(`- Risk Score: ${warningProfile.riskScore}%`);
  console.log(`- Probabilities: Safe=${warningProfile.probabilities.SAFE * 100}%, Warning=${warningProfile.probabilities.WARNING * 100}%, Critical=${warningProfile.probabilities.CRITICAL * 100}%`);

  if (warningProfile.severity !== "WARNING") {
    console.error("❌ Test Case 2 Failed!");
    process.exit(1);
  }

  // Test Case 3: Exploit Script / Shell Account (Simulated Critical profile)
  // 20 KB bytecode, 10 transactions, 0.05 SOL balance, 6 failed checks
  const criticalProfile = classifySecurityTarget(20, 10, 0.05, 6);
  console.log("\nCase 3: Insecure / Critical Risk Contract (6 failed checks, empty balance)");
  console.log(`- Severity: ${criticalProfile.severity} (Expected: CRITICAL)`);
  console.log(`- Risk Score: ${criticalProfile.riskScore}%`);
  console.log(`- Probabilities: Safe=${criticalProfile.probabilities.SAFE * 100}%, Warning=${criticalProfile.probabilities.WARNING * 100}%, Critical=${criticalProfile.probabilities.CRITICAL * 100}%`);

  if (criticalProfile.severity !== "CRITICAL") {
    console.error("❌ Test Case 3 Failed!");
    process.exit(1);
  }

  console.log("\n--------------------------------------------------");
  console.log("✅ ALL KNN SECURITY CLASS TEST CASES PASSED SUCCESSFULLY!");
  console.log("--------------------------------------------------");
}

runTest();
