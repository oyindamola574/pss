// pss/backend/src/ml/benchmark.ts
import { loadDataset } from "./dataset.js";
import { classifySecurityTarget } from "./knnClassifier.js";

export interface BenchmarkMetrics {
  total: number;
  accuracy: number;
  precision: { SAFE: number; WARNING: number; CRITICAL: number };
  recall: { SAFE: number; WARNING: number; CRITICAL: number };
  falsePositiveRate: number;
  avgLatencyMs: number;
  baselineAccuracy: number;
}

export function runBenchmark(): BenchmarkMetrics {
  const dataset = loadDataset();
  let correct = 0;
  let baselineCorrect = 0;

  // Track confusion matrix counts: [Actual][Predicted]
  const classes = ["SAFE", "WARNING", "CRITICAL"] as const;
  type ClassType = typeof classes[number];

  const counts: Record<ClassType, Record<ClassType, number>> = {
    SAFE: { SAFE: 0, WARNING: 0, CRITICAL: 0 },
    WARNING: { SAFE: 0, WARNING: 0, CRITICAL: 0 },
    CRITICAL: { SAFE: 0, WARNING: 0, CRITICAL: 0 },
  };

  const startTime = process.hrtime.bigint();

  for (const target of dataset) {
    const [bytecode, txs, balance, failedChecks] = target.features;
    const pred = classifySecurityTarget(bytecode, txs, balance, failedChecks);

    counts[target.label][pred.severity]++;

    if (pred.severity === target.label) {
      correct++;
    }

    // Naive baseline rule
    let baselinePred: ClassType = "SAFE";
    if (failedChecks > 0 && failedChecks < 4) {
      baselinePred = "WARNING";
    } else if (failedChecks >= 4) {
      baselinePred = "CRITICAL";
    }

    if (baselinePred === target.label) {
      baselineCorrect++;
    }
  }

  const endTime = process.hrtime.bigint();
  const latencyMs = Number(endTime - startTime) / 1e6; // nanoseconds to milliseconds

  // Calculate Precision and Recall
  const precision: Record<ClassType, number> = { SAFE: 0, WARNING: 0, CRITICAL: 0 };
  const recall: Record<ClassType, number> = { SAFE: 0, WARNING: 0, CRITICAL: 0 };

  for (const c of classes) {
    const actualTotal = counts[c].SAFE + counts[c].WARNING + counts[c].CRITICAL;
    const predictedTotal = counts.SAFE[c] + counts.WARNING[c] + counts.CRITICAL[c];

    precision[c] = predictedTotal > 0 ? counts[c][c] / predictedTotal : 0;
    recall[c] = actualTotal > 0 ? counts[c][c] / actualTotal : 0;
  }

  // False Positive Rate: False Positives / (False Positives + True Negatives)
  // For security, a false positive is predicting WARNING or CRITICAL when actual is SAFE
  const fp = counts.SAFE.WARNING + counts.SAFE.CRITICAL;
  const tn = counts.SAFE.SAFE;
  const falsePositiveRate = (fp + tn) > 0 ? fp / (fp + tn) : 0;

  return {
    total: dataset.length,
    accuracy: correct / dataset.length,
    precision,
    recall,
    falsePositiveRate,
    avgLatencyMs: latencyMs / dataset.length,
    baselineAccuracy: baselineCorrect / dataset.length,
  };
}

// If run directly from terminal
const isDirectRun = process.argv[1] && (process.argv[1].endsWith("benchmark.ts") || process.argv[1].endsWith("benchmark.js"));
if (isDirectRun) {
  console.log("==================================================");
  console.log("🧪 RUNNING PROTOCOL SECURITY SCOUT BENCHMARK HARNESS");
  console.log("==================================================");

  const metrics = runBenchmark();
  console.log(`\nTotal Labeled Examples: ${metrics.total}`);
  console.log(`KNN Classifier Accuracy: ${(metrics.accuracy * 100).toFixed(2)}%`);
  console.log(`Baseline Heuristic Accuracy: ${(metrics.baselineAccuracy * 100).toFixed(2)}%`);
  console.log(`False Positive Rate: ${(metrics.falsePositiveRate * 100).toFixed(2)}%`);
  console.log(`Average Inference Latency: ${metrics.avgLatencyMs.toFixed(4)} ms`);

  console.log("\nClass-Specific Performance Metrics:");
  console.log("--------------------------------------------------");
  console.log("Class    | Precision | Recall");
  console.log("--------------------------------------------------");
  for (const c of ["SAFE", "WARNING", "CRITICAL"] as const) {
    console.log(`${c.padEnd(8)} | ${(metrics.precision[c] * 100).toFixed(1).padStart(8)}% | ${(metrics.recall[c] * 100).toFixed(1).padStart(5)}%`);
  }
  console.log("--------------------------------------------------");
}
