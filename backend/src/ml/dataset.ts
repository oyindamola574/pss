// pss/backend/src/ml/dataset.ts
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATASET_PATH = path.join(__dirname, "../../data/dataset.json");

export interface LabeledTarget {
  address: string;
  type: "PROGRAM" | "WALLET" | "PDA" | "TRANSACTION";
  features: [number, number, number, number]; // [bytecodeSizeKb, txCount, solBalance, failedChecks]
  label: "SAFE" | "WARNING" | "CRITICAL";
  vulnerabilities: string[];
  description: string;
}

export function loadDataset(): LabeledTarget[] {
  if (!fs.existsSync(DATASET_PATH)) {
    throw new Error(`Missing required live labeled dataset: ${DATASET_PATH}`);
  }

  let data: LabeledTarget[];
  try {
    data = JSON.parse(fs.readFileSync(DATASET_PATH, "utf-8"));
  } catch (e) {
    throw new Error(`Unable to read labeled dataset: ${(e as Error).message}`);
  }

  if (!Array.isArray(data) || data.length === 0) {
    throw new Error(`Labeled dataset is empty or invalid: ${DATASET_PATH}`);
  }

  return data;
}

export function saveDataset(data: LabeledTarget[]) {
  const dir = path.dirname(DATASET_PATH);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(DATASET_PATH, JSON.stringify(data, null, 2));
}
