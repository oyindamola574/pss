// pss/frontend/src/types.ts
export type ThreatSeverity = "INFO" | "WARNING" | "HIGH" | "CRITICAL";

export interface ThreatFinding {
  type: string;
  severity: ThreatSeverity;
  description: string;
  remediation: string;
  location?: string;
}

export interface ForensicData {
  slot: number;
  blockTime: number | null;
  signerCount: number;
  instructionCount: number;
  innerCallCount: number;
  programsInvoked: string[];
  fee: number;
}

export interface ScanReport {
  success: boolean;
  scanId: string;
  targetAddress: string;
  addressType: "PROGRAM" | "WALLET" | "PDA" | "TRANSACTION" | "UNKNOWN";
  riskScore: number;
  severity: "SAFE" | "WARNING" | "CRITICAL";
  confidence: number;
  threats: ThreatFinding[];
  forensics: ForensicData | null;
  telemetry: {
    bytecodeSizeKb: number;
    txCount: number;
    solBalance: number;
    executable: boolean;
    owner: string;
  };
  mlProbabilities: { SAFE: number; WARNING: number; CRITICAL: number };
  signature: string;
  scanFeeSOL: number;
  scannedAt: string;
  reportUrl: string;
  explorerUrl: string;
}

export interface Comment {
  id: string;
  user: string;
  text: string;
  createdAt: string;
}

export interface SecurityTask {
  id: string;
  title: string;
  description: string;
  targetAddress: string;
  status: "Pending" | "In Progress" | "Review" | "Completed";
  priority: "Low" | "Medium" | "High" | "Urgent";
  assignedTo: string[];
  createdBy: string;
  createdAt: string;
  riskScore: number;
  severity: "SAFE" | "WARNING" | "CRITICAL";
  vulnerabilities: ThreatFinding[];
  comments: Comment[];
  projectLink: string;
  signature?: string;
  reportUrl: string;
}

export interface ThreatOption {
  key: string;
  label: string;
  baseSeverity: ThreatSeverity;
}

export interface WsMessage {
  type: "WELCOME" | "SCAN_PROGRESS" | "SCAN_COMPLETED" | "ACTIVITY_UPDATE";
  msg?: string;
  progress?: number;
  task?: SecurityTask;
  report?: ScanReport;
  message?: string;
  taskId?: string;
}

export interface BenchmarkMetrics {
  total: number;
  accuracy: number;
  precision: { SAFE: number; WARNING: number; CRITICAL: number };
  recall: { SAFE: number; WARNING: number; CRITICAL: number };
  falsePositiveRate: number;
  avgLatencyMs: number;
  baselineAccuracy: number;
}
