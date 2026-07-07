// pss/backend/src/server.ts
import express, { Request, Response } from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { createServer } from "http";
import { WebSocketServer, WebSocket } from "ws";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

import { classifySecurityTarget } from "./ml/knnClassifier.js";
import { verifyPayment, resolveAndScanTarget, VAULT_ADDRESS, THREAT_REGISTRY } from "./solana.js";
import contextRouter from "./routes/context.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.join(__dirname, "../data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const LEDGER_PATH = path.join(DATA_DIR, "ledger.jsonl");
const TASKS_PATH  = path.join(DATA_DIR, "tasks.json");
const REPORTS_DIR = path.join(DATA_DIR, "reports");
if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });

// ── Pricing (matches build_plan.md) ──────────────────────────────────────────
const FEE_GENERAL      = parseFloat(process.env.SCAN_FEE_GENERAL        ?? "0.02");
const FEE_CUSTOM_BASE  = parseFloat(process.env.SCAN_FEE_CUSTOM_BASE    ?? "0.01");
const FEE_PER_THREAT   = parseFloat(process.env.SCAN_FEE_CUSTOM_PER_THREAT ?? "0.005");

export function calcScanFee(selectedThreats: string[]): number {
  if (selectedThreats.length === 0) return FEE_GENERAL;
  return Math.round((FEE_CUSTOM_BASE + FEE_PER_THREAT * selectedThreats.length) * 1000) / 1000;
}

// ── Types ─────────────────────────────────────────────────────────────────────
export interface Comment { id: string; user: string; text: string; createdAt: string; }

export interface SecurityTask {
  id: string; title: string; description: string; targetAddress: string;
  status: "Pending" | "In Progress" | "Review" | "Completed";
  priority: "Low" | "Medium" | "High" | "Urgent";
  assignedTo: string[]; createdBy: string; createdAt: string;
  riskScore: number; severity: "SAFE" | "WARNING" | "CRITICAL";
  vulnerabilities: any[]; comments: Comment[];
  projectLink: string; signature?: string; reportUrl: string;
}

// ── Task Persistence ──────────────────────────────────────────────────────────
let tasks: SecurityTask[] = [];
if (fs.existsSync(TASKS_PATH)) {
  try { tasks = JSON.parse(fs.readFileSync(TASKS_PATH, "utf-8")); } catch { tasks = []; }
} else {
  tasks = [{
    id: "scan-seed-1", title: "Audit: SPL Token Program",
    description: "Review safety profile of the core token library on-chain.",
    targetAddress: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    status: "Completed", priority: "Urgent",
    assignedTo: ["Security Lead"], createdBy: "System",
    createdAt: new Date(Date.now() - 86400000).toISOString(),
    riskScore: 3, severity: "SAFE", vulnerabilities: [],
    comments: [{ id: "c-1", user: "Security Lead",
      text: "Verified on-chain bytecode matches SPL release build. Zero vulnerabilities found.",
      createdAt: new Date(Date.now() - 72000000).toISOString() }],
    projectLink: "https://explorer.solana.com/address/TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA?cluster=devnet",
    reportUrl: "/api/reports/scan-seed-1",
  }];
  fs.writeFileSync(TASKS_PATH, JSON.stringify(tasks, null, 2));
}

function saveTasks() { fs.writeFileSync(TASKS_PATH, JSON.stringify(tasks, null, 2)); }

function logToLedger(type: string, payload: any) {
  fs.appendFileSync(LEDGER_PATH, JSON.stringify({ timestamp: new Date().toISOString(), type, ...payload }) + "\n");
}

function saveReport(scanId: string, report: any) {
  fs.writeFileSync(path.join(REPORTS_DIR, `${scanId}.json`), JSON.stringify(report, null, 2));
}

function loadReport(scanId: string): any | null {
  const p = path.join(REPORTS_DIR, `${scanId}.json`);
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, "utf-8")); } catch { return null; }
}

// ── App + Middleware ───────────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200,
  message: { error: "Too many requests. Please slow down." } }));
app.use("/api/context", contextRouter);

// ── WebSocket Server ──────────────────────────────────────────────────────────
const httpServer = createServer(app);
const wss = new WebSocketServer({ server: httpServer });
const clients = new Set<WebSocket>();

wss.on("connection", ws => {
  clients.add(ws);
  ws.send(JSON.stringify({ type: "WELCOME", message: "Connected to PSS Security Bus" }));
  ws.on("close", () => clients.delete(ws));
});

function broadcast(payload: any) {
  const msg = JSON.stringify(payload);
  clients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg); });
}

// ── Routes ────────────────────────────────────────────────────────────────────

// GET /api/config — returns vault address, cluster, pricing
app.get("/api/config", (_req: Request, res: Response) => {
  res.json({
    vaultAddress: VAULT_ADDRESS, cluster: "devnet",
    pricing: { general: FEE_GENERAL, customBase: FEE_CUSTOM_BASE, perThreat: FEE_PER_THREAT },
    threats: THREAT_REGISTRY.map(t => ({ key: t.key, label: t.label, baseSeverity: t.baseSeverity })),
  });
});

// POST /api/scan/submit — full pipeline
app.post("/api/scan/submit", async (req: Request, res: Response) => {
  const { signature, targetAddress, selectedThreats = [], customPattern, userRole } = req.body;
  if (!signature || !targetAddress) {
    return res.status(400).json({ success: false, error: "Missing signature or targetAddress" });
  }

  // Dynamic fee from request (validate on our side)
  const expectedFee = calcScanFee(selectedThreats);

  try {
    // Stage 1: Payment
    broadcast({ type: "SCAN_PROGRESS", progress: 10, msg: "Verifying payment on Solana Devnet..." });
    const paid = await verifyPayment(signature, expectedFee);
    if (!paid) {
      logToLedger("PAYMENT_FAILED", { signature, targetAddress, expectedFee });
      return res.status(402).json({ success: false, error: `Payment verification failed. Expected ${expectedFee} SOL.` });
    }
    logToLedger("PAYMENT_SUCCESS", { signature, targetAddress, fee: expectedFee });

    // Stage 2: Resolve target
    broadcast({ type: "SCAN_PROGRESS", progress: 35, msg: "Fetching Solana Devnet account metadata..." });
    const targetInfo = await resolveAndScanTarget(targetAddress, selectedThreats, customPattern);

    // Stage 3: ML scoring
    broadcast({ type: "SCAN_PROGRESS", progress: 65, msg: "Running Iris KNN risk classifier..." });
    const prediction = classifySecurityTarget(
      targetInfo.bytecodeSizeKb, targetInfo.txCount,
      targetInfo.solBalance, targetInfo.failedChecks
    );

    // Stage 4: Report
    broadcast({ type: "SCAN_PROGRESS", progress: 88, msg: "Generating audit report..." });

    const scanId = `scan-${Date.now()}`;
    const reportUrl = `/api/reports/${scanId}`;

    // Build the API response matching build_plan.md spec exactly
    const report = {
      success: true,
      scanId,
      targetAddress,
      addressType: targetInfo.type,
      riskScore: prediction.riskScore,
      severity: prediction.severity,
      confidence: Math.round(prediction.confidence * 100),
      threats: targetInfo.vulnerabilities,
      forensics: targetInfo.forensics ?? null,
      telemetry: {
        bytecodeSizeKb: targetInfo.bytecodeSizeKb,
        txCount: targetInfo.txCount,
        solBalance: targetInfo.solBalance,
        executable: targetInfo.executable,
        owner: targetInfo.owner,
      },
      mlProbabilities: prediction.probabilities,
      signature,
      scanFeeSOL: expectedFee,
      scannedAt: new Date().toISOString(),
      reportUrl,
      explorerUrl: `https://explorer.solana.com/address/${targetAddress}?cluster=devnet`,
    };

    saveReport(scanId, report);

    // Save to TMS task board
    const newTask: SecurityTask = {
      id: scanId,
      title: `Audit: ${targetAddress.slice(0, 8)}… (${targetInfo.type})`,
      description: `Security risk assessment for ${targetAddress}.`,
      targetAddress, signature, reportUrl,
      status: targetInfo.failedChecks > 0 ? "Review" : "Completed",
      priority: prediction.severity === "CRITICAL" ? "Urgent" : prediction.severity === "WARNING" ? "High" : "Medium",
      assignedTo: userRole === "Project Manager" ? ["Developer Lead"] : ["Self"],
      createdBy: userRole ?? "External User",
      createdAt: new Date().toISOString(),
      riskScore: prediction.riskScore,
      severity: prediction.severity,
      vulnerabilities: targetInfo.vulnerabilities,
      comments: [],
      projectLink: report.explorerUrl,
    };
    tasks.unshift(newTask);
    saveTasks();

    logToLedger("SCAN_SUCCESS", { scanId, targetAddress, riskScore: prediction.riskScore, severity: prediction.severity });
    broadcast({ type: "SCAN_COMPLETED", task: newTask, report });
    broadcast({ type: "ACTIVITY_UPDATE", message: `New audit: ${targetAddress.slice(0, 8)}… — Risk ${prediction.riskScore}%` });

    return res.status(200).json(report);
  } catch (err: any) {
    console.error("[Server] Scan error:", err.message);
    logToLedger("SCAN_ERROR", { signature, targetAddress, error: err.message });
    broadcast({ type: "SCAN_PROGRESS", progress: 0, msg: `Error: ${err.message}` });
    return res.status(500).json({ success: false, error: "Internal scan error" });
  }
});

// GET /api/reports/:id — fetch stored report JSON
app.get("/api/reports/:id", (req: Request, res: Response) => {
  const report = loadReport(req.params.id);
  if (!report) return res.status(404).json({ error: "Report not found" });
  res.json(report);
});

// GET /api/reports/:id/export — download as JSON file
app.get("/api/reports/:id/export", (req: Request, res: Response) => {
  const report = loadReport(req.params.id);
  if (!report) return res.status(404).json({ error: "Report not found" });
  res.setHeader("Content-Disposition", `attachment; filename="pss-report-${req.params.id}.json"`);
  res.setHeader("Content-Type", "application/json");
  res.send(JSON.stringify(report, null, 2));
});

// GET /api/tasks — TMS board
app.get("/api/tasks", (_req: Request, res: Response) => res.json(tasks));

// GET /api/tasks/:id
app.get("/api/tasks/:id", (req: Request, res: Response) => {
  const task = tasks.find(t => t.id === req.params.id);
  if (!task) return res.status(404).json({ error: "Task not found" });
  res.json(task);
});

// POST /api/tasks/:id/status
app.post("/api/tasks/:id/status", (req: Request, res: Response) => {
  const task = tasks.find(t => t.id === req.params.id);
  if (!task) return res.status(404).json({ error: "Task not found" });
  const old = task.status;
  task.status = req.body.status;
  saveTasks();
  logToLedger("TASK_STATUS_UPDATED", { taskId: task.id, old, new: task.status });
  broadcast({ type: "ACTIVITY_UPDATE", message: `Task "${task.title}" moved to ${task.status}`, taskId: task.id });
  res.json(task);
});

// POST /api/tasks/:id/comment
app.post("/api/tasks/:id/comment", (req: Request, res: Response) => {
  const { user, text } = req.body;
  if (!user || !text) return res.status(400).json({ error: "Missing user or text" });
  const task = tasks.find(t => t.id === req.params.id);
  if (!task) return res.status(404).json({ error: "Task not found" });
  const comment: Comment = { id: `c-${Date.now()}`, user, text, createdAt: new Date().toISOString() };
  task.comments.push(comment);
  saveTasks();
  logToLedger("TASK_COMMENT_ADDED", { taskId: task.id, user, commentId: comment.id });
  broadcast({ type: "ACTIVITY_UPDATE", message: `${user} commented on "${task.title}"`, taskId: task.id });
  res.json(task);
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT ?? 5000;
httpServer.listen(PORT, () => {
  console.log(`🚀 PSS Backend on port ${PORT} | Vault: ${VAULT_ADDRESS}`);
});
