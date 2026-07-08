// pss/frontend/src/components/ReportView.tsx
import { CheckCircle, AlertTriangle, XCircle, Download, ExternalLink, Shield, BarChart2, Terminal } from "lucide-react";
import type { ScanReport } from "../types";

interface Props {
  report: ScanReport;
}

const SEV_CONFIG = {
  CRITICAL: { bg: "bg-red-950/20", text: "text-red-400", border: "border-red-900/40", icon: <XCircle className="w-4 h-4" /> },
  HIGH: { bg: "bg-orange-950/20", text: "text-orange-400", border: "border-orange-900/40", icon: <AlertTriangle className="w-4 h-4" /> },
  WARNING: { bg: "bg-amber-950/20", text: "text-amber-400", border: "border-amber-900/40", icon: <AlertTriangle className="w-4 h-4" /> },
  INFO: { bg: "bg-blue-950/20", text: "text-blue-400", border: "border-blue-900/40", icon: <Shield className="w-4 h-4" /> },
};

const SCORE_COLOR = (s: number) =>
  s >= 70 ? "border-red-500 text-red-400"
    : s >= 35 ? "border-amber-500 text-amber-400"
      : "border-emerald-500 text-emerald-400";

function exportJson(report: ScanReport) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `pss-report-${report.scanId}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ReportView({ report }: Props) {
  const sc = SEV_CONFIG[report.severity === "SAFE" ? "INFO" : report.severity] ?? SEV_CONFIG.INFO;

  return (
    <div className="glass rounded-2xl p-6 flex flex-col gap-6 shadow-xl">
      {/* Header */}
      <div className="flex justify-between items-start border-b border-white/5 pb-4 gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className={`text-[10px] font-extrabold px-2.5 py-1 rounded-full border uppercase tracking-wider ${sc.bg} ${sc.text} ${sc.border}`}>
              {report.severity}
            </span>
            <span className="text-[10px] text-gray-400 font-mono bg-[#0d1525] px-2 py-0.5 rounded border border-white/5">
              {report.addressType}
            </span>
          </div>
          <h2 className="text-base font-bold text-white font-mono break-all">
            {report.targetAddress.slice(0, 20)}…
          </h2>
          <p className="text-[10px] text-gray-500 mt-0.5">
            Scanned {new Date(report.scannedAt).toLocaleString()} · Fee: {report.scanFeeSOL} SOL
          </p>
        </div>
        {/* Export */}
        <div className="flex gap-2">
          <button onClick={() => exportJson(report)}
            className="flex items-center gap-1.5 bg-[#0d1525] hover:bg-[#1a2540] border border-white/10 text-xs font-bold text-gray-300 hover:text-white px-3.5 py-2 rounded-lg transition-all">
            <Download className="w-3.5 h-3.5" /> JSON
          </button>
          <a href={report.explorerUrl} target="_blank" rel="noreferrer"
            className="flex items-center gap-1.5 bg-[#0d1525] hover:bg-[#1a2540] border border-white/10 text-xs font-bold text-gray-300 hover:text-white px-3.5 py-2 rounded-lg transition-all">
            <ExternalLink className="w-3.5 h-3.5" /> Explorer
          </a>
        </div>
      </div>

      {/* Score + Telemetry */}
      <div className="grid grid-cols-12 gap-5">
        {/* Risk Score Radial */}
        <div className="col-span-12 md:col-span-5 bg-[#0d1525] rounded-2xl border border-white/5 p-5 flex flex-col items-center justify-center text-center gap-3">
          <p className="text-[10px] uppercase tracking-widest text-gray-400 font-bold">AI Risk Score</p>
          <div className={`w-32 h-32 rounded-full border-8 flex flex-col items-center justify-center ${SCORE_COLOR(report.riskScore)}`}
            style={{ boxShadow: report.riskScore >= 70 ? "0 0 20px rgba(239,68,68,0.3)" : report.riskScore >= 35 ? "0 0 20px rgba(245,158,11,0.3)" : "0 0 20px rgba(16,185,129,0.3)" }}>
            <span className="text-4xl font-extrabold text-white">{report.riskScore}</span>
            <span className="text-[9px] text-gray-400 font-bold tracking-wider">/ 100</span>
          </div>
          <div className="grid grid-cols-3 gap-2 w-full mt-1 text-center">
            {(["SAFE", "WARNING", "CRITICAL"] as const).map(k => (
              <div key={k} className="bg-[#090d16] rounded-lg p-2 border border-white/5">
                <p className="text-[8px] text-gray-500 uppercase tracking-wider">{k}</p>
                <p className="text-sm font-bold text-white">{Math.round(report.mlProbabilities[k] * 100)}%</p>
              </div>
            ))}
          </div>
        </div>

        {/* Telemetry */}
        <div className="col-span-12 md:col-span-7 bg-[#0d1525] rounded-2xl border border-white/5 p-5 flex flex-col gap-4">
          <p className="text-[10px] uppercase tracking-widest text-gray-400 font-bold border-b border-white/5 pb-1">
            <BarChart2 className="inline w-3.5 h-3.5 mr-1 text-blue-400" /> Account Telemetry
          </p>
          <div className="grid grid-cols-2 gap-3 text-xs font-mono">
            {[
              ["Bytecode", `${report.telemetry.bytecodeSizeKb.toFixed(1)} KB`],
              ["Tx Count", `${report.telemetry.txCount}`],
              ["Balance", `${report.telemetry.solBalance.toFixed(4)} SOL`],
              ["Executable", report.telemetry.executable ? "Yes" : "No"],
              ["Owner", report.telemetry.owner.slice(0, 14) + "…"],
              ["Confidence", `${report.confidence}%`],
            ].map(([k, v]) => (
              <div key={k}>
                <p className="text-[9px] text-gray-500 uppercase tracking-wider">{k}</p>
                <p className="text-gray-200 font-semibold mt-0.5">{v}</p>
              </div>
            ))}
          </div>
          {/* On-chain receipt */}
          <div className="mt-auto pt-2 border-t border-white/5 flex items-center justify-between text-[10px] font-mono">
            <span className="text-gray-500">Payment status:</span>
            {report.signature && report.signature !== "none" && !report.signature.includes("free") ? (
              <a href={`https://explorer.solana.com/tx/${report.signature}?cluster=devnet`}
                target="_blank" rel="noreferrer"
                className="text-blue-400 hover:text-blue-300 flex items-center gap-1">
                {report.signature.slice(0, 10)}… <ExternalLink className="w-3 h-3" />
              </a>
            ) : (
              <span className="text-emerald-400 font-bold uppercase tracking-wider text-[8px] bg-emerald-950/20 px-2 py-0.5 rounded border border-emerald-900/30">
                Free Program Scan
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Forensics (tx hash mode) */}
      {report.forensics && (
        <div className="bg-[#0d1525] rounded-2xl border border-blue-900/30 p-5 flex flex-col gap-3">
          <p className="text-[10px] uppercase tracking-widest text-blue-400 font-bold flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5" /> Forensic Transaction Analysis
          </p>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs font-mono">
            {[
              ["Slot", report.forensics.slot.toString()],
              ["Block Time", report.forensics.blockTime ? new Date(report.forensics.blockTime * 1000).toLocaleTimeString() : "N/A"],
              ["Signers", report.forensics.signerCount.toString()],
              ["Instructions", report.forensics.instructionCount.toString()],
              ["Inner Calls", report.forensics.innerCallCount.toString()],
              ["Fee (lamports)", report.forensics.fee.toLocaleString()],
            ].map(([k, v]) => (
              <div key={k} className="bg-[#090d16] p-2.5 rounded-lg border border-white/5">
                <p className="text-[9px] text-gray-500 uppercase">{k}</p>
                <p className="text-blue-300 font-semibold mt-0.5">{v}</p>
              </div>
            ))}
          </div>
          {report.forensics.programsInvoked.length > 0 && (
            <div className="text-[10px] text-gray-400 mt-1">
              <span className="font-semibold text-gray-300">Programs invoked: </span>
              {report.forensics.programsInvoked.join(", ")}
            </div>
          )}
        </div>
      )}

      {/* Vulnerability Findings */}
      <div className="flex flex-col gap-3">
        <h3 className="text-sm font-bold text-white border-b border-white/5 pb-1.5 flex items-center gap-1.5">
          <Shield className="w-4 h-4 text-purple-400" />
          Detected Threats ({report.threats.length})
        </h3>
        {report.threats.length === 0 ? (
          <div className="bg-emerald-950/20 p-4 rounded-xl border border-emerald-900/30 flex items-center gap-2 text-xs text-emerald-400">
            <CheckCircle className="w-4 h-4 flex-shrink-0" />
            No vulnerabilities detected. Contract compiled with all security validations.
          </div>
        ) : (
          report.threats.map((t, i) => {
            const cfg = SEV_CONFIG[t.severity] ?? SEV_CONFIG.INFO;
            return (
              <div key={i} className={`p-4 rounded-xl border ${cfg.bg} ${cfg.border} flex flex-col gap-2`}>
                <div className="flex justify-between items-center flex-wrap gap-2">
                  <span className="font-mono text-xs font-bold text-white">{t.type}</span>
                  <span className={`text-[9px] font-extrabold px-2 py-0.5 rounded border uppercase flex items-center gap-1 ${cfg.bg} ${cfg.text} ${cfg.border}`}>
                    {cfg.icon} {t.severity}
                  </span>
                </div>
                <p className="text-xs text-gray-300 leading-relaxed">{t.description}</p>
                {t.location && (
                  <p className="text-[10px] text-gray-500 font-mono">📍 {t.location}</p>
                )}
                <div className="bg-[#090d16] p-3 rounded-lg border border-white/5 font-mono text-[10px] text-emerald-400 select-all">
                  <span className="text-gray-500">// Remediation: </span>{t.remediation}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
