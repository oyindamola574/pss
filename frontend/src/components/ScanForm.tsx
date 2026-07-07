// pss/frontend/src/components/ScanForm.tsx
import { Shield, RefreshCw, ChevronRight, Crosshair } from "lucide-react";
import type { ThreatOption } from "../types";

interface Props {
  threats: ThreatOption[];
  targetAddress: string;
  setTargetAddress: (v: string) => void;
  scanType: "general" | "custom";
  setScanType: (v: "general" | "custom") => void;
  selectedThreats: string[];
  toggleThreat: (key: string) => void;
  customPattern: string;
  setCustomPattern: (v: string) => void;
  scanFee: number;
  isScanning: boolean;
  walletConnected: boolean;
  onSubmit: () => void;
  progress: number;
  progressMsg: string;
}

// Address type detector badge
function detectType(addr: string): string {
  if (!addr) return "";
  if (addr.length >= 80) return "TX HASH";
  if (addr.length >= 32 && addr.length <= 44) {
    if (addr === "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA") return "PROGRAM ✓";
    if (addr === "11111111111111111111111111111111") return "SYSTEM PROGRAM ✓";
    return "ADDRESS";
  }
  return "UNKNOWN";
}

export default function ScanForm({
  threats, targetAddress, setTargetAddress, scanType, setScanType,
  selectedThreats, toggleThreat, customPattern, setCustomPattern,
  scanFee, isScanning, walletConnected, onSubmit, progress, progressMsg,
}: Props) {
  const addrType = detectType(targetAddress);

  return (
    <div className="glass rounded-2xl p-5 flex flex-col gap-5 shadow-xl">
      {/* Step 3: Target */}
      <div>
        <label className="block text-[10px] uppercase tracking-widest text-gray-400 font-bold mb-1.5">
          Step 3 — Target Address
        </label>
        <div className="relative">
          <input
            type="text"
            value={targetAddress}
            onChange={e => setTargetAddress(e.target.value)}
            placeholder="Program ID / Wallet / PDA / Tx Hash"
            disabled={isScanning}
            className="w-full bg-[#0d1525] border border-white/10 rounded-xl px-4 py-3 text-sm font-mono text-white placeholder-gray-600 focus:outline-none focus:border-purple-500 transition-colors pr-28"
          />
          {addrType && (
            <span className={`absolute right-3 top-1/2 -translate-y-1/2 text-[9px] font-bold px-2 py-0.5 rounded border ${
              addrType.includes("✓") ? "bg-emerald-950/30 text-emerald-400 border-emerald-900/30"
              : addrType === "TX HASH" ? "bg-blue-950/30 text-blue-400 border-blue-900/30"
              : "bg-purple-950/30 text-purple-400 border-purple-900/30"
            }`}>{addrType}</span>
          )}
        </div>
        {/* Presets */}
        <div className="flex gap-2 mt-2 flex-wrap">
          {[
            { label: "SPL Token (Safe)", addr: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", type: "general" },
            { label: "PDA Exploit Demo", addr: "PDAvulnerableExampleAddress1111111111111", type: "custom" },
            { label: "Tx Hash Demo", addr: "4hXTCkRzt9WyecNzV1XPgCDfGAZzQKNxLXgynz5QDuWJ8owkMLTn9hPWK8FWP9iHjAVEWFZkFkqjDzPSmkV7bqC", type: "general" },
          ].map(p => (
            <button key={p.label}
              onClick={() => { setTargetAddress(p.addr); setScanType(p.type as any); }}
              className="text-[10px] bg-[#0d1525] hover:bg-[#1a2540] border border-white/5 px-2.5 py-1 rounded text-gray-400 hover:text-white transition-all"
            >{p.label}</button>
          ))}
        </div>
      </div>

      {/* Step 2: Scan Type */}
      <div>
        <label className="block text-[10px] uppercase tracking-widest text-gray-400 font-bold mb-1.5">
          Step 2 — Scan Type
        </label>
        <div className="grid grid-cols-2 gap-2 bg-[#0d1525] p-1 rounded-xl border border-white/5">
          <button onClick={() => setScanType("general")}
            className={`py-2.5 text-xs font-bold rounded-lg transition-all flex items-center justify-center gap-1.5 ${
              scanType === "general" ? "bg-gradient-to-r from-blue-600 to-purple-600 text-white" : "text-gray-500 hover:text-white"
            }`}>
            <Shield className="w-3.5 h-3.5" /> General Audit
          </button>
          <button onClick={() => setScanType("custom")}
            className={`py-2.5 text-xs font-bold rounded-lg transition-all flex items-center justify-center gap-1.5 ${
              scanType === "custom" ? "bg-gradient-to-r from-purple-600 to-pink-600 text-white" : "text-gray-500 hover:text-white"
            }`}>
            <Crosshair className="w-3.5 h-3.5" /> Custom Agent
          </button>
        </div>
      </div>

      {/* Step 2B: All 8 threats (custom mode) */}
      {scanType === "custom" && (
        <div className="bg-[#0d1525] p-4 rounded-xl border border-white/5 flex flex-col gap-2">
          <p className="text-[10px] uppercase tracking-widest text-gray-400 font-bold mb-1">
            Select Threat Agents ({selectedThreats.length} selected)
          </p>
          {threats.map(t => (
            <label key={t.key} className="flex items-center gap-3 text-xs text-gray-300 cursor-pointer hover:text-white transition-colors group">
              <span className={`w-4 h-4 rounded border flex items-center justify-center transition-all flex-shrink-0 ${
                selectedThreats.includes(t.key)
                  ? "bg-purple-600 border-purple-500"
                  : "border-white/20 group-hover:border-purple-500"
              }`} onClick={() => toggleThreat(t.key)}>
                {selectedThreats.includes(t.key) && <span className="text-white text-[10px]">✓</span>}
              </span>
              <span className="flex-1">{t.label}</span>
              <span className={`text-[8px] font-bold px-1.5 py-0.5 rounded ${
                t.baseSeverity === "CRITICAL" ? "bg-red-950/30 text-red-400"
                : t.baseSeverity === "HIGH" ? "bg-orange-950/30 text-orange-400"
                : "bg-amber-950/30 text-amber-400"
              }`}>{t.baseSeverity}</span>
            </label>
          ))}
          {/* Custom Pattern input */}
          <div className="mt-2 border-t border-white/5 pt-3">
            <label className="text-[10px] text-gray-400 font-semibold block mb-1">
              Custom Pattern (optional regex or opcode signature)
            </label>
            <input type="text" value={customPattern}
              onChange={e => setCustomPattern(e.target.value)}
              placeholder="e.g. \x00\x00 or authority|admin"
              className="w-full bg-[#090d16] border border-white/10 rounded-lg px-3 py-1.5 text-xs font-mono text-purple-300 placeholder-gray-600 focus:outline-none focus:border-purple-500"
            />
          </div>
        </div>
      )}

      {/* Step 4: Fee + Submit */}
      <div className="flex items-center justify-between bg-[#0d1525] px-4 py-3 rounded-xl border border-white/5">
        <div>
          <p className="text-[10px] text-gray-400 uppercase tracking-wider font-semibold">Scan Fee</p>
          <p className="text-lg font-bold font-mono text-purple-300">{scanFee} <span className="text-sm text-gray-400">SOL</span></p>
        </div>
        <div className="text-[10px] text-gray-500 text-right">
          {scanType === "general" ? "General audit flat rate" : `0.01 + ${((scanFee - 0.01) / 0.005).toFixed(0)}×0.005 SOL`}
        </div>
      </div>

      <button onClick={onSubmit} disabled={isScanning || !walletConnected || !targetAddress.trim()}
        className={`w-full py-3.5 rounded-xl font-bold transition-all flex items-center justify-center gap-2 text-sm ${
          isScanning ? "bg-purple-900/40 text-purple-400 cursor-not-allowed border border-purple-800/20"
          : !walletConnected ? "bg-gray-800/60 text-gray-600 cursor-not-allowed"
          : !targetAddress.trim() ? "bg-gray-800/60 text-gray-600 cursor-not-allowed"
          : "bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-500 hover:to-blue-500 text-white shadow-lg active:scale-95"
        }`}>
        {isScanning
          ? <><RefreshCw className="w-4 h-4 animate-spin" /> Scanning…</>
          : <><Shield className="w-4 h-4" /> Run Security Scan <ChevronRight className="w-4 h-4" /></>}
      </button>

      {/* Step 5: Live Progress */}
      {isScanning && (
        <div className="bg-[#0d1525]/90 p-4 rounded-xl border border-purple-500/25">
          <div className="flex justify-between text-xs mb-2">
            <span className="text-purple-300 animate-pulse font-medium">{progressMsg}</span>
            <span className="text-purple-400 font-bold">{progress}%</span>
          </div>
          <div className="w-full h-2 bg-[#090d16] rounded-full overflow-hidden border border-white/5">
            <div className="h-full bg-gradient-to-r from-purple-500 to-blue-400 transition-all duration-500 ease-out"
              style={{ width: `${progress}%` }} />
          </div>
          <div className="grid grid-cols-4 mt-3 gap-1">
            {["Payment", "Resolve", "ML Score", "Report"].map((s, i) => (
              <div key={s} className={`text-center text-[9px] font-bold uppercase py-1 rounded transition-all ${
                progress > i * 25 ? "text-purple-300" : "text-gray-600"
              }`}>{s}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
