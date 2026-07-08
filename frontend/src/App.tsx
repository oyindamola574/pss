// pss/frontend/src/App.tsx
import { useState, useEffect, useRef } from "react";
import { Shield, Wallet, UserCheck, Terminal, Cpu } from "lucide-react";
import { Connection, PublicKey, Transaction, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";

// Components & Types
import type { SecurityTask, ScanReport, ThreatOption, BenchmarkMetrics } from "./types";
import ScanForm from "./components/ScanForm";
import ReportView from "./components/ReportView";
import TaskBoard from "./components/TaskBoard";
import ThreatFeed from "./components/ThreatFeed";

type SolanaWalletProvider = {
  name: "Phantom" | "Solflare" | "MetaMask";
  provider: {
    isPhantom?: boolean;
    isSolflare?: boolean;
    isMetaMask?: boolean;
    publicKey?: PublicKey;
    connect: () => Promise<{ publicKey: PublicKey } | void>;
    disconnect?: () => Promise<void>;
    signTransaction: (tx: Transaction) => Promise<Transaction>;
  };
};

function getSolanaWalletProviders(): SolanaWalletProvider[] {
  const win = window as any;
  const candidates = [
    win.solana,
    ...(Array.isArray(win.solana?.providers) ? win.solana.providers : []),
    win.phantom?.solana,
    win.solflare,
    win.metamask?.solana,
  ].filter(Boolean);

  const providers = new Map<string, SolanaWalletProvider>();
  for (const provider of candidates) {
    if (typeof provider.connect !== "function" || typeof provider.signTransaction !== "function") {
      continue;
    }

    if (provider.isPhantom) providers.set("Phantom", { name: "Phantom", provider });
    if (provider.isSolflare) providers.set("Solflare", { name: "Solflare", provider });
    if (provider.isMetaMask) providers.set("MetaMask", { name: "MetaMask", provider });
  }

  return ["Phantom", "Solflare", "MetaMask"]
    .map(name => providers.get(name))
    .filter(Boolean) as SolanaWalletProvider[];
}

export default function App() {
  // Roles
  const [userRole, setUserRole] = useState<"Project Manager" | "Developer">("Project Manager");
  const [userName, setUserName] = useState<string>("Jane Lead");

  // Wallet
  const [walletAddress, setWalletAddress] = useState<string>("");
  const [walletBalance, setWalletBalance] = useState<number | null>(null);
  const [walletName, setWalletName] = useState<SolanaWalletProvider["name"] | "">("");

  // Config loaded from backend
  const [vaultAddress, setVaultAddress] = useState<string>("HUXqL7fN3eR2MvL1U8K9vGj98bX9N18L2X3y4z5w6a7");
  const [threatOptions, setThreatOptions] = useState<ThreatOption[]>([]);
  const [fees, setFees] = useState({ general: 0.02, customBase: 0.01, perThreat: 0.005 });

  // Scan selections
  const [targetAddress, setTargetAddress] = useState<string>("");
  const [scanType, setScanType] = useState<"general" | "custom">("general");
  const [selectedThreats, setSelectedThreats] = useState<string[]>(["PDA_STATE_MUTATION", "CPI_REENTRANCY", "OWNER_VERIFICATION"]);
  const [customPattern, setCustomPattern] = useState<string>("");

  // Target Account Type Detection (Phase 1)
  const [isProgramTarget, setIsProgramTarget] = useState<boolean>(false);
  const [isCheckingType, setIsCheckingType] = useState<boolean>(false);

  // Scan state
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [scanProgressMsg, setScanProgressMsg] = useState<string>("");

  // Loaded data
  const [tasks, setTasks] = useState<SecurityTask[]>([]);
  const [selectedTask, setSelectedTask] = useState<SecurityTask | null>(null);
  const [activeReport, setActiveReport] = useState<ScanReport | null>(null);
  const [articles, setArticles] = useState<any[]>([]);
  const [wsLogs, setWsLogs] = useState<string[]>([]);
  const [benchmark, setBenchmark] = useState<BenchmarkMetrics | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const walletProviderRef = useRef<SolanaWalletProvider["provider"] | null>(null);

  // Dynamic fee calculation (General is 0.02 SOL, Custom is base + per selected threat)
  const currentScanFee = scanType === "general"
    ? fees.general
    : Math.round((fees.customBase + fees.perThreat * selectedThreats.length) * 1000) / 1000;

  useEffect(() => {
    setUserName(userRole === "Project Manager" ? "Jane PM" : "Dev Dan");
  }, [userRole]);

  // Check target address type on-chain (Devnet)
  useEffect(() => {
    let timer: any;
    if (targetAddress && targetAddress.length >= 32 && targetAddress.length <= 44) {
      const checkType = async () => {
        setIsCheckingType(true);
        try {
          const connection = new Connection("https://api.devnet.solana.com", "confirmed");
          const pubkey = new PublicKey(targetAddress);
          const info = await connection.getAccountInfo(pubkey);
          setIsProgramTarget(info ? info.executable : false);
        } catch {
          setIsProgramTarget(false);
        } finally {
          setIsCheckingType(false);
        }
      };
      timer = setTimeout(checkType, 500);
    } else {
      setIsProgramTarget(false);
    }
    return () => {
      if (timer) clearTimeout(timer);
    };
  }, [targetAddress]);

  // Load config, tasks, threat articles, benchmark metrics, and connect websocket
  useEffect(() => {
    fetchConfig();
    fetchTasks();
    fetchArticles();
    fetchBenchmark();

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsHost = window.location.hostname === "localhost" ? "localhost:5000" : window.location.host;
    const ws = new WebSocket(`${protocol}//${wsHost}`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "WELCOME") {
        logEvent(`[System]: Connected to Security Socket Event Bus.`);
      } else if (data.type === "SCAN_PROGRESS") {
        setScanProgress(data.progress || 0);
        setScanProgressMsg(data.msg || "");
        logEvent(`[Scan Engine]: ${data.msg}`);
      } else if (data.type === "SCAN_COMPLETED") {
        setIsScanning(false);
        setScanProgress(100);
        setScanProgressMsg("Scan complete!");
        fetchTasks();
        fetchBenchmark();
        if (data.report) {
          setActiveReport(data.report);
        }
        logEvent(`[Audit Log]: Assessment report generated for ${data.task?.targetAddress.slice(0, 10)}...`);
      } else if (data.type === "ACTIVITY_UPDATE") {
        fetchTasks();
        fetchBenchmark();
        logEvent(`[TMS Activity]: ${data.message}`);
      }
    };

    ws.onclose = () => {
      logEvent("[System]: WebSocket disconnected.");
    };

    return () => ws.close();
  }, []);

  const logEvent = (msg: string) => {
    setWsLogs(prev => [msg, ...prev.slice(0, 49)]);
  };

  const fetchConfig = async () => {
    try {
      const res = await fetch("/api/config");
      if (res.ok) {
        const data = await res.json();
        setVaultAddress(data.vaultAddress);
        if (data.pricing) setFees(data.pricing);
        if (data.threats) setThreatOptions(data.threats);
      }
    } catch (e) {
      console.warn("Failed to load backend config", e);
    }
  };

  const fetchTasks = async () => {
    try {
      const res = await fetch("/api/tasks");
      if (res.ok) {
        const data = await res.json();
        setTasks(data);
      }
    } catch (e) {
      console.error("Failed to fetch tasks", e);
    }
  };

  const fetchArticles = async () => {
    try {
      const res = await fetch("/api/context/articles");
      if (res.ok) {
        const data = await res.json();
        setArticles(data);
      }
    } catch (e) {
      console.error("Failed to fetch articles", e);
    }
  };

  const fetchBenchmark = async () => {
    try {
      const res = await fetch("/api/benchmark");
      if (res.ok) {
        const data = await res.json();
        setBenchmark(data);
      }
    } catch (e) {
      console.warn("Failed to fetch benchmark metrics", e);
    }
  };

  // Wallet Connection (Solana Devnet only)
  const connectWallet = async () => {
    const wallet = getSolanaWalletProviders()[0];
    if (!wallet) {
      alert("No supported Solana wallet found. Please install Phantom, Solflare, or a MetaMask Solana wallet provider to scan addresses requiring a fee.");
      return;
    }

    try {
      const resp = await wallet.provider.connect();
      const publicKey = resp?.publicKey ?? wallet.provider.publicKey;
      if (!publicKey) {
        throw new Error(`${wallet.name} did not return a Solana public key.`);
      }

      const address = publicKey.toString();
      walletProviderRef.current = wallet.provider;
      setWalletAddress(address);
      setWalletName(wallet.name);
      logEvent(`[Wallet]: Connected ${wallet.name} Devnet: ${address.slice(0, 8)}...`);

      const connection = new Connection("https://api.devnet.solana.com", "confirmed");
      const bal = await connection.getBalance(publicKey);
      setWalletBalance(bal / LAMPORTS_PER_SOL);
    } catch (err) {
      console.error("Rejected connection", err);
    }
  };

  const disconnectWallet = () => {
    walletProviderRef.current?.disconnect?.().catch(() => undefined);
    walletProviderRef.current = null;
    setWalletAddress("");
    setWalletBalance(null);
    setWalletName("");
    logEvent("[Wallet]: Disconnected.");
  };

  // Submit scan with payment signature if fee applies
  const handleRunScan = async () => {
    if (!targetAddress.trim()) return;

    setIsScanning(true);
    setScanProgress(5);
    setScanProgressMsg("Initiating scan...");

    let signature = "";
    try {
      // Wallet payment only required if target is not a program executable
      if (!isProgramTarget) {
        if (!walletAddress) {
          throw new Error("Wallet connection is required for scanning non-program addresses (scan fee applies).");
        }
        const provider = walletProviderRef.current;
        if (!provider?.signTransaction) {
          throw new Error("Connected wallet is unavailable. Please reconnect Phantom, Solflare, or MetaMask.");
        }
        const connection = new Connection("https://api.devnet.solana.com", "confirmed");
        const from = new PublicKey(walletAddress);
        const to = new PublicKey(vaultAddress);

        const tx = new Transaction().add(
          SystemProgram.transfer({
            fromPubkey: from,
            toPubkey: to,
            lamports: Math.round(currentScanFee * LAMPORTS_PER_SOL),
          })
        );
        const { blockhash } = await connection.getLatestBlockhash();
        tx.recentBlockhash = blockhash;
        tx.feePayer = from;

        logEvent(`[Wallet]: Prompting ${walletName || "wallet"} for transaction signature...`);
        const signed = await provider.signTransaction(tx);
        signature = await connection.sendRawTransaction(signed.serialize());
        logEvent(`[Solana]: Fee payment tx dispatched. Sig: ${signature.slice(0, 10)}...`);
      }

      // Submit to backend
      const res = await fetch("/api/scan/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          signature: signature || undefined,
          targetAddress,
          selectedThreats: scanType === "custom" ? selectedThreats : [],
          customPattern: scanType === "custom" ? customPattern : undefined,
          userRole,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || "Failed to start security scan");
      }
    } catch (e: any) {
      console.error(e);
      setIsScanning(false);
      setScanProgress(0);
      alert(`Scan failed: ${e.message}`);
    }
  };

  const handleUpdateStatus = async (id: string, status: SecurityTask["status"]) => {
    try {
      const res = await fetch(`/api/tasks/${id}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      if (res.ok) fetchTasks();
    } catch (e) {
      console.error(e);
    }
  };

  const handleAddComment = async (id: string, user: string, text: string) => {
    try {
      const res = await fetch(`/api/tasks/${id}/comment`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user, text }),
      });
      if (res.ok) {
        fetchTasks();
        const updated = await res.json();
        setSelectedTask(updated);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleReviewModel = async (id: string, label: "SAFE" | "WARNING" | "CRITICAL") => {
    try {
      const res = await fetch(`/api/tasks/${id}/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label }),
      });
      if (res.ok) {
        fetchTasks();
        fetchBenchmark();
        const updated = await res.json();
        setSelectedTask(updated);
        logEvent(`[Model Review]: Submitted updated label: ${label}. Model retrained.`);
      } else {
        const err = await res.json();
        alert(`Failed to submit model review: ${err.error}`);
      }
    } catch (e: any) {
      console.error(e);
    }
  };

  const toggleThreat = (key: string) => {
    setSelectedThreats(prev =>
      prev.includes(key) ? prev.filter(t => t !== key) : [...prev, key]
    );
  };

  return (
    <div className="min-h-screen bg-background text-gray-200 flex flex-col relative overflow-hidden">
      {/* Glow overlays */}
      <div className="absolute top-0 left-1/4 w-[500px] h-[500px] bg-purple-900/10 rounded-full blur-3xl pointer-events-none"></div>
      <div className="absolute bottom-0 right-1/4 w-[500px] h-[500px] bg-blue-900/10 rounded-full blur-3xl pointer-events-none"></div>

      {/* Header */}
      <header className="glass sticky top-0 z-40 px-6 py-4 flex items-center justify-between shadow-xl border-b border-white/5">
        <div className="flex items-center gap-3">
          <div className="bg-gradient-to-tr from-purple-600 to-blue-500 p-2.5 rounded-xl shadow-md">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-blue-400">
              Protocol Security Scout
            </h1>
            <p className="text-[10px] text-gray-400">Autonomous Solana Security Auditing & Model Verification Platform</p>
          </div>
        </div>

        {/* Identity & Wallet Controls */}
        <div className="flex items-center gap-3.5">
          <div className="flex items-center gap-2 bg-panel px-3 py-1.5 rounded-lg border border-white/5">
            <UserCheck className="w-3.5 h-3.5 text-purple-400" />
            <select
              value={userRole}
              onChange={(e) => setUserRole(e.target.value as any)}
              className="bg-transparent text-xs text-gray-200 outline-none cursor-pointer font-medium"
            >
              <option value="Project Manager" className="bg-panel">Manager (Jane PM)</option>
              <option value="Developer" className="bg-panel">Developer (Dev Dan)</option>
            </select>
          </div>

          {walletAddress ? (
            <div className="flex items-center gap-2.5 bg-panel pl-3.5 pr-2 py-1 rounded-lg border border-white/10">
              <Wallet className="w-3.5 h-3.5 text-blue-400" />
              <div className="text-left font-mono">
                <p className="text-[8px] text-gray-500 uppercase tracking-wider">
                  {walletName ? `${walletName} Devnet` : "Solana Devnet"}
                </p>
                <p className="text-xs font-semibold text-gray-200">
                  {walletAddress.slice(0, 6)}...{walletAddress.slice(-4)}
                </p>
              </div>
              {walletBalance !== null && (
                <span className="bg-blue-900/30 text-blue-300 text-[10px] font-bold px-2 py-0.5 rounded border border-blue-800/40">
                  {walletBalance.toFixed(2)} SOL
                </span>
              )}
              <button
                onClick={disconnectWallet}
                className="text-[10px] text-red-400 hover:text-red-300 px-2 py-1 ml-1"
              >
                Disconnect
              </button>
            </div>
          ) : (
            <button
              onClick={connectWallet}
              className="flex items-center gap-2 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-xs font-bold text-white px-4 py-2 rounded-xl transition-all shadow-md active:scale-95"
            >
              <Wallet className="w-4 h-4" />
              Connect Wallet
            </button>
          )}
        </div>
      </header>

      {/* Main Grid */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-5 grid grid-cols-1 lg:grid-cols-12 gap-5 z-10">
        {/* Left Section: Audit submissions & database presets */}
        <section className="lg:col-span-4 flex flex-col gap-5">
          <ScanForm
            threats={threatOptions}
            targetAddress={targetAddress}
            setTargetAddress={setTargetAddress}
            scanType={scanType}
            setScanType={setScanType}
            selectedThreats={selectedThreats}
            toggleThreat={toggleThreat}
            customPattern={customPattern}
            setCustomPattern={setCustomPattern}
            scanFee={currentScanFee}
            isScanning={isScanning}
            walletConnected={!!walletAddress}
            onSubmit={handleRunScan}
            progress={scanProgress}
            progressMsg={scanProgressMsg}
            isProgramTarget={isProgramTarget}
            isCheckingType={isCheckingType}
          />
          <ThreatFeed articles={articles} onArticleAdded={fetchArticles} />
        </section>

        {/* Right Section: Model verification desk & Report findings */}
        <section className="lg:col-span-8 flex flex-col gap-5">
          {/* Benchmark Metrics Dashboard (Phase 1 addition) */}
          {benchmark && (
            <div className="glass rounded-2xl p-5 border border-purple-500/10 shadow-xl bg-[#0b0f19]/80">
              <div className="flex justify-between items-center border-b border-white/5 pb-2.5 mb-4">
                <h2 className="text-sm font-bold text-white flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-purple-400" />
                  Model Accuracy & Verification Desk
                </h2>
                <span className="text-[8px] font-extrabold bg-purple-900/30 text-purple-300 border border-purple-800/40 px-2 py-0.5 rounded uppercase tracking-wider">
                  KNN Engine Status: ONLINE
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-12 gap-5 items-center">
                {/* Accuracy Radial Gauge */}
                <div className="col-span-12 md:col-span-3 flex flex-col items-center justify-center text-center p-3 bg-[#0d1424] rounded-xl border border-white/5">
                  <span className="text-[8px] text-gray-500 font-extrabold uppercase tracking-wider">MODEL ACCURACY</span>
                  <div className="relative flex items-center justify-center mt-2">
                    <div className="w-20 h-20 rounded-full border-4 border-purple-600/30 flex flex-col items-center justify-center shadow-lg shadow-purple-500/5">
                      <span className="text-xl font-extrabold text-white">{(benchmark.accuracy * 100).toFixed(1)}%</span>
                      <span className="text-[7px] text-gray-400 font-bold uppercase mt-0.5">score</span>
                    </div>
                  </div>
                </div>

                {/* Performance Stats */}
                <div className="col-span-12 md:col-span-4 grid grid-cols-2 gap-3">
                  <div className="bg-[#0d1424] p-2.5 rounded-xl border border-white/5 text-center">
                    <p className="text-[8px] text-gray-500 font-bold uppercase">FALSE POSITIVES</p>
                    <p className="text-base font-extrabold text-red-400 mt-0.5">{(benchmark.falsePositiveRate * 100).toFixed(1)}%</p>
                  </div>
                  <div className="bg-[#0d1424] p-2.5 rounded-xl border border-white/5 text-center">
                    <p className="text-[8px] text-gray-500 font-bold uppercase">AVG INFERENCE</p>
                    <p className="text-base font-extrabold text-emerald-400 mt-0.5">{benchmark.avgLatencyMs.toFixed(3)} ms</p>
                  </div>
                  <div className="bg-[#0d1424] p-2.5 rounded-xl border border-white/5 text-center">
                    <p className="text-[8px] text-gray-500 font-bold uppercase">DATASET SIZE</p>
                    <p className="text-base font-extrabold text-purple-300 mt-0.5">{benchmark.total}</p>
                  </div>
                  <div className="bg-[#0d1424] p-2.5 rounded-xl border border-white/5 text-center">
                    <p className="text-[8px] text-gray-500 font-bold uppercase">BASELINE RULE</p>
                    <p className="text-base font-extrabold text-gray-400 mt-0.5">{(benchmark.baselineAccuracy * 100).toFixed(1)}%</p>
                  </div>
                </div>

                {/* Precision & Recall Detail */}
                <div className="col-span-12 md:col-span-5 bg-[#0d1424] p-3 rounded-xl border border-white/5 flex flex-col gap-2">
                  <span className="text-[8px] text-gray-500 font-extrabold uppercase tracking-wider">CLASS PERFORMANCE</span>
                  <table className="w-full text-[9px] text-left border-collapse">
                    <thead>
                      <tr className="border-b border-white/5 text-gray-500 font-bold uppercase">
                        <th className="pb-1 font-medium">CLASS</th>
                        <th className="pb-1 font-medium text-right">PRECISION</th>
                        <th className="pb-1 font-medium text-right">RECALL</th>
                      </tr>
                    </thead>
                    <tbody className="font-mono text-gray-300">
                      {(["SAFE", "WARNING", "CRITICAL"] as const).map(c => (
                        <tr key={c} className="border-b border-white/5 last:border-0">
                          <td className="py-1 font-sans font-bold flex items-center gap-1">
                            <span className={`w-1.5 h-1.5 rounded-full ${
                              c === "SAFE" ? "bg-emerald-500" : c === "WARNING" ? "bg-amber-500" : "bg-red-500"
                            }`} />
                            {c}
                          </td>
                          <td className="py-1 text-right font-bold text-white">{(benchmark.precision[c] * 100).toFixed(1)}%</td>
                          <td className="py-1 text-right font-bold text-white">{(benchmark.recall[c] * 100).toFixed(1)}%</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {activeReport ? (
            <ReportView report={activeReport} />
          ) : (
            <div className="glass p-12 rounded-2xl text-center flex flex-col items-center justify-center gap-3 border border-white/5 min-h-[300px]">
              <Shield className="w-12 h-12 text-gray-600 animate-pulse" />
              <div>
                <h3 className="text-sm font-bold text-white">No Target Inspected</h3>
                <p className="text-[11px] text-gray-500 mt-1 max-w-xs mx-auto">
                  Submit a target Solana address or executable program to run a live security scan, or view an existing report from the Kanban queue.
                </p>
              </div>
            </div>
          )}

          {/* Kanban sprint board & analyst queue */}
          <TaskBoard
            tasks={tasks}
            selectedTask={selectedTask}
            onSelectTask={(task) => setSelectedTask(task)}
            onUpdateStatus={handleUpdateStatus}
            onAddComment={handleAddComment}
            userName={userName}
            onViewReport={(report) => setActiveReport(report)}
            onReviewModel={handleReviewModel}
          />

          {/* Operations websocket logs feed */}
          <div className="glass p-4 rounded-2xl flex flex-col gap-2 border border-white/5">
            <h2 className="text-[10px] font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-emerald-400" /> Operations WebSocket Feed (CHRONOS Log)
            </h2>
            <div className="bg-[#090d16] p-3 rounded-xl border border-white/5 font-mono text-[9px] text-emerald-400 h-28 overflow-y-auto flex flex-col-reverse gap-1 select-all">
              {wsLogs.map((log, index) => (
                <div key={index} className="leading-relaxed border-b border-white/5 pb-0.5 last:border-0 truncate">
                  {log}
                </div>
              ))}
            </div>
          </div>
        </section>
      </main>

      <footer className="glass py-4 text-center border-t border-white/5 text-[10px] text-gray-500 mt-auto">
        &copy; 2026 Protocol Security Scout.
      </footer>
    </div>
  );
}
