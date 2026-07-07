// pss/frontend/src/App.tsx
import { useState, useEffect, useRef } from "react";
import { Shield, Wallet, UserCheck, Terminal } from "lucide-react";
import { Connection, PublicKey, Transaction, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";

// Components & Types
import type { SecurityTask, ScanReport, ThreatOption } from "./types";
import ScanForm from "./components/ScanForm";
import ReportView from "./components/ReportView";
import TaskBoard from "./components/TaskBoard";
import ThreatFeed from "./components/ThreatFeed";

export default function App() {
  // Roles
  const [userRole, setUserRole] = useState<"Project Manager" | "Developer">("Project Manager");
  const [userName, setUserName] = useState<string>("Jane Lead");

  // Wallet
  const [walletAddress, setWalletAddress] = useState<string>("");
  const [walletBalance, setWalletBalance] = useState<number | null>(null);
  const [isSandboxWallet, setIsSandboxWallet] = useState<boolean>(false);

  // Config loaded from backend
  const [vaultAddress, setVaultAddress] = useState<string>("HUXqL7fN3eR2MvL1U8K9vGj98bX9N18L2X3y4z5w6a7");
  const [threatOptions, setThreatOptions] = useState<ThreatOption[]>([]);
  const [fees, setFees] = useState({ general: 0.02, customBase: 0.01, perThreat: 0.005 });

  // Scan selections
  const [targetAddress, setTargetAddress] = useState<string>("");
  const [scanType, setScanType] = useState<"general" | "custom">("general");
  const [selectedThreats, setSelectedThreats] = useState<string[]>(["PDA_STATE_MUTATION", "CPI_REENTRANCY", "OWNER_VERIFICATION"]);
  const [customPattern, setCustomPattern] = useState<string>("");

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

  const wsRef = useRef<WebSocket | null>(null);

  // Dynamic fee formula matching build_plan
  const currentScanFee = scanType === "general"
    ? fees.general
    : Math.round((fees.customBase + fees.perThreat * selectedThreats.length) * 1000) / 1000;

  useEffect(() => {
    setUserName(userRole === "Project Manager" ? "Jane PM" : "Dev Dan");
  }, [userRole]);

  // Load config, tasks, threat articles, and connect websocket
  useEffect(() => {
    fetchConfig();
    fetchTasks();
    fetchArticles();

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
        if (data.report) {
          setActiveReport(data.report);
        }
        logEvent(`[Audit Log]: Report generated for ${data.task?.targetAddress.slice(0, 10)}...`);
      } else if (data.type === "ACTIVITY_UPDATE") {
        fetchTasks();
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

  // Step 1: Wallet Connection (with Sandbox fallback)
  const connectWallet = async () => {
    const solanaProvider = (window as any).solana;
    if (solanaProvider?.isPhantom) {
      try {
        const resp = await solanaProvider.connect();
        const address = resp.publicKey.toString();
        setWalletAddress(address);
        setIsSandboxWallet(false);
        logEvent(`[Wallet]: Connected Phantom: ${address.slice(0, 8)}...`);

        const connection = new Connection("https://api.devnet.solana.com", "confirmed");
        const bal = await connection.getBalance(resp.publicKey);
        setWalletBalance(bal / LAMPORTS_PER_SOL);
      } catch (err) {
        console.error("Rejected connection", err);
      }
    } else {
      // Connect to Sandbox mode
      setWalletAddress("dev-wallet-HUXqL7fN3eR2MvL1U8K9vGj98b");
      setWalletBalance(12.45);
      setIsSandboxWallet(true);
      logEvent(`[Sandbox]: Connected sandbox developer wallet.`);
    }
  };

  const disconnectWallet = () => {
    setWalletAddress("");
    setWalletBalance(null);
    setIsSandboxWallet(false);
    logEvent("[Wallet]: Disconnected.");
  };

  // Submit scan with payment
  const handleRunScan = async () => {
    if (!walletAddress || !targetAddress.trim()) return;

    setIsScanning(true);
    setScanProgress(5);
    setScanProgressMsg("Initiating scan payment...");

    let signature = "";
    try {
      if (isSandboxWallet) {
        signature = `sim-sig-${Math.random().toString(36).substring(2, 15)}`;
        await new Promise(r => setTimeout(r, 1200));
        logEvent(`[Sandbox]: Payment signature: ${signature}`);
      } else {
        const provider = (window as any).solana;
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

        logEvent(`[Wallet]: Prompting Phantom for transaction signature...`);
        const signed = await provider.signTransaction(tx);
        signature = await connection.sendRawTransaction(signed.serialize());
        logEvent(`[Solana]: Tx sent. Sig: ${signature.slice(0, 10)}...`);
      }

      // Submit to backend
      const res = await fetch("/api/scan/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          signature,
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
            <p className="text-[10px] text-gray-400">Autonomous Solana Security Auditing & TMS Platform</p>
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
                  {isSandboxWallet ? "Sandbox Wallet" : "Devnet"}
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
                Exit
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
        {/* Left Section: Step 2-5 Form & News Feed */}
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
          />
          <ThreatFeed articles={articles} onArticleAdded={fetchArticles} />
        </section>

        {/* Right Section: Active Report view or placeholder */}
        <section className="lg:col-span-8 flex flex-col gap-5">
          {activeReport ? (
            <ReportView report={activeReport} />
          ) : (
            <div className="glass p-12 rounded-2xl text-center flex flex-col items-center justify-center gap-3 border border-white/5 min-h-[300px]">
              <Shield className="w-12 h-12 text-gray-600 animate-pulse" />
              <div>
                <h3 className="text-sm font-bold text-white">No Target Inspected</h3>
                <p className="text-[11px] text-gray-500 mt-1 max-w-xs mx-auto">
                  Submit a target Solana address to run a security scan, or view an existing report from the Kanban task board.
                </p>
              </div>
            </div>
          )}

          {/* Kanban board */}
          <TaskBoard
            tasks={tasks}
            selectedTask={selectedTask}
            onSelectTask={(task) => {
              setSelectedTask(task);
            }}
            onUpdateStatus={handleUpdateStatus}
            onAddComment={handleAddComment}
            userName={userName}
            onViewReport={(report) => {
              setActiveReport(report);
            }}
          />

          {/* Live events console */}
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
