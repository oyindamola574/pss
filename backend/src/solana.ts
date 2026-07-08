// pss/backend/src/solana.ts
import { Connection, PublicKey, LAMPORTS_PER_SOL } from "@solana/web3.js";

export const VAULT_ADDRESS =
  process.env.VAULT_ADDRESS || "HUXqL7fN3eR2MvL1U8K9vGj98bX9N18L2X3y4z5w6a7";

const DEVNET_RPC = process.env.RPC_URL || "https://api.devnet.solana.com";
const connection = new Connection(DEVNET_RPC, "confirmed");

// ── Types ─────────────────────────────────────────────────────────────────────
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

export interface ScanTargetInfo {
  address: string;
  type: "PROGRAM" | "WALLET" | "PDA" | "TRANSACTION" | "UNKNOWN";
  bytecodeSizeKb: number;
  txCount: number;
  solBalance: number;
  owner: string;
  executable: boolean;
  failedChecks: number;
  vulnerabilities: ThreatFinding[];
  forensics?: ForensicData;
}

export interface ThreatSpec {
  key: string;
  label: string;
  baseSeverity: ThreatSeverity;
  description: string;
  remediation: string;
}

export const THREAT_REGISTRY: ThreatSpec[] = [
  {
    key: "PDA_STATE_MUTATION",
    label: "PDA State Mutation",
    baseSeverity: "CRITICAL",
    description: "Program derives a PDA and mutates its state without verifying the authority of the derived seeds. An attacker can craft colliding PDAs to overwrite protected account data.",
    remediation: "Verify find_program_address seeds match expected inputs before any write. Add an authority signer constraint on all state-mutating instructions.",
  },
  {
    key: "ACCOUNT_CLOSURE",
    label: "Account Closure Exploits",
    baseSeverity: "WARNING",
    description: "The program closes accounts without zeroing all state fields. A re-opened account retains stale discriminators, enabling re-initialization exploits.",
    remediation: "Zero all data fields and set a 'closed' sentinel discriminator before transferring lamports out.",
  },
  {
    key: "REINITIALIZATION_ATTACK",
    label: "Reinitialization Attacks",
    baseSeverity: "CRITICAL",
    description: "Program does not check whether an account has already been initialized. A second initialize call overwrites existing state, allowing an attacker to reset balances or authority.",
    remediation: "Add an is_initialized boolean guard or use Anchor's #[account(init)] which enforces single initialization.",
  },
  {
    key: "CPI_REENTRANCY",
    label: "CPI Reentrancy",
    baseSeverity: "HIGH",
    description: "Cross-program invocation target IDs are accepted dynamically from user account lists. A malicious program can intercept the CPI and re-enter with modified state.",
    remediation: "Hardcode expected program IDs. Assert eq!(cpi_program.key(), &expected_program_id) before every cross-program call.",
  },
  {
    key: "RENT_EXEMPTION_COLLAPSE",
    label: "Rent-Exemption Collapse",
    baseSeverity: "HIGH",
    description: "An instruction subtracts lamports from a data account without checking the post-transfer balance against the minimum rent-exempt threshold. Validators may garbage-collect the account.",
    remediation: "After any lamport deduction, verify account.lamports() >= Rent::get()?.minimum_balance(data_len). Use Anchor's rent_exempt = enforce constraint.",
  },
  {
    key: "LAMPORT_DRAINING",
    label: "Lamport-Draining",
    baseSeverity: "HIGH",
    description: "The program allows arbitrary transfer of lamports from a program-owned account without validating caller authority or enforcing an amount cap.",
    remediation: "Enforce a maximum transfer amount and require a signed authority instruction before debiting any program-owned account.",
  },
  {
    key: "OWNER_VERIFICATION",
    label: "Owner Verification Gaps",
    baseSeverity: "CRITICAL",
    description: "Account ownership is not verified against the expected program ID. Any program can pass a crafted account that passes deserialization but belongs to a different owner.",
    remediation: "Always assert account.owner == program_id before deserializing. Anchor enforces this automatically via typed Account<T> constraints.",
  },
  {
    key: "CUSTOM_PATTERN",
    label: "Custom Pattern",
    baseSeverity: "WARNING",
    description: "A user-defined regex or opcode signature was matched against the program bytecode or account data.",
    remediation: "Review the matched pattern in context. If intentional, document the rationale. Otherwise refactor to eliminate the pattern.",
  },
];

// ── Helpers ───────────────────────────────────────────────────────────────────
export function isValidAddress(address: string): boolean {
  try {
    new PublicKey(address);
    return true;
  } catch {
    return false;
  }
}

export function looksLikeTxSignature(s: string): boolean {
  return s.length >= 80 && !isValidAddress(s);
}

export async function isProgramExecutable(address: string): Promise<boolean> {
  if (!isValidAddress(address)) return false;
  try {
    const info = await connection.getAccountInfo(new PublicKey(address));
    return info ? info.executable : false;
  } catch {
    return false;
  }
}

// ── Payment Verifier ──────────────────────────────────────────────────────────
export async function verifyPayment(signature: string, expectedSolFee: number): Promise<boolean> {
  try {
    let status = null;
    for (let i = 0; i < 5; i++) {
      const res = await connection.getSignatureStatus(signature, { searchTransactionHistory: true });
      if (res?.value) {
        status = res.value;
        if (status.confirmationStatus === "confirmed" || status.confirmationStatus === "finalized") break;
      }
      await new Promise(r => setTimeout(r, 2000));
    }
    if (!status || status.err) return false;

    const tx = await connection.getParsedTransaction(signature, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 0,
    });
    if (!tx?.meta) return false;

    let paid = 0;
    const check = (inst: any) => {
      if (inst?.program === "system" && inst?.parsed?.type === "transfer" &&
        inst?.parsed?.info?.destination === VAULT_ADDRESS) {
        paid += inst.parsed.info.lamports;
      }
    };
    tx.transaction.message.instructions.forEach(check);
    tx.meta.innerInstructions?.forEach(inner => inner.instructions.forEach(check));

    return paid >= (expectedSolFee * LAMPORTS_PER_SOL) - 1000;
  } catch (err: any) {
    console.error(`[Solana] verifyPayment error: ${err.message}`);
    return false;
  }
}

// ── Transaction Forensic Resolver ─────────────────────────────────────────────
export async function resolveTransactionForensics(txHash: string): Promise<ScanTargetInfo> {
  console.log(`[Solana] Resolving transaction forensics: ${txHash}`);
  const tx = await connection.getParsedTransaction(txHash, {
    commitment: "confirmed",
    maxSupportedTransactionVersion: 0,
  });

  if (!tx) {
    throw new Error(`Transaction ${txHash} not found on Solana Devnet.`);
  }

  const programs = new Set<string>();
  const check = (inst: any) => { if (inst?.programId) programs.add(inst.programId.toString()); };
  tx.transaction.message.instructions.forEach(check);
  let innerCallCount = 0;
  tx.meta?.innerInstructions?.forEach(inner => {
    innerCallCount += inner.instructions.length;
    inner.instructions.forEach(check);
  });

  const vulnerabilities: ThreatFinding[] = [];
  const logString = tx.meta?.logMessages?.join(" ") || "";

  if (tx.meta?.err) {
    let matchedKey = "CUSTOM_PATTERN";
    let desc = "Transaction execution failed on-chain.";
    let remediation = "Verify program state constraints and input parameters.";

    if (logString.includes("custom program error")) {
      matchedKey = "OWNER_VERIFICATION";
      desc = "Transaction failed due to custom program error (often incorrect account ownership or signers).";
      remediation = "Assert account ownership and correct constraints in instruction handlers.";
    } else if (logString.includes("Rent-exempt")) {
      matchedKey = "RENT_EXEMPTION_COLLAPSE";
      desc = "Transaction failed due to rent-exempt minimum threshold requirements.";
      remediation = "Ensure the destination accounts contain enough lamports to remain rent-exempt.";
    }

    vulnerabilities.push({
      type: matchedKey,
      severity: "HIGH",
      description: desc,
      remediation,
    });
  }

  return {
    address: txHash,
    type: "TRANSACTION",
    bytecodeSizeKb: 0,
    txCount: 1,
    solBalance: 0,
    owner: "N/A",
    executable: false,
    failedChecks: vulnerabilities.length,
    vulnerabilities,
    forensics: {
      slot: tx.slot,
      blockTime: tx.blockTime ?? null,
      signerCount: tx.transaction.message.accountKeys.filter((k: any) => k.signer).length,
      instructionCount: tx.transaction.message.instructions.length,
      innerCallCount,
      programsInvoked: Array.from(programs),
      fee: tx.meta?.fee ?? 0,
    },
  };
}

// ── Main Scanner ──────────────────────────────────────────────────────────────
export async function resolveAndScanTarget(
  target: string,
  selectedThreats: string[] = [],
  customPattern?: string
): Promise<ScanTargetInfo> {
  console.log(`[Solana] Resolving target: ${target}`);

  // Transaction hash — forensic path
  if (looksLikeTxSignature(target)) {
    return await resolveTransactionForensics(target);
  }

  if (!isValidAddress(target)) {
    throw new Error(`Invalid Solana address format: ${target}`);
  }

  const pubkey = new PublicKey(target);
  const info = await connection.getAccountInfo(pubkey);

  if (!info) {
    throw new Error(`Account address ${target} was not found on Solana Devnet.`);
  }

  const solBalance = info.lamports / LAMPORTS_PER_SOL;
  const owner = info.owner.toBase58();
  const executable = info.executable;
  const bytecodeSizeKb = info.data.length / 1024;
  const programDataHex = Buffer.from(info.data.slice(0, 256)).toString("hex");

  let type: ScanTargetInfo["type"] = "UNKNOWN";
  if (executable) {
    type = "PROGRAM";
  } else if (owner === "11111111111111111111111111111111") {
    type = "WALLET";
  } else {
    type = "PDA";
  }

  // Get transaction count (signatures list)
  const sigs = await connection.getSignaturesForAddress(pubkey, { limit: 10 }).catch(() => []);
  const txCount = sigs.length;

  const vulnerabilities: ThreatFinding[] = [];

  // Live checks
  let failedTxns = 0;
  let logsCombined = "";

  // Query up to 3 transactions to examine runtime log errors
  for (const s of sigs.slice(0, 3)) {
    try {
      const parsed = await connection.getParsedTransaction(s.signature, {
        commitment: "confirmed",
        maxSupportedTransactionVersion: 0,
      });
      if (parsed?.meta) {
        if (parsed.meta.err) failedTxns++;
        if (parsed.meta.logMessages) {
          logsCombined += " " + parsed.meta.logMessages.join(" ");
        }
      }
    } catch { }
  }

  // Map log errors to findings
  if (failedTxns > 0) {
    if (logsCombined.includes("custom program error")) {
      vulnerabilities.push({
        type: "OWNER_VERIFICATION",
        severity: "CRITICAL",
        description: "Recent transaction failure logs indicate account ownership / validation mismatch (custom program error).",
        remediation: "Verify program account constraints are implemented securely.",
      });
    }
    if (logsCombined.includes("Rent")) {
      vulnerabilities.push({
        type: "RENT_EXEMPTION_COLLAPSE",
        severity: "HIGH",
        description: "Recent transaction logs show failures relating to rent exemption minimum balance requirements.",
        remediation: "Ensure created accounts receive correct rent-exempt lamport balances.",
      });
    }
  }

  if (type === "PROGRAM") {
    // Check bytecode size anomalies
    if (bytecodeSizeKb < 5) {
      vulnerabilities.push({
        type: "ACCOUNT_CLOSURE",
        severity: "WARNING",
        description: "Program bytecode is unusually small, indicating a shell program or placeholder.",
        remediation: "Verify the correct deployment transaction or upgrade status.",
      });
    }

    // Check Anchor IDL availability on-chain
    const [idlAddress] = PublicKey.findProgramAddressSync(
      [Buffer.from("idl"), pubkey.toBuffer()],
      pubkey
    );
    const idlAccount = await connection.getAccountInfo(idlAddress).catch(() => null);
    if (!idlAccount) {
      vulnerabilities.push({
        type: "OWNER_VERIFICATION",
        severity: "WARNING",
        description: "Anchor IDL metadata account not found for this program ID.",
        remediation: "Publish the Anchor IDL to enable developer explainability and safety audits.",
      });
    }
  }

  if (type === "WALLET") {
    if (solBalance < 0.005 && txCount > 0) {
      vulnerabilities.push({
        type: "LAMPORT_DRAINING",
        severity: "WARNING",
        description: "Wallet balance is extremely low and depleted. May indicate drainer activity or wallet abandonment.",
        remediation: "Avoid using this wallet for executing high-volume or high-value transactions.",
      });
    }
  }

  if (type === "PDA") {
    if (info.data.length === 0) {
      vulnerabilities.push({
        type: "REINITIALIZATION_ATTACK",
        severity: "WARNING",
        description: "PDA account data is empty. It could be uninitialized or closed.",
        remediation: "Verify state initialization instructions guard against uninitialized inputs.",
      });
    }
  }

  // Custom regex pattern check against bytecode hex or transaction logs
  if (customPattern?.trim()) {
    try {
      const re = new RegExp(customPattern, "i");
      if (re.test(programDataHex) || re.test(logsCombined)) {
        vulnerabilities.push({
          type: "CUSTOM_PATTERN",
          severity: "WARNING",
          description: `Custom pattern regex match '${customPattern}' triggered on program logs/bytecode.`,
          remediation: "Inspect the matched pattern location to eliminate code anomalies.",
        });
      }
    } catch { }
  }

  // Filter vulnerabilities based on selected threats (if custom selection is active)
  const finalVulnerabilities = selectedThreats.length > 0
    ? vulnerabilities.filter(v => selectedThreats.includes(v.type))
    : vulnerabilities;

  return {
    address: target,
    type,
    bytecodeSizeKb,
    txCount,
    solBalance,
    owner,
    executable,
    failedChecks: finalVulnerabilities.length,
    vulnerabilities: finalVulnerabilities,
  };
}
