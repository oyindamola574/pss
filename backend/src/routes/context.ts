// pss/backend/src/routes/context.ts
import express, { Request, Response, NextFunction } from "express";
import { LRUCache } from "lru-cache";

const router = express.Router();

// Initialize LRU Cache (max 50 items, 5 minute TTL)
export const cache = new LRUCache<string, any>({
  max: 50,
  ttl: 1000 * 60 * 5
});

// Cache Middleware
export const cacheMiddleware = (req: Request, res: Response, next: NextFunction) => {
  if (req.method !== "GET") return next();
  const key = req.originalUrl;
  const cached = cache.get(key);
  if (cached) {
    console.log(`[Cache] Cache hit for key: ${key}`);
    return res.json(cached);
  }
  
  // Intercept json responses
  const originalJson = res.json.bind(res);
  res.json = (body: any): Response => {
    cache.set(key, body);
    return originalJson(body);
  };
  next();
};

export interface SecurityArticle {
  id: string;
  headline: string;
  content: string;
  severity: "INFO" | "WARNING" | "CRITICAL";
  threatType: string;
  publishedAt: string;
}

// Mock Security Context Articles (SentinelDataCore equivalent)
const securityArticles: SecurityArticle[] = [
  {
    id: "art-1",
    headline: "Solana CPI Verification Gaps Expose Smart Contracts to Mimicry Attacks",
    content: "Security researchers identified that failing to explicitly verify cross-program invocation (CPI) programs allows malicious contracts to pass fake accounts. The exploit leads to unauthorized state transitions in multi-instruction calls.",
    severity: "CRITICAL",
    threatType: "CPI_REENTRANCY",
    publishedAt: new Date(Date.now() - 3600000 * 4).toISOString()
  },
  {
    id: "art-2",
    headline: "Incorrect Rent Exemption Handling Leads to Account Deinitialization Threats",
    content: "If a system instruction transfers SOL balance away from a data account, dropping it below the minimum rent-exempt threshold, the validator may close the account. This can allow attackers to re-initialize it later with forged parameters.",
    severity: "WARNING",
    threatType: "LAMPORT_DRAINING",
    publishedAt: new Date(Date.now() - 3600000 * 12).toISOString()
  },
  {
    id: "art-3",
    headline: "PDA State Overrides Found in Open-Source Solana DEX Forks",
    content: "A widely copied repository was found to construct Program Derived Addresses (PDA) using user-supplied parameters without verifying the derived seeds logic on the backend. Up to three programs were audited and patched.",
    severity: "CRITICAL",
    threatType: "PDA_STATE_MUTATION",
    publishedAt: new Date(Date.now() - 3600000 * 24).toISOString()
  },
  {
    id: "art-4",
    headline: "Solana Validator Client Releases Crucial Update on Devnet Status",
    content: "New slot scheduler updates have landed on Devnet to optimize slot processing efficiency. Upcoming slot leader skip ratios are predicted to drop by 4.2% globally, reducing transaction latency.",
    severity: "INFO",
    threatType: "GENERAL",
    publishedAt: new Date(Date.now() - 3600000 * 48).toISOString()
  }
];

// GET: Fetch all security articles (Cached)
router.get("/articles", cacheMiddleware, (req: Request, res: Response) => {
  res.json(securityArticles);
});

// GET: Fetch articles filtering by threat type (Cached)
router.get("/articles/threat/:type", cacheMiddleware, (req: Request, res: Response) => {
  const type = req.params.type.toUpperCase();
  const filtered = securityArticles.filter(art => art.threatType === type || type === "GENERAL");
  res.json(filtered);
});

// POST: Add new security article (Admin action - clears cache)
router.post("/articles", (req: Request, res: Response) => {
  const { headline, content, severity, threatType } = req.body;
  if (!headline || !content) {
    return res.status(400).json({ error: "Missing article headline or content" });
  }

  const newArticle: SecurityArticle = {
    id: `art-${Date.now()}`,
    headline,
    content,
    severity: severity || "INFO",
    threatType: threatType || "GENERAL",
    publishedAt: new Date().toISOString()
  };

  securityArticles.unshift(newArticle);
  cache.clear(); // invalidate all cached routes
  console.log("[Cache] New article added, LRU cache cleared.");
  res.status(201).json(newArticle);
});

export default router;
