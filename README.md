# Protocol Security Scout (PSS)

**Protocol Security Scout (PSS)** is a risk intelligence layer that scores swap routes, transactions, and pools for MEV exposure, sandwich risk, and liquidity impact before trade execution.

PSS is designed for Solana wallets, trading terminals, automated Telegram/Discord bots, route providers, RPC providers, and protocol dashboards that need to warn users before they submit risky swaps.

## Problem

Solana DeFi users face silent and often devastating value loss at the moment of swap execution. Retail traders, automated Telegram bots, high-frequency terminals, and protocol treasuries all depend on interfaces that show quotes, routes, and transaction previews without contextualizing the underlying battlefield.

A user may see a favorable price while remaining blind to sandwich bots circling the pool, stale oracle or quote data that can trigger massive slippage, liquidity depth that is insufficient for the order size, or a priority-fee arms race they are about to lose. Post-trade explorers such as Solscan or Dune quantify damage after the fact, while execution venues such as Jupiter or Jito primarily focus on routing optimization and execution infrastructure.

The fragmented landscape leaves a critical gap: there is no independent, neutral layer that analyzes swap intent and warns users before they submit the transaction. That gap erodes user trust, creates preventable losses, and weakens UX across the Solana ecosystem.

## Solution

PSS fills the gap as a neutral, Solana-native risk intelligence layer. Rather than competing with aggregators or execution venues, PSS acts as a safety overlay that plugs directly into wallets, trading bots, terminals, route providers, and protocol dashboards.

Integrations submit a swap route, raw transaction, pool address, or token pair to the PSS API and receive a structured intelligence packet:

- `riskScore`: quantitative score from 0-100
- `riskLevel`: Low, Medium, High, or Critical
- `riskReasons`: granular explanations for detected threats
- `recommendedAction`: clear mitigation guidance
- `confidence`: certainty of the analysis
- `dataQuality`: completeness of available on-chain data

PSS follows a strict safety-by-default doctrine. It recommends mitigations such as using protected routing lanes, lowering slippage tolerance, splitting orders across multiple routes, refreshing quotes, waiting for volatility to settle, or avoiding compromised pools. It does not execute trades or submit bundles, preserving its integrity as an independent advisory layer.

## Current Implementation

The current codebase is a working full-stack implementation:

- React/Vite analytics desk with Tailwind UI
- Express/Solana backend using `@solana/web3.js`
- Live Solana Devnet account and transaction resolution
- WebSocket-driven scan progress
- Automated report generation
- Collaborative task board for review workflow
- KNN prototype classifier
- Labeled dataset loader
- Benchmark metrics harness
- Wallet support for Phantom, Solflare, and MetaMask Solana providers

The implementation has been verified with:

```bash
npm run build
npm test
```

## Local Development

Install dependencies:

```bash
npm run install:all
```

Run backend and frontend together:

```bash
npm run dev
```

Run the backend:

```bash
cd backend
npm run dev
```

Run the frontend:

```bash
cd frontend
npm run dev
```

Build everything:

```bash
npm run build
```

Run tests:

```bash
npm test
```

## Project Direction

PSS is not an MEV bot, DEX aggregator, or execution venue. It is the independent intelligence layer that evaluates swap intent and explains risk before execution.
