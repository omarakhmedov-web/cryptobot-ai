# Metridex — Regression Checklist (QuickScan & HTML Report)

## Core invariants
1. **Score equality**: Chat badge score equals HTML header score (same clamp: when level=LOW and score=0 → show **15**).
2. **Snapshot completeness** (HTML): `Price`, `FDV`, `MC`, `Liquidity`, `24h Volume`, `Δ5m`, `Δ1h`, `Δ24h`, `Age`, `Source`, `As of` — present and non-empty (use `—` only if truly unavailable).
3. **Chain normalization**: Chain name rendered as `Ethereum / BSC / Polygon / ...` (not lowercase/raw).
4. **Links**:
   - **DEX**: official domain per chain (Uniswap / PancakeSwap / QuickSwap / ...).
   - **Scan**: correct explorer per chain (Etherscan / BscScan / Polygonscan / ...).
   - **DexScreener**: present for tradable pairs and points to the **pair**.
   - **Site**: shown if provided by market (optional for legacy tokens).
5. **Why / Why++** (chat): sections present; factors match top metrics by sense (liquidity/volume/age/moves).
6. **On‑chain**: `owner`, `renounced`, `paused`, `upgradeable`, `maxTx`, `maxWallet` displayed (use `—` for N/A).
7. **LP lock (lite)**: at minimum shows LP token address; when RPC configured — adds `status` (Burned/Locked/Unknown) and basic percentages.
8. **No pools** case: badge score forced `80`, explicit reason “No pools / not tradable”; if chain is known — include “Open in Scan”; show a friendly hint to paste pair URL.

## Performance / UX
- Callback de‑dup works for DETAILS/WHY/WHY++/LP/REPORT; TTL≈30s (env).
- Buttons: official DEX/Scan first row; no duplicate DexScreener.
- HTML export: filename `PAIR_Report_YYYY-MM-DD_HHMM.html`.