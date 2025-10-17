
# Metridex — On-chain Hotfix (2025-10-17)

Scope: stabilize "🧪 On-chain" for BSC/Polygon/Ethereum, eliminate silent failures, reduce redundant RPC calls.

## What changed
1) **onchain_inspector.py**
   - Rewrote `inspect_token(...)` to be **non-throwing** and **idempotent** (short TTL cache).
   - Fixed a bug with **duplicate ERC‑20 reads** (`name/symbol/decimals` were requested twice), which caused extra latency and potential timeouts.
   - Pick the first working RPC from candidates; if none confirmed, fall back to the first candidate (still returns a safe stub).
   - Clearer error surface (`invalid token address` vs. previous generic message).
   - Preserves legacy compatibility via `build_onchain_payload(...)` wrapper.

2) **selfcheck_onchain.py** (new)
   - Offline smoke‑test that monkey‑patches network calls to verify code paths without Internet.
   - Exercises inspector and v2 renderer for two addresses: CAKE (BSC) and 0x9fc5… (ETH).

## Why it helps
- **Silent button** cases typically happen when a deep exception bubbles up or timeouts cascade. Now the inspector never raises and always returns a dict, so the server’s fallback renderers can respond.
- Removing duplicate RPC calls cuts request volume by ~2× per click, lowering the probability of timeouts on rate‑limited public RPCs.
- The result shape is unchanged, so `format_onchain_text(...)` and `render_onchain_v2(...)` continue to work.

## Suggested follow‑ups (server-side; optional now)
- In the `ONCHAIN` handler, add a final **“ensure reply”** guard: if no message was sent after all branches, send `render_onchain_v2(...)` (minimal output). This guarantees a user‑visible response even if upstream data is missing.
- Consider reducing JSON‑RPC timeouts to 6–8s and capping total retries per click.

## Regression safety
- `compileall` passes.
- `selfcheck_onchain.py` runs OK offline (no network).

— Prepared for production review.
