# AUTO-GENERATED SHIM — routes LP-lite calls to v2
# Version: lp-shim-2025-10-17
# Do not edit here; maintain only lp_lite_v2.py

try:
    # Re-export the public API from v2
    from lp_lite_v2 import (
        check_lp_lock_v2,
    )
    # Optionally export constants if callers rely on them
    from lp_lite_v2 import DEAD, ZERO
except Exception as e:
    # Keep import-time errors explicit to fail fast during deployment
    raise

__all__ = ["check_lp_lock_v2", "DEAD", "ZERO"]
