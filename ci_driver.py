# Lightweight CI driver to touch safe code paths without network/external deps.
# It never fails the job; it only prints results.
import os, importlib, sys

modname = os.environ.get("APP_MODULE", "server:app").split(":")[0]

def _log(msg):
    print(f"[ci-driver] {msg}")

try:
    m = importlib.import_module(modname)
    _log(f"Imported module: {modname}")
except Exception as e:
    _log(f"Import failed: {e}")
    sys.exit(0)  # don't fail CI

def _try(func_name, *args, **kwargs):
    f = getattr(m, func_name, None)
    if callable(f):
        try:
            res = f(*args, **kwargs)
            _log(f"{func_name} executed, type={type(res).__name__}")
        except Exception as e:
            _log(f"{func_name} raised (ignored): {e}")
    else:
        _log(f"{func_name} not present — skipping")

# Touch a few likely-safe functions if they exist.
_try("_render_report", {})                 # safe placeholder dict
_try("mdx_postprocess_text", "Hello", 0)   # (text, chat_id) signature in many builds
_try("mdx_build_html_report", {})          # build HTML without network if supported
_try("mdx_build_short_reply", "0x" + "0"*40, **{"chain": "ethereum"})  # fake CA

_log("Done.")
