# -*- coding: utf-8 -*-
import os, sys, time, importlib.util

# --- Hard bind the renderer by absolute path ---
RENDERERS_PATH = os.getenv("RENDERERS_PATH", "/opt/render/project/src/renderers_mdx.py")
spec = importlib.util.spec_from_file_location("renderers_mdx", RENDERERS_PATH)
_renderers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_renderers)

# Export expected symbols for the rest of the server:
render_quick   = _renderers.render_quick
render_details = _renderers.render_details
render_why     = _renderers.render_why
render_whypp   = _renderers.render_whypp
render_lp      = _renderers.render_lp

# Boot log (stderr) to verify which module is active
sys.stderr.write(f"[BOOT] Using renderers module: {_renderers.__file__} | tag={getattr(_renderers, 'RENDERER_BUILD_TAG', None)}\n")

# --- Rest of your original server.py should follow below ---
# (Paste the rest of your server implementation here, unchanged.)
