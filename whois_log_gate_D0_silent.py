# D0.x — whois log silencer (drop-in; import early in server entrypoint)
import logging
for name in ("whois", "whois.whois"):
    try:
        logging.getLogger(name).setLevel(logging.CRITICAL)
    except Exception:
        pass
