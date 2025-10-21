# watchlite_0_1_3.py — Watchlist + Alerts (lite) with help UX & presets
# Non-invasive drop-in for Metridex server.
# Storage: watch_db.json (per-chat watchlist) and watch_state.json (per-chat config/state).

import os, json, time, threading, re

# --- Public limits / defaults ---
_DEFAULT_DB = "./watch_db.json"
_DEFAULT_STATE = "./watch_state.json"
_DEFAULT_LIMIT = 200

# --- Server callback hooks (wired via init()) ---
_send_message = None
_send_raw = None
_escape = None
_tg = None
_build_kbd = None
_fetch_market = None
_answer_cb = None

DB_PATH = _DEFAULT_DB
STATE_PATH = _DEFAULT_STATE
LIMIT = _DEFAULT_LIMIT

# In-memory caches
_db = {}
_state = {}
_lock = threading.RLock()
_ticker_started = False

# Defaults
_DEFAULT_THRESHOLDS = {"d5": 2.0, "d1h": 5.0, "d24": 10.0, "vol": 250000.0}
_DEFAULT_INTERVAL_MIN = 15
_DEFAULT_COOLDOWN_MIN = 60
_DEFAULT_PRESET = "normal"

_PRESETS = {
    "fast":   {"d5": 1.0, "d1h": 3.0,  "d24": 7.0,  "vol": 150000.0, "int": 10, "cd": 45},
    "normal": {"d5": 2.0, "d1h": 5.0,  "d24": 10.0, "vol": 250000.0, "int": 15, "cd": 60},
    "calm":   {"d5": 3.0, "d1h": 8.0,  "d24": 15.0, "vol": 400000.0, "int": 30, "cd": 90},
}

def _is_cmd(low: str, base: str) -> bool:
    if not isinstance(low, str):
        return False
    return re.match(rf'^/{base}(?:@[\w_]+)?(?:\s|$)', low) is not None

def _ensure_loaded():
    global _db, _state
    with _lock:
        try:
            with open(DB_PATH, "r", encoding="utf-8") as f:
                _db = json.load(f) or {}
        except Exception:
            _db = {}
        try:
            with open(STATE_PATH, "r", encoding="utf-8") as f:
                _state = json.load(f) or {}
        except Exception:
            _state = {}

def _save_db():
    with _lock:
        try:
            with open(DB_PATH, "w", encoding="utf-8") as f:
                json.dump(_db, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

def _save_state():
    with _lock:
        try:
            with open(STATE_PATH, "w", encoding="utf-8") as f:
                json.dump(_state, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

def _now(): return int(time.time())

def _cfg(cid):
    s = _state.setdefault(str(cid), {})
    s.setdefault("enabled", True)
    s.setdefault("thresholds", dict(_DEFAULT_THRESHOLDS))
    s.setdefault("interval_min", _DEFAULT_INTERVAL_MIN)
    s.setdefault("cooldown_min", _DEFAULT_COOLDOWN_MIN)
    s.setdefault("preset", _DEFAULT_PRESET)
    s.setdefault("mute_until_ts", 0)
    s.setdefault("last_tick_ts", 0)
    s.setdefault("last_token", None)
    s.setdefault("last_alerts", {})  # key: f"{token}:{metric}" -> ts
    s.setdefault("hints", {})        # onboarding flags
    return s

def _wl(cid):
    return _db.setdefault(str(cid), [])

def _md(text):
    if _escape:
        try: return _escape(text)
        except Exception: pass
    return text

def _find_token_in_text(text):
    if not isinstance(text, str): return None
    m = re.search(r'(0x[a-fA-F0-9]{40})', text)
    return m.group(1) if m else None

def _chain_slug(name):
    n = (name or "").lower()
    if n in ("eth","ethereum","mainnet"): return "ethereum"
    if n in ("bsc","bnb","binance-smart-chain","binance smart chain"): return "bsc"
    if n in ("polygon","matic"): return "polygon"
    if n.startswith("arbitrum"): return "arbitrum"
    if n in ("base",): return "base"
    if n in ("optimism","op"): return "optimism"
    if n in ("avalanche","avax"): return "avalanche"
    if n in ("fantom","ftm"): return "fantom"
    return n or "ethereum"

def _scan_url(chain, token):
    cs = _chain_slug(chain)
    routes = {
        "ethereum": f"https://etherscan.io/token/{token}",
        "bsc": f"https://bscscan.com/token/{token}",
        "polygon": f"https://polygonscan.com/token/{token}",
        "arbitrum": f"https://arbiscan.io/token/{token}",
        "base": f"https://basescan.org/token/{token}",
        "optimism": f"https://optimistic.etherscan.io/token/{token}",
        "avalanche": f"https://snowtrace.io/token/{token}",
        "fantom": f"https://ftmscan.com/token/{token}",
    }
    return routes.get(cs, f"https://etherscan.io/token/{token}")

def _dex_url(chain, token, mkt=None):
    # Prefer dexscreener pair if present, else token search
    cs = _chain_slug(chain)
    pair = None
    if isinstance(mkt, dict):
        pair = (mkt.get("pairAddress") or mkt.get("pair") or "").strip() or None
        if not pair:
            # some sources nest in links
            pair = ((mkt.get("links") or {}).get("pair") or "").strip() or None
    if pair:
        return f"https://dexscreener.com/{cs}/{pair}"
    # token search as fallback
    return f"https://dexscreener.com/search?q={token}"

def _normalized_links(links, chain, token, mkt=None):
    # Merge provided links with our fallbacks
    out = {}
    if isinstance(links, dict):
        out.update({k:v for k,v in links.items() if isinstance(v, str) and v})
    # Always ensure scan exists
    out.setdefault("scan", _scan_url(chain, token))
    # DEX only if provided or we can build a plausible url
    out.setdefault("dex", _dex_url(chain, token, mkt))
    return out

def _safe_acb(cb_id, text="OK", alert=False):
    try:
        if _answer_cb:
            _answer_cb(cb_id, text, alert)
            return
    except Exception:
        pass
    try:
        if _tg:
            _tg("answerCallbackQuery", callback_query_id=cb_id, text=text, show_alert=alert)
    except Exception:
        pass

def _build_watch_keyboard(links, token, watched):
    rows = []
    if isinstance(links, dict):
        if links.get("dex"):  rows.append([{"text":"🟢 Open in DEX", "url": links["dex"]}])
        if links.get("scan"): rows.append([{"text":"🔍 Open in Scan", "url": links["scan"]}])
    rows.append([{"text":"👁️ Watch", "callback_data": f"WATCH_T:{token}"}, {"text":"👁️ Unwatch", "callback_data": f"UNWATCH_T:{token}"}])
    # preset controls row
    rows.append([{"text":"⚡ Fast", "callback_data":"ALERT_PRESET:fast"}, {"text":"🟨 Normal", "callback_data":"ALERT_PRESET:normal"}, {"text":"🌙 Calm", "callback_data":"ALERT_PRESET:calm"}])
    rows.append([{"text":"🔕 Mute 24h", "callback_data":"MUTE_24H"}, {"text":"🔔 Unmute", "callback_data":"UNMUTE"}])
    return {"inline_keyboard": rows}

def _build_alert_keyboard(links, token):
    rows = []
    if isinstance(links, dict):
        if links.get("dex"):  rows.append([{"text":"🟢 Open in DEX", "url": links["dex"]}])
        if links.get("scan"): rows.append([{"text":"🔍 Open in Scan", "url": links["scan"]}])
    rows.append([{"text":"👁️ Unwatch", "callback_data": f"UNWATCH_T:{token}"}])
    rows.append([{"text":"🔕 Mute 24h", "callback_data":"MUTE_24H"}, {"text":"🔔 Unmute", "callback_data":"UNMUTE"}])
    return {"inline_keyboard": rows}

def _build_presets_keyboard():
    return {"inline_keyboard":[
        [
            {"text":"⚡ Fast",   "callback_data":"ALERT_PRESET:fast"},
            {"text":"🟨 Normal", "callback_data":"ALERT_PRESET:normal"},
            {"text":"🌙 Calm",   "callback_data":"ALERT_PRESET:calm"},
        ]
    ]}

def init(paths=None, limit=None, send_message_fn=None, send_message_raw=None, tg_fn=None, escape_fn=None, fetch_market_fn=None, build_keyboard_fn=None, answer_callback_fn=None):
    global DB_PATH, STATE_PATH, LIMIT, _send_message, _send_raw, _escape, _tg, _fetch_market, _build_kbd, _answer_cb
    if isinstance(paths, dict):
        DB_PATH = paths.get("db") or DB_PATH
        STATE_PATH = paths.get("state") or STATE_PATH
    if isinstance(limit, int) and limit > 0:
        LIMIT = limit
    _send_message = send_message_fn or _send_message
    _send_raw = send_message_raw or _send_raw
    _escape = escape_fn or _escape
    _tg = tg_fn or _tg
    _fetch_market = fetch_market_fn or _fetch_market
    _build_kbd = build_keyboard_fn or _build_kbd
    _answer_cb = answer_callback_fn or _answer_cb
    _ensure_loaded()
    _start_ticker_once()

def _start_ticker_once():
    global _ticker_started
    if _ticker_started: return
    t = threading.Thread(target=_ticker_loop, name="watchlite-ticker", daemon=True)
    t.start()
    _ticker_started = True

def _fmt_thresholds(cfg):
    th = cfg.get("thresholds") or {}
    return (f"d5={th.get('d5', _DEFAULT_THRESHOLDS['d5'])}%  "
            f"d1h={th.get('d1h', _DEFAULT_THRESHOLDS['d1h'])}%  "
            f"d24={th.get('d24', _DEFAULT_THRESHOLDS['d24'])}%  "
            f"vol≈${int(th.get('vol', _DEFAULT_THRESHOLDS['vol'])):,}  "
            f"int={cfg.get('interval_min', _DEFAULT_INTERVAL_MIN)}m  "
            f"cd={cfg.get('cooldown_min', _DEFAULT_COOLDOWN_MIN)}m")

def _parse_set_args(text):
    # supports: reset | preset X | d5=2 d1h=5 d24=10 vol=250k int=15 cd=60
    low = text.strip().lower()
    if " reset" in low or low.endswith(" reset") or low.strip() == "/alerts_set reset":
        return {"reset": True}
    m = re.search(r"preset\s+([a-z]+)", low)
    preset = m.group(1) if m else None
    kv = {}
    for k in ("d5","d1h","d24","vol","int","cd"):
        mo = re.search(rf"{k}\s*=\s*([0-9]+(?:\.[0-9]+)?[kKmM]?)", low)
        if mo:
            val = mo.group(1)
            if k == "vol":
                v = val.lower()
                mult = 1
                if v.endswith("k"): mult = 1000; v=v[:-1]
                elif v.endswith("m"): mult = 1000000; v=v[:-1]
                try: kv[k] = float(v) * mult
                except Exception: pass
            else:
                try: kv[k] = float(val)
                except Exception: pass
    return {"preset": preset, "kv": kv}

def _status_text(cid):
    cfg = _cfg(cid)
    wl = _wl(cid)
    enabled = cfg.get("enabled", True)
    mute_ts = int(cfg.get("mute_until_ts") or 0)
    muted = mute_ts > _now()
    mute_left = max(0, mute_ts - _now())
    lines = [
        f"*Alerts:* {'ON' if enabled else 'OFF'}  {'🔕 muted' if muted else ''}",
        f"*Preset:* {cfg.get('preset','normal')}",
        "*Thresholds:* " + _fmt_thresholds(cfg),
        f"*Watchlist:* {len(wl)} tokens (limit {LIMIT})",
    ]
    if muted:
        mins = int(round(mute_left/60.0))
        lines.append(f"*Mute:* {mins} min left")
    lines.append("Presets: `/alerts_set preset fast|normal|calm` • Custom: `/alerts_set d5=… d1h=… d24=… vol=… int=… cd=…`")
    lines.append("Help: `/watch_help`, `/alerts_help`")
    return "\n".join(lines)

def handle_message_commands(chat_id: int, text: str, load_bundle_fn=None, raw_msg=None):
    """Return True if handled fully (intercepted); otherwise False to delegate to original on_message."""
    if not isinstance(text, str): return False
    low = text.strip().lower()
    if not low.startswith("/"): return False

    _ensure_loaded()
    cfg = _cfg(chat_id)

    def reply(msg, **kw):
        if _send_message: _send_message(chat_id, msg, **kw)

    # /watch
    if _is_cmd(low, 'watch'):
        parts = text.split(None, 1)
        token = parts[1].strip() if len(parts) > 1 else cfg.get("last_token")
        if not (isinstance(token, str) and token.startswith("0x") and len(token)==42):
            reply("Usage: `/watch 0x...` or scan a token first, then `/watch` (no args).")
            return True
        wl = _wl(chat_id)
        tok = token.lower()
        if tok not in wl:
            if len(wl) >= LIMIT:
                reply(f"Watchlist is full (limit {LIMIT}). Remove some with `/unwatch 0x...`")
                return True
            wl.append(tok); _save_db()
        # Info + buttons
        try: mkt = _fetch_market(tok) if _fetch_market else None
        except Exception: mkt = None
        if isinstance(mkt, dict):
            psym = mkt.get("pairSymbol") or "Token"
            chain = mkt.get("chain") or "—"
            links = _normalized_links(mkt.get("links") or {}, chain, tok, mkt)
            kb = _build_watch_keyboard(links, tok, watched=True)
            header = f"*Watching — {psym}*  `[{chain}]`\n`{tok}`"
            reply(header, reply_markup=kb)
        else:
            reply(f"Watching `{tok}`. Total: {len(_wl(chat_id))}")
        return True

    # /unwatch
    if _is_cmd(low, 'unwatch'):
        parts = text.split(None, 1)
        token = parts[1].strip() if len(parts) > 1 else cfg.get("last_token")
        if not (isinstance(token, str) and token.startswith("0x") and len(token)==42):
            reply("Usage: `/unwatch 0x...` or scan a token first, then `/unwatch` (no args).")
            return True
        wl = _wl(chat_id); tok = token.lower()
        if tok in wl:
            wl.remove(tok); _save_db()
            try: mkt = _fetch_market(tok) if _fetch_market else None
            except Exception: mkt = None
            if isinstance(mkt, dict):
                psym = mkt.get("pairSymbol") or "Token"
                chain = mkt.get("chain") or "—"
                links = _normalized_links(mkt.get("links") or {}, chain, tok, mkt)
                kb = _build_watch_keyboard(links, tok, watched=False)
                header = f"*Unwatched — {psym}*  `[{chain}]`\n`{tok}`"
                reply(header, reply_markup=kb)
            else:
                reply(f"Removed `{tok}` from watchlist. Total: {len(_wl(chat_id))}")
        else:
            reply(f"Not in watchlist: `{tok}`")
        return True

    # /watchlist
    if _is_cmd(low, 'watchlist'):
        wl = _wl(chat_id)
        if not wl:
            reply("Watchlist is empty. Add with `/watch 0x...` or scan a token then `/watch`. For help: `/watch_help`")
            return True
        lines = ["*Watchlist*"] + [f"{i}. `{t}`" for i,t in enumerate(wl,1)]
        reply("\n".join(lines)); return True

    # Alerts toggles/config
    if _is_cmd(low, 'alerts_on'):  cfg["enabled"]=True;  _save_state(); reply("Alerts: ON");  return True
    if _is_cmd(low, 'alerts_off'): cfg["enabled"]=False; _save_state(); reply("Alerts: OFF"); return True

    if _is_cmd(low, 'alerts_set'):
        p = _parse_set_args(text)
        if p.get("reset"):
            cfg["thresholds"] = dict(_DEFAULT_THRESHOLDS)
            cfg["interval_min"] = _DEFAULT_INTERVAL_MIN
            cfg["cooldown_min"] = _DEFAULT_COOLDOWN_MIN
            cfg["preset"] = "normal"
            _save_state(); reply("Alerts config reset to defaults."); return True
        if p.get("preset"):
            name = (p["preset"] or "").strip().lower()
            if name in _PRESETS:
                pr = _PRESETS[name]
                cfg["thresholds"] = {k: pr[k] for k in ("d5","d1h","d24","vol")}
                cfg["interval_min"] = pr["int"]
                cfg["cooldown_min"] = pr["cd"]
                cfg["preset"] = name
                _save_state(); reply(f"Preset applied: *{name}*\n" + _fmt_thresholds(cfg)); return True
            else:
                reply("Unknown preset. Use: `fast`, `normal`, or `calm`."); return True
        kv = p.get("kv") or {}
        if kv:
            th = cfg["thresholds"]
            for k,v in kv.items():
                if k in ("d5","d1h","d24","vol"): th[k] = float(v)
                elif k == "int": cfg["interval_min"] = max(1, int(float(v)))
                elif k == "cd":  cfg["cooldown_min"] = max(1, int(float(v)))
            cfg["preset"] = "custom"; _save_state(); reply("Alerts updated.\n"+_fmt_thresholds(cfg)); return True
        reply("Usage: `/alerts_set d5=2 d1h=5 d24=10 vol=250k int=15 cd=60` or `preset fast|normal|calm` or `reset`."); return True

    if _is_cmd(low, 'alerts_mute'):
        minutes=1440
        parts=text.split(None,1)
        if len(parts)>1:
            try: minutes=max(1,int(float(parts[1].strip())))
            except Exception: minutes=1440
        cfg["mute_until_ts"]=_now()+minutes*60; _save_state(); reply(f"Muted alerts for {minutes} minutes."); return True

    if _is_cmd(low, 'alerts_unmute'):
        cfg["mute_until_ts"]=0; _save_state(); reply("Unmuted alerts."); return True

    if _is_cmd(low, 'alerts'):
        reply(_status_text(chat_id)); return True

    # Help commands
    if _is_cmd(low, 'watch_help'):
        lines = [
            "*Watchlist — how to use*",
            "1) Paste a token (0x…), TX hash or pair link to scan it.",
            "2) Add: `/watch 0x...` or just `/watch` right after a scan.",
            "3) Manage: `/watchlist` to view, `/unwatch 0x...` to remove.",
            "4) Alerts: `/alerts` for status. Presets: `/alerts_set preset fast|normal|calm`.",
        ]
        reply("\n".join(lines), reply_markup=_build_presets_keyboard()); return True

    if _is_cmd(low, 'alerts_help'):
        lines = [
            "*Alerts — thresholds & presets*",
            "• Triggers: |Δ5m|, |Δ1h|, |Δ24h|, Vol24h.",
            "• Defaults: d5=2% d1h=5% d24=10% vol=$250k int=15m cd=60m",
            "• Presets: `/alerts_set preset fast|normal|calm`",
            "• Custom: `/alerts_set d5=1.5 d1h=4 d24=8 vol=150k int=10 cd=45`",
            "• Mute: `/alerts_mute 60`  /  `/alerts_unmute`",
        ]
        reply("\n".join(lines), reply_markup=_build_presets_keyboard()); return True

    return False

def handle_callback(cb):
    """Intercept own callbacks. Return True if consumed; else False to delegate."""
    data = (cb.get("data") or "")
    msg = cb.get("message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    cb_id = cb.get("id")
    if not chat_id:
        return False
    _ensure_loaded()
    cfg = _cfg(chat_id)

    # Presets via buttons
    if data.startswith("ALERT_PRESET:"):
        name = data.split(":",1)[1].strip().lower()
        if name in _PRESETS:
            pr = _PRESETS[name]
            cfg["thresholds"] = {k: pr[k] for k in ("d5","d1h","d24","vol")}
            cfg["interval_min"] = pr["int"]
            cfg["cooldown_min"] = pr["cd"]
            cfg["preset"] = name
            _save_state()
            _safe_acb(cb_id, f"Preset applied: {name}", False)
            if _send_message: _send_message(chat_id, "Preset applied.\n"+_fmt_thresholds(cfg))
            return True
        else:
            _safe_acb(cb_id, "Unknown preset.", True)
            return True

    # WATCH_T / UNWATCH_T with explicit token
    if data.startswith("UNWATCH_T:") or data.startswith("WATCH_T:"):
        tok = data.split(":",1)[1].strip().lower()
        wl = _wl(chat_id)
        if data.startswith("UNWATCH_T:"):
            if tok in wl:
                wl.remove(tok); _save_db()
                _safe_acb(cb_id, "Removed from watchlist.", False)
                if _send_message: _send_message(chat_id, f"Removed `{tok}` from watchlist.")
            else:
                _safe_acb(cb_id, "Not in watchlist.", False)
            return True
        else:
            if tok not in wl and len(wl) < LIMIT:
                wl.append(tok); _save_db()
                _safe_acb(cb_id, "Added to watchlist.", False)
                if _send_message: _send_message(chat_id, f"Watching `{tok}`. Total: {len(wl)}")
            else:
                _safe_acb(cb_id, "Already watching or list full.", False)
            return True

    # Legacy WATCH/UNWATCH without token — use message token or last_token
    if data in ("WATCH","UNWATCH"):
        msg_text = (msg.get("text") or "") + "\n" + (msg.get("caption") or "")
        tok = _find_token_in_text(msg_text) or cfg.get("last_token")
        if not (isinstance(tok, str) and tok.startswith("0x") and len(tok)==42):
            _safe_acb(cb_id, "Scan a token first.", True); return True
        wl = _wl(chat_id)
        if data == "WATCH":
            if tok not in wl and len(wl) < LIMIT:
                wl.append(tok); _save_db()
                _safe_acb(cb_id, "Added to watchlist.", False)
                if _send_message: _send_message(chat_id, f"Watching `{tok}`. Total: {len(wl)}")
            else:
                _safe_acb(cb_id, "Already watching or list full.", False)
            return True
        else:
            if tok in wl:
                wl.remove(tok); _save_db()
                _safe_acb(cb_id, "Removed from watchlist.", False)
                if _send_message: _send_message(chat_id, f"Removed `{tok}` from watchlist.")
            else:
                _safe_acb(cb_id, "Not in watchlist.", False)
            return True

    if data == "MUTE_24H":
        cfg["mute_until_ts"] = _now() + 24*3600; _save_state()
        _safe_acb(cb_id, "Muted for 24h.", False)
        if _send_message: _send_message(chat_id, "Muted alerts for 24h.")
        return True

    if data == "UNMUTE":
        cfg["mute_until_ts"] = 0; _save_state()
        _safe_acb(cb_id, "Unmuted.", False)
        if _send_message: _send_message(chat_id, "Unmuted alerts.")
        return True

    return False

def note_quickscan(chat_id: int, bundle: dict, msg_id=None):
    """Record last token from QuickScan result to support /watch with no args."""
    if not isinstance(bundle, dict): return
    mkt = (bundle.get("market") or {})
    tok = (mkt.get("tokenAddress") or "").strip()
    if tok and tok.startswith("0x") and len(tok)==42:
        _ensure_loaded()
        cfg = _cfg(chat_id)
        cfg["last_token"] = tok
        _save_state()

def _pct(v):
    try:
        n = float(v); arrow = "▲" if n>0 else ("▼" if n<0 else "•")
        return f"{arrow} {n:+.2f}%"
    except Exception:
        return "—"

def _maybe_alert_for_token(cid, tok, cfg):
    now = _now()
    if (cfg.get("mute_until_ts") or 0) > now: return
    try: mkt = _fetch_market(tok) if _fetch_market else None
    except Exception: mkt = None
    if not (isinstance(mkt, dict) and mkt.get("ok")): return

    ch = mkt.get("priceChanges") or {}
    vol = mkt.get("vol24h") or 0
    th = cfg.get("thresholds") or _DEFAULT_THRESHOLDS
    triggered = []

    def _add(metric, label, val, thr):
        try:
            if abs(float(val)) >= float(thr): triggered.append((metric,label,val,thr))
        except Exception: pass

    if "m5" in ch:  _add("d5",  "Δ5m",  ch.get("m5"),  th.get("d5",  _DEFAULT_THRESHOLDS["d5"]))
    if "h1" in ch:  _add("d1h", "Δ1h",  ch.get("h1"),  th.get("d1h", _DEFAULT_THRESHOLDS["d1h"]))
    if "h24" in ch: _add("d24", "Δ24h", ch.get("h24"), th.get("d24", _DEFAULT_THRESHOLDS["d24"]))

    try: v_ok = float(vol) >= float(th.get("vol", _DEFAULT_THRESHOLDS["vol"]))
    except Exception: v_ok = False
    if v_ok: triggered.append(("vol","Vol24h",vol, th.get("vol", _DEFAULT_THRESHOLDS["vol"])))

    if not triggered: return

    # cooldown per token+metric
    cd = int(cfg.get("cooldown_min", _DEFAULT_COOLDOWN_MIN))*60
    la = cfg.setdefault("last_alerts", {})
    any_send=False; lines=[]
    for metric,label,val,thr in triggered:
        key=f"{tok}:{metric}"; last=int(la.get(key) or 0)
        if now - last < cd: continue
        la[key]=now; lines.append(f"*{label}*: {_pct(val)} (≥ {thr})"); any_send=True

    if not any_send: return

    chain = (mkt.get("chain") or "—"); psym = mkt.get("pairSymbol") or "Token"
    header = f"*Alert — {psym}*  `[{chain}]`"
    text = header + "\n" + "\n".join(lines)
    links = _normalized_links(mkt.get("links") or {}, chain, tok, mkt)
    kb = _build_alert_keyboard(links, tok)
    if _send_message:
        _send_message(cid, text, reply_markup=kb); _save_state()

def _ticker_loop():
    while True:
        try:
            time.sleep(30)  # coarse tick
            _ensure_loaded()
            now = _now()
            for cid, cfg in list(_state.items()):
                try: cid_int = int(cid)
                except Exception: continue
                if not cfg.get("enabled", True): continue
                interval = max(1, int(cfg.get("interval_min", _DEFAULT_INTERVAL_MIN)))*60
                last = int(cfg.get("last_tick_ts") or 0)
                if now - last < interval: continue
                cfg["last_tick_ts"]=now; _save_state()
                wl = _db.get(str(cid), []) or []
                for tok in list(wl):
                    _maybe_alert_for_token(cid_int, tok, cfg)
        except Exception:
            time.sleep(1)
