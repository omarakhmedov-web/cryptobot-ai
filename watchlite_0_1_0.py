
# watchlite_0_1_0.py — minimal, non-invasive Watchlist + Alerts (lite) for Metridex
# Requirements: no new ENV. Uses JSON files next to server: watch_db.json, watch_state.json
# Features:
# - Commands: /watch, /unwatch [0x..], /watchlist
# - Alerts controls: /alerts_on, /alerts_off, /alerts, /alerts_set, /alerts_mute [min], /alerts_unmute
# - Presets: /alerts_set preset fast|normal|normal|calm
# - Auto-ticker (lite) per chat, interval default 15 min, cooldown default 60 min per token+metric
# - Callback: UNWATCH_T:<token>, MUTE_24H, UNMUTE (intercepted before main on_callback)
# - Uses server's send_message(), mdv2_escape(), tg(), build_keyboard(), fetch_market()

import os, json, time, threading, re

_DEFAULT_DB = "./watch_db.json"
_DEFAULT_STATE = "./watch_state.json"
_DEFAULT_LIMIT = 200

# callbacks into server
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

def _ensure_loaded():
    global _db, _state
    with _lock:
        # DB
        try:
            with open(DB_PATH, "r", encoding="utf-8") as f:
                _db = json.load(f) or {}
        except Exception:
            _db = {}
        # STATE
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

def _now():
    return int(time.time())

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
    return s

def _wl(cid):
    return _db.setdefault(str(cid), [])

def _md(text):
    if _escape:
        return _escape(text)
    return text

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
    if _ticker_started:
        return
    t = threading.Thread(target=_ticker_loop, name="watchlite-ticker", daemon=True)
    t.start()
    _ticker_started = True

def _fmt_thresholds(cfg):
    th = cfg.get("thresholds") or {}
    s = cfg
    return (f"d5={th.get('d5', _DEFAULT_THRESHOLDS['d5'])}%  "
            f"d1h={th.get('d1h', _DEFAULT_THRESHOLDS['d1h'])}%  "
            f"d24={th.get('d24', _DEFAULT_THRESHOLDS['d24'])}%  "
            f"vol≈${int(th.get('vol', _DEFAULT_THRESHOLDS['vol'])):,}  "
            f"int={s.get('interval_min', _DEFAULT_INTERVAL_MIN)}m  "
            f"cd={s.get('cooldown_min', _DEFAULT_COOLDOWN_MIN)}m")

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
                try:
                    kv[k] = float(v) * mult
                except Exception:
                    pass
            else:
                try:
                    kv[k] = float(val)
                except Exception:
                    pass
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
    return "\n".join(lines)

def handle_message_commands(chat_id: int, text: str, load_bundle_fn=None, raw_msg=None):
    """Return True if handled fully (intercepted); otherwise False to delegate to original on_message."""
    if not isinstance(text, str):
        return False
    low = text.strip().lower()
    if not low.startswith("/"):
        return False

    _ensure_loaded()
    cfg = _cfg(chat_id)

    def reply(msg):
        if _send_message:
            _send_message(chat_id, msg)

    # WATCH
    if low.startswith("/watch"):
        parts = text.split(None, 1)
        token = None
        if len(parts) > 1:
            token = parts[1].strip()
        if not token:
            token = cfg.get("last_token")
        if not (isinstance(token, str) and token.startswith("0x") and len(token)==42):
            reply("Usage: `/watch 0x...` or scan a token first, then `/watch` (no args).")
            return True
        wl = _wl(chat_id)
        tok = token.lower()
        if tok in wl:
            reply(f"Already watching `{tok}`.")
            return True
        if len(wl) >= LIMIT:
            reply(f"Watchlist is full (limit {LIMIT}). Remove some with `/unwatch 0x...`")
            return True
        wl.append(tok); _save_db()
        reply(f"Watching `{tok}`. Total: {len(wl)}")
        return True

    # UNWATCH
    if low.startswith("/unwatch"):
        parts = text.split(None, 1)
        token = None
        if len(parts) > 1:
            token = parts[1].strip()
        if not token:
            token = cfg.get("last_token")
        if not (isinstance(token, str) and token.startswith("0x") and len(token)==42):
            reply("Usage: `/unwatch 0x...` or scan a token first, then `/unwatch` (no args).")
            return True
        wl = _wl(chat_id)
        tok = token.lower()
        if tok in wl:
            wl.remove(tok); _save_db()
            reply(f"Removed `{tok}` from watchlist. Total: {len(wl)}")
        else:
            reply(f"Not in watchlist: `{tok}`")
        return True

    # WATCHLIST
    if low.startswith("/watchlist"):
        wl = _wl(chat_id)
        if not wl:
            reply("Watchlist is empty. Add with `/watch 0x...`")
            return True
        lines = ["*Watchlist*"]
        for i, t in enumerate(wl, 1):
            lines.append(f"{i}. `{t}`")
        reply("\n".join(lines))
        return True

    # ALERTS TOGGLES
    if low.startswith("/alerts_on"):
        cfg["enabled"] = True; _save_state(); reply("Alerts: ON"); return True
    if low.startswith("/alerts_off"):
        cfg["enabled"] = False; _save_state(); reply("Alerts: OFF"); return True

    if low.startswith("/alerts_set"):
        p = _parse_set_args(text)
        if p.get("reset"):
            cfg["thresholds"] = dict(_DEFAULT_THRESHOLDS)
            cfg["interval_min"] = _DEFAULT_INTERVAL_MIN
            cfg["cooldown_min"] = _DEFAULT_COOLDOWN_MIN
            cfg["preset"] = "normal"
            _save_state()
            reply("Alerts config reset to defaults.")
            return True
        if p.get("preset"):
            name = p["preset"].strip().lower()
            if name in _PRESETS:
                pr = _PRESETS[name]
                cfg["thresholds"] = {k: pr[k] for k in ("d5","d1h","d24","vol")}
                cfg["interval_min"] = pr["int"]
                cfg["cooldown_min"] = pr["cd"]
                cfg["preset"] = name
                _save_state()
                reply(f"Preset applied: *{name}*\n" + _fmt_thresholds(cfg))
                return True
            else:
                reply("Unknown preset. Use: `fast`, `normal`, or `calm`.")
                return True
        kv = p.get("kv") or {}
        if kv:
            th = cfg["thresholds"]
            for k,v in kv.items():
                if k in ("d5","d1h","d24","vol"):
                    th[k] = float(v)
                elif k == "int":
                    cfg["interval_min"] = max(1, int(float(v)))
                elif k == "cd":
                    cfg["cooldown_min"] = max(1, int(float(v)))
            cfg["preset"] = "custom"
            _save_state()
            reply("Alerts updated.\n" + _fmt_thresholds(cfg))
            return True
        reply("Usage: `/alerts_set d5=2 d1h=5 d24=10 vol=250k int=15 cd=60` or `preset fast|normal|calm` or `reset`.")
        return True

    if low.startswith("/alerts_mute"):
        minutes = 1440  # default
        parts = text.split(None,1)
        if len(parts)>1:
            try:
                minutes = max(1, int(float(parts[1].strip())))
            except Exception:
                minutes = 1440
        cfg["mute_until_ts"] = _now() + minutes*60
        _save_state()
        reply(f"Muted alerts for {minutes} minutes.")
        return True

    if low.startswith("/alerts_unmute"):
        cfg["mute_until_ts"] = 0; _save_state(); reply("Unmuted alerts."); return True

    if low.startswith("/alerts"):
        reply(_status_text(chat_id)); return True

    return False

def handle_callback(cb):
    """Intercept own callbacks. Return True if consumed; else False to delegate."""
    data = (cb.get("data") or "")
    msg = cb.get("message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    if not chat_id:
        return False
    _ensure_loaded()
    cfg = _cfg(chat_id)

    if data.startswith("UNWATCH_T:"):
        token = data.split(":",1)[1].strip().lower()
        wl = _wl(chat_id)
        if token in wl:
            wl.remove(token); _save_db()
            if _answer_cb: _answer_cb(cb["id"], "Removed from watchlist.", False)
            if _send_message: _send_message(chat_id, f"Removed `{token}` from watchlist.")
            return True
        return False

    if data == "MUTE_24H":
        cfg["mute_until_ts"] = _now() + 24*3600; _save_state()
        if _answer_cb: _answer_cb(cb["id"], "Muted for 24h.", False)
        if _send_message: _send_message(chat_id, "Muted alerts for 24h.")
        return True

    if data == "UNMUTE":
        cfg["mute_until_ts"] = 0; _save_state()
        if _answer_cb: _answer_cb(cb["id"], "Unmuted.", False)
        if _send_message: _send_message(chat_id, "Unmuted alerts.")
        return True

    return False

def note_quickscan(chat_id: int, bundle: dict, msg_id=None):
    """Record last token from QuickScan result to support /watch with no args."""
    if not isinstance(bundle, dict):
        return
    mkt = (bundle.get("market") or {})
    tok = (mkt.get("tokenAddress") or "").strip()
    if tok and tok.startswith("0x") and len(tok)==42:
        _ensure_loaded()
        cfg = _cfg(chat_id)
        cfg["last_token"] = tok
        _save_state()

def _pct(v):
    try:
        n = float(v)
        arrow = "▲" if n > 0 else ("▼" if n < 0 else "•")
        return f"{arrow} {n:+.2f}%"
    except Exception:
        return "—"

def _build_alert_keyboard(links, token, ctx="alert"):
    # Buttons: Open in DEX, Open in Scan, Unwatch, Mute 24h/Unmute
    rows = []
    if isinstance(links, dict):
        if links.get("dex"):
            rows.append([{"text":"🟢 Open in DEX", "url": links["dex"]}])
        if links.get("scan"):
            rows.append([{"text":"🔍 Open in Scan", "url": links["scan"]}])
    rows.append([{"text":"👁️ Unwatch", "callback_data": f"UNWATCH_T:{token}"}])
    rows.append([{"text":"🔕 Mute 24h", "callback_data":"MUTE_24H"}, {"text":"🔔 Unmute", "callback_data":"UNMUTE"}])
    return {"inline_keyboard": rows}

def _maybe_alert_for_token(cid, tok, cfg):
    # guard: muted
    now = _now()
    if (cfg.get("mute_until_ts") or 0) > now:
        return

    # fetch market
    try:
        mkt = _fetch_market(tok) if _fetch_market else None
    except Exception:
        mkt = None
    if not (isinstance(mkt, dict) and mkt.get("ok")):
        return

    ch = mkt.get("priceChanges") or {}
    vol = mkt.get("vol24h") or 0
    th = cfg.get("thresholds") or _DEFAULT_THRESHOLDS
    triggered = []  # list of (metric,label,val,thr)
    def _add(metric, label, val, thr):
        try:
            if abs(float(val)) >= float(thr):
                triggered.append((metric,label,val,thr))
        except Exception:
            pass

    if "m5" in ch: _add("d5",  "Δ5m", ch.get("m5"),  th.get("d5", _DEFAULT_THRESHOLDS["d5"]))
    if "h1" in ch: _add("d1h", "Δ1h", ch.get("h1"),  th.get("d1h", _DEFAULT_THRESHOLDS["d1h"]))
    if "h24" in ch: _add("d24","Δ24h", ch.get("h24"), th.get("d24", _DEFAULT_THRESHOLDS["d24"]))
    try:
        v_ok = float(vol) >= float(th.get("vol", _DEFAULT_THRESHOLDS["vol"]))
    except Exception:
        v_ok = False
    if v_ok:
        triggered.append(("vol","Vol24h", vol, th.get("vol", _DEFAULT_THRESHOLDS["vol"])))

    if not triggered:
        return

    # cooldown per metric+token
    cd = int(cfg.get("cooldown_min", _DEFAULT_COOLDOWN_MIN))*60
    la = cfg.setdefault("last_alerts", {})
    any_send = False
    send_lines = []
    for metric, label, val, thr in triggered:
        key = f"{tok}:{metric}"
        last = int(la.get(key) or 0)
        if now - last < cd:
            continue
        la[key] = now
        send_lines.append(f"*{label}*: {_pct(val)} (≥ {thr})")
        any_send = True

    if not any_send:
        return

    # Compose alert text
    chain = mkt.get("chain") or "—"
    psym = mkt.get("pairSymbol") or "Token"
    header = f"*Alert — {psym}*  `[{chain}]`"
    text = header + "\n" + "\n".join(send_lines)

    # Keyboard
    links = mkt.get("links") or {}
    kb = _build_alert_keyboard(links, tok, ctx="alert")

    if _send_message:
        _send_message(cid, text, reply_markup=kb)
        _save_state()

def _ticker_loop():
    while True:
        try:
            time.sleep(30)  # coarse tick
            _ensure_loaded()
            now = _now()
            # Iterate chats
            for cid, cfg in list(_state.items()):
                try:
                    cid_int = int(cid)
                except Exception:
                    continue
                if not cfg.get("enabled", True):
                    continue
                interval = max(1, int(cfg.get("interval_min", _DEFAULT_INTERVAL_MIN)))*60
                last = int(cfg.get("last_tick_ts") or 0)
                if now - last < interval:
                    continue
                # mark tick
                cfg["last_tick_ts"] = now
                _save_state()

                # go over tokens
                wl = _db.get(str(cid), []) or []
                if not wl:
                    continue
                for tok in list(wl):
                    _maybe_alert_for_token(cid_int, tok, cfg)
        except Exception:
            # keep thread alive
            time.sleep(1)
