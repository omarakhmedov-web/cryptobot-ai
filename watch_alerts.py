
# watch_alerts.py — non-invasive Watchlist & Alerts extension for Metridex bot
# Safe to import even if server lacks optional pieces.
import os, json, time, re, threading, traceback
from typing import Any, Dict

INSTALLED = False
_G = {}
_LOCK = threading.RLock()
_TICKER_THREAD = None
_STOP = False

# Defaults
WATCH_DB_PATH = os.getenv("WATCH_DB_PATH", "./watch_db.json")
WATCH_STATE_PATH = os.getenv("WATCH_STATE_PATH", "./watch_state.json")
WATCHLIST_LIMIT = int(os.getenv("WATCHLIST_LIMIT", "200"))

DEFAULTS = {
    "enabled": True,
    "preset": "normal",
    "thresholds": {"d5": 2.0, "d1h": 5.0, "d24": 10.0, "vol": 250_000},
    "interval": 15,   # minutes
    "cooldown": 60,   # minutes
    "muted_until": 0,
    "last_scanned_at": 0,
    "last_token": None,
    "cooldowns": {}   # {token: {metric: ts}}
}

PRESETS = {
    "fast":   {"d5": 1.0, "d1h": 3.0, "d24": 8.0,  "vol": 100_000, "interval": 10, "cooldown": 30},
    "normal": {"d5": 2.0, "d1h": 5.0, "d24": 10.0, "vol": 250_000, "interval": 15, "cooldown": 60},
    "calm":   {"d5": 3.0, "d1h": 7.0, "d24": 15.0, "vol": 500_000, "interval": 20, "cooldown": 90},
}

def _ensure_file(path: str, default):
    try:
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(default, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def _read_json(path: str, default):
    _ensure_file(path, default)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default.copy() if isinstance(default, dict) else list(default)

def _write_json(path: str, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def _now() -> int:
    return int(time.time())

def _abs_pct(x) -> float:
    try:
        return abs(float(x))
    except Exception:
        return 0.0

def _parse_amount(text: str) -> int:
    if text is None:
        return 0
    s = str(text).strip().lower()
    mul = 1
    if s.endswith("k"):
        mul = 1_000; s = s[:-1]
    elif s.endswith("m"):
        mul = 1_000_000; s = s[:-1]
    try:
        return int(float(s) * mul)
    except Exception:
        return 0

def _scan_to_token(bundle: dict) -> str | None:
    """Derive token address from bundle['market'] or links as fallback."""
    if not isinstance(bundle, dict):
        return None
    mkt = (bundle.get("market") or {})
    for k in ("tokenAddress","address","token","token0Address","baseTokenAddress","token1Address","baseToken"):
        v = mkt.get(k)
        if isinstance(v, str) and v.startswith("0x") and len(v) == 42:
            return v
        if isinstance(v, dict):
            a = (v.get("address") or "").strip()
            if a.startswith("0x") and len(a) == 42:
                return a
    links = (bundle.get("links") or {})
    if isinstance(links, dict):
        val = f"{links.get('scan') or ''} {links.get('dex') or ''}"
        m = re.search(r"(?:token|address|inputCurrency|outputCurrency)=?0x([0-9a-fA-F]{40})", val)
        if m:
            return "0x" + m.group(1)
    return None

def _get_state() -> dict:
    with _LOCK:
        return _read_json(WATCH_STATE_PATH, {})

def _save_state(st: dict):
    with _LOCK:
        _write_json(WATCH_STATE_PATH, st)

def _get_db() -> dict:
    with _LOCK:
        db = _read_json(WATCH_DB_PATH, {"chats": {}, "updated_at": 0})
        if "chats" not in db: db["chats"] = {}
        return db

def _save_db(db: dict):
    with _LOCK:
        db["updated_at"] = _now()
        _write_json(WATCH_DB_PATH, db)

def _state_for(chat_id: int) -> dict:
    st = _get_state()
    s = st.get(str(chat_id)) or {}
    # hydrate defaults (non-destructive)
    cur = {}
    for k, v in DEFAULTS.items():
        cur[k] = s.get(k, v if not isinstance(v, dict) else v.copy())
    st[str(chat_id)] = cur
    _save_state(st)
    return cur

def _chat_enabled(chat_id: int) -> bool:
    return bool(_state_for(chat_id).get("enabled", True))

def _set_chat_enabled(chat_id: int, flag: bool):
    st = _get_state()
    cur = st.get(str(chat_id)) or {}
    cur["enabled"] = bool(flag)
    st[str(chat_id)] = cur
    _save_state(st)

def _set_last_token(chat_id: int, token: str | None):
    st = _get_state()
    cur = st.get(str(chat_id)) or {}
    cur["last_token"] = token
    st[str(chat_id)] = cur
    _save_state(st)

def _get_last_token(chat_id: int) -> str | None:
    return _state_for(chat_id).get("last_token")

def _set_muted(chat_id: int, minutes: int):
    st = _get_state()
    cur = st.get(str(chat_id)) or {}
    cur["muted_until"] = _now() + int(minutes) * 60
    st[str(chat_id)] = cur
    _save_state(st)

def _clear_mute(chat_id: int):
    st = _get_state()
    cur = st.get(str(chat_id)) or {}
    cur["muted_until"] = 0
    st[str(chat_id)] = cur
    _save_state(st)

def _muted_until(chat_id: int) -> int:
    return int(_state_for(chat_id).get("muted_until") or 0)

def _fmt_hms(minutes: int) -> str:
    h = minutes // 60
    m = minutes % 60
    if h and m: return f"{h}h {m}m"
    if h: return f"{h}h"
    return f"{m}m"

def _apply_preset(s: dict, name: str):
    p = PRESETS.get(name)
    if not p: return
    th = s.get("thresholds", {}).copy()
    for k in ("d5","d1h","d24","vol"):
        if k in p: th[k] = p[k]
    s["thresholds"] = th
    s["interval"] = p.get("interval", s.get("interval", DEFAULTS["interval"]))
    s["cooldown"] = p.get("cooldown", s.get("cooldown", DEFAULTS["cooldown"]))
    s["preset"] = name

def _update_thresholds(s: dict, args: dict):
    th = s.get("thresholds", {}).copy()
    if "d5" in args:  th["d5"]  = float(args["d5"])
    if "d1h" in args: th["d1h"] = float(args["d1h"])
    if "d24" in args: th["d24"] = float(args["d24"])
    if "vol" in args: th["vol"] = _parse_amount(args["vol"])
    s["thresholds"] = th
    if "int" in args: s["interval"] = max(3, int(args["int"]))  # min 3m
    if "cd"  in args: s["cooldown"] = max(10, int(args["cd"]))  # min 10m

def _dex_fallback(chain: str, token: str) -> str | None:
    d = {"eth":"https://app.uniswap.org/swap?inputCurrency={t}",
         "bsc":"https://pancakeswap.finance/swap?outputCurrency={t}",
         "polygon":"https://app.uniswap.org/swap?inputCurrency={t}"}
    return d.get(chain, "").format(t=token) if token else None

def _scan_fallback(chain: str, token: str) -> str | None:
    s = {"eth":"https://etherscan.io/token/{t}",
         "bsc":"https://bscscan.com/token/{t}",
         "polygon":"https://polygonscan.com/token/{t}"}
    return s.get(chain, "").format(t=token) if token else None

def _pick_links(market: dict, links: dict, chain: str, token: str):
    dex = (links or {}).get("dex") or _dex_fallback(chain, token)
    scan = (links or {}).get("scan") or _scan_fallback(chain, token)
    return dex, scan

def _md(text: str) -> str:
    # Let server.send_message do MarkdownV2 escaping; we pass plain => server escapes
    return str(text)

def _reply(chat_id: int, text: str, reply_markup=None):
    try:
        _G["send_message"](chat_id, _md(text), reply_markup=reply_markup)
    except Exception as e:
        print("[watch_alerts] send fail:", e)

def _inline_keyboard(rows: list[list[dict]]) -> dict:
    return {"inline_keyboard": rows}

def _watch_add(chat_id: int, token: str) -> str:
    db = _get_db()
    lst = list(db["chats"].get(str(chat_id), {}).get("tokens", []))
    if token in lst:
        return "Already watching."
    if len(lst) >= WATCHLIST_LIMIT:
        return f"Watchlist is full ({WATCHLIST_LIMIT})."
    lst.append(token)
    db["chats"][str(chat_id)] = {"tokens": lst}
    _save_db(db)
    return "Added to watchlist."

def _watch_remove(chat_id: int, token: str) -> str:
    db = _get_db()
    lst = list(db["chats"].get(str(chat_id), {}).get("tokens", []))
    if token not in lst:
        return "Token not in watchlist."
    lst = [t for t in lst if t != token]
    db["chats"][str(chat_id)] = {"tokens": lst}
    _save_db(db)
    return "Removed from watchlist."

def _handle_watch_commands(chat_id: int, text: str) -> bool:
    low = text.lower().strip()
    # /watchlist
    if low.startswith("/watchlist"):
        db = _get_db()
        lst = db["chats"].get(str(chat_id), {}).get("tokens", [])
        if not lst:
            _reply(chat_id, "*Watchlist*\n— empty —")
            return True
        lines = [f"{i+1}. `{t}`" for i, t in enumerate(lst)]
        _reply(chat_id, "*Watchlist*\n" + "\n".join(lines))
        return True

    def _normalize_token(arg: str | None) -> str | None:
        if arg and arg.startswith("0x") and len(arg) == 42:
            return arg
        return None

    # /watch [0x..]
    m = re.match(r"^/watch(?:\s+(\S+))?$", low)
    if m:
        tok = _normalize_token(m.group(1))
        if not tok:
            tok = _get_last_token(chat_id)
        if not tok:
            _reply(chat_id, "No token to watch. Send a scan first or pass a token address.")
            return True
        msg = _watch_add(chat_id, tok)
        _reply(chat_id, f"*Watch*\n{msg}\n`{tok}`")
        return True

    # /unwatch [0x..]
    m = re.match(r"^/unwatch(?:\s+(\S+))?$", low)
    if m:
        tok = _normalize_token(m.group(1))
        if not tok:
            tok = _get_last_token(chat_id)
        if not tok:
            _reply(chat_id, "No token to unwatch. Send a scan first or pass a token address.")
            return True
        msg = _watch_remove(chat_id, tok)
        _reply(chat_id, f"*Unwatch*\n{msg}\n`{tok}`")
        return True

    # Alerts toggles/status
    if low.startswith("/alerts_on"):
        _set_chat_enabled(chat_id, True)
        _reply(chat_id, "*Alerts*: enabled")
        return True
    if low.startswith("/alerts_off"):
        _set_chat_enabled(chat_id, False)
        _reply(chat_id, "*Alerts*: disabled")
        return True
    if low.startswith("/alerts_mute"):
        m = re.match(r"^/alerts_mute(?:\s+(\d+))?$", low)
        minutes = int(m.group(1)) if m and m.group(1) else 24*60
        _set_muted(chat_id, minutes)
        _reply(chat_id, f"*Alerts*: muted for {_fmt_hms(minutes)}")
        return True
    if low.startswith("/alerts_unmute"):
        _clear_mute(chat_id)
        _reply(chat_id, "*Alerts*: unmuted")
        return True

    if low.startswith("/alerts_set"):
        args = {}
        if " reset" in low or low.strip() == "/alerts_set reset":
            st = _get_state()
            st[str(chat_id)] = DEFAULTS.copy()
            _save_state(st)
            _reply(chat_id, "*Alerts*: defaults restored")
            return True

        # preset
        m = re.search(r"preset\s+(fast|normal|calm)", low)
        if m:
            s = _state_for(chat_id)
            _apply_preset(s, m.group(1))
            st = _get_state(); st[str(chat_id)] = s; _save_state(st)
        # key=val tokens
        for key in ("d5","d1h","d24","vol","int","cd"):
            m = re.search(rf"{key}\s*=\s*([a-zA-Z0-9\.\-]+)", low)
            if m:
                args[key] = m.group(1)
        if args:
            s = _state_for(chat_id)
            _update_thresholds(s, args)
            st = _get_state(); st[str(chat_id)] = s; _save_state(st)
        _reply(chat_id, "*Alerts*: settings updated")
        return True

    if low.startswith("/alerts"):
        s = _state_for(chat_id)
        th = s["thresholds"]
        tm = _muted_until(chat_id)
        muted = (tm > _now())
        mu_txt = f"yes (until <code>{time.strftime('%Y-%m-%d %H:%M', time.gmtime(tm))} UTC</code>)" if muted else "no"
        txt = (
            "*Alerts status*\n"
            f"enabled: {'yes' if s['enabled'] else 'no'} (preset: {s['preset']})\n"
            f"thresholds: Δ5m {th['d5']}% • Δ1h {th['d1h']}% • Δ24h {th['d24']}% • Vol24h ${th['vol']:,}\n"
            f"interval: {s['interval']}m • cooldown: {s['cooldown']}m • muted: {mu_txt}"
        )
        _reply(chat_id, txt)
        return True

    return False

def _handle_callbacks(cb: dict) -> bool:
    cb_id = cb.get("id")
    data = (cb.get("data") or "").strip()
    msg = cb.get("message") or {}
    chat_id = msg.get("chat", {}).get("id")

    if data.startswith("UNWATCH_T:"):
        token = data.split(":",1)[1].strip()
        msg = _watch_remove(chat_id, token)
        try:
            _G["answer_callback_query"](cb_id, msg, False)
        except Exception:
            pass
        _reply(chat_id, f"*Unwatch*\n{msg}\n`{token}`")
        return True

    if data == "ALERTS_MUTE_24H":
        _set_muted(chat_id, 24*60)
        try:
            _G["answer_callback_query"](cb_id, "Muted for 24h", False)
        except Exception:
            pass
        _reply(chat_id, "*Alerts*: muted for 24h")
        return True

    if data == "ALERTS_UNMUTE":
        _clear_mute(chat_id)
        try:
            _G["answer_callback_query"](cb_id, "Unmuted", False)
        except Exception:
            pass
        _reply(chat_id, "*Alerts*: unmuted")
        return True

    # Known external WATCH/UNWATCH keyboard actions (existing in bot)
    if data == "WATCH" or data == "UNWATCH":
        # let original handler process it
        return False

    return False

def _wrap_on_message(orig):
    def wrapper(msg: dict):
        try:
            chat_id = msg["chat"]["id"]
            text = (msg.get("text") or "").strip()
        except Exception:
            return orig(msg)
        # intercept only our commands; else delegate
        if text.startswith("/") and any(text.lower().startswith(p) for p in ("/watch","/unwatch","/watchlist","/alerts","/alerts_on","/alerts_off","/alerts_set","/alerts_mute","/alerts_unmute")):
            if _handle_watch_commands(chat_id, text):
                return _G["jsonify"]({"ok": True})
        return orig(msg)
    return wrapper

def _wrap_on_callback(orig):
    def wrapper(cb: dict):
        try:
            if _handle_callbacks(cb):
                return _G["jsonify"]({"ok": True})
        except Exception as e:
            print("[watch_alerts] callback error", e, traceback.format_exc())
        return orig(cb)
    return wrapper

def _wrap_store_bundle(orig):
    def wrapper(chat_id: int, msg_id: int, bundle: dict):
        try:
            tok = _scan_to_token(bundle)
            if tok:
                _set_last_token(chat_id, tok)
        except Exception:
            pass
        return orig(chat_id, msg_id, bundle)
    return wrapper

def install_hooks(g: Dict[str, Any]):
    global INSTALLED, _G
    if INSTALLED:
        return True
    required = ["send_message","jsonify","answer_callback_query"]
    for name in required:
        if name not in g:
            raise RuntimeError(f"server missing: {name}")
    _G = g
    # Wrap handlers
    if "on_message" in g and callable(g["on_message"]):
        g["on_message"] = _wrap_on_message(g["on_message"])
    if "on_callback" in g and callable(g["on_callback"]):
        g["on_callback"] = _wrap_on_callback(g["on_callback"])
    if "store_bundle" in g and callable(g["store_bundle"]):
        g["store_bundle"] = _wrap_store_bundle(g["store_bundle"])
    INSTALLED = True
    return True

def _should_fire(s: dict, token: str, market: dict) -> tuple[bool, str, dict]:
    """Return (fire, reason, metrics_used)"""
    th = s["thresholds"]
    ch = (market.get("priceChanges") or {})
    vol = int((market.get("vol24h") or market.get("volume24h") or 0) or 0)
    d5 = _abs_pct(ch.get("m5"))
    d1 = _abs_pct(ch.get("h1"))
    d24 = _abs_pct(ch.get("h24") or ch.get("d1") or ch.get("24h") or ch.get("day"))
    triggered = {}
    if d5 >= th["d5"]: triggered["d5"] = d5
    if d1 >= th["d1h"]: triggered["d1h"] = d1
    if d24 >= th["d24"]: triggered["d24"] = d24
    if vol >= th["vol"]: triggered["vol"] = vol
    if not triggered: return (False, "", {})
    return (True, " • ".join([
        *(f"Δ5m {d5:.2f}%" for _ in [1] if "d5" in triggered),
        *(f"Δ1h {d1:.2f}%" for _ in [1] if "d1h" in triggered),
        *(f"Δ24h {d24:.2f}%" for _ in [1] if "d24" in triggered),
        *(f"Vol24h ${vol:,}" for _ in [1] if "vol" in triggered),
    ]), {"d5": d5, "d1h": d1, "d24": d24, "vol": vol})

def _cool_ok(s: dict, token: str, metric: str) -> bool:
    cd = s.get("cooldowns") or {}
    t = (cd.get(token) or {}).get(metric) or 0
    return _now() > (int(t) + s["cooldown"]*60)

def _cool_touch(s: dict, token: str, metric: str):
    cd = s.get("cooldowns") or {}
    row = cd.get(token) or {}
    row[metric] = _now()
    cd[token] = row
    s["cooldowns"] = cd

def _normalize_chain(chain: str | int | None) -> str:
    if chain is None: return ""
    c = str(chain).strip().lower()
    if c.isdigit(): c = {"1":"eth","56":"bsc","137":"polygon"}.get(c, c)
    return {"matic":"polygon","pol":"polygon","poly":"polygon"}.get(c, c)

def _send_alert(chat_id: int, s: dict, token: str, market: dict, links: dict):
    chain = _normalize_chain(market.get("chain"))
    dex, scan = _pick_links(market, links, chain, token)
    _, reason, metrics = _should_fire(s, token, market)
    if not reason:
        return False
    # Respect per-metric cooldowns
    fired_any = False
    for metric in ("d5","d1h","d24","vol"):
        if metric == "vol" and metrics.get("vol", 0) == 0: 
            continue
        if metric in ("d5","d1h","d24") and metrics.get(metric, 0) == 0:
            continue
        if not _cool_ok(s, token, metric):
            continue
        _cool_touch(s, token, metric)
        fired_any = True
    if not fired_any:
        return False

    name = (market.get("token") or market.get("symbol") or market.get("pair") or "Token")
    ch = market.get("priceChanges") or {}
    def _pct(v):
        try:
            n=float(v); return f"{'▲' if n>0 else ('▼' if n<0 else '•')} {n:+.2f}%"
        except Exception: return "—"

    txt = (
        f"*Alert — {name}*\n"
        f"`{market.get('chain','')}`  •  Δ5m {_pct(ch.get('m5'))}  •  Δ1h {_pct(ch.get('h1'))}  •  Δ24h {_pct(ch.get('h24') or ch.get('d1'))}\n"
        f"Vol 24h: ${int(market.get('vol24h') or market.get('volume24h') or 0):,}\n"
        f"Reason: {reason}"
    )
    kb = _inline_keyboard([
        *([[{"text":"🟢 Open in DEX", "url": dex}]] if dex else []),
        *([[{"text":"🔍 Open in Scan", "url": scan}]] if scan else []),
        [{"text":"👁️ Unwatch", "callback_data": f"UNWATCH_T:{token}"}],
        ([{"text":"🔕 Mute 24h", "callback_data":"ALERTS_MUTE_24H"}] if _now() <= _muted_until(chat_id) else [{"text":"🔔 Unmute", "callback_data":"ALERTS_UNMUTE"}],)
    ])
    _reply(chat_id, txt, reply_markup=kb)
    return True

def _tick_once():
    if not INSTALLED: 
        return
    db = _get_db()
    chats = list((db.get("chats") or {}).keys())
    for chat_id_str in chats:
        try:
            chat_id = int(chat_id_str)
            s = _state_for(chat_id)
            if not s.get("enabled", True): 
                continue
            if _now() < s.get("muted_until", 0):
                continue
            # Respect per-chat interval
            if _now() - int(s.get("last_scanned_at", 0)) < s.get("interval", 15) * 60:
                continue
            tokens = list((db["chats"].get(chat_id_str) or {}).get("tokens", []))
            if not tokens:
                continue
            for tok in tokens:
                try:
                    # fetch_market returns {'ok': True, 'market': {...}, 'links': {...}}
                    res = _G["fetch_market"](tok)
                    if not (isinstance(res, dict) and res.get("ok")):
                        continue
                    market = res.get("market") or {}
                    links = res.get("links") or {}
                    _send_alert(chat_id, s, tok, market, links)
                except Exception as e:
                    print("[watch_alerts] fetch/send alert error:", e)
            # mark tick
            st = _get_state()
            row = st.get(chat_id_str) or {}
            row["last_scanned_at"] = _now()
            st[chat_id_str] = row
            _save_state(st)
        except Exception as e:
            print("[watch_alerts] tick error:", e)

def _ticker_loop():
    try:
        while not _STOP:
            time.sleep(60)  # base tick
            _tick_once()
    except Exception as e:
        print("[watch_alerts] ticker died:", e, traceback.format_exc())

def start_ticker():
    global _TICKER_THREAD
    if _TICKER_THREAD and _TICKER_THREAD.is_alive():
        return False
    t = threading.Thread(target=_ticker_loop, name="watch_alerts_ticker", daemon=True)
    t.start()
    _TICKER_THREAD = t
    return True
