import secrets
# -*- coding: utf-8 -*-

# === Standard library imports ===
import os
import re
import ssl
import json
import time
import socket
import sqlite3
import tempfile
import hashlib
import threading
from datetime import datetime, timedelta
from urllib.parse import urlparse

# === Helpers ===
def _get_share_ttl_hours() -> int:
    """TTL (hours) for Share-links from env, default 72."""
    try:
        return int(os.getenv("SHARE_TTL_HOURS", "72") or "72")
    except Exception:
        return 72


from flask import Flask, request, jsonify, Response, redirect

# Project-local utilities (must exist in your project)
from quickscan import quickscan_entrypoint, quickscan_pair_entrypoint, SafeCache
from utils import locale_text
from tg_safe import tg_send_message, tg_answer_callback
from metri_domain_rdap import _rdap as __rdap_impl  # injected
from flask import Flask
import sqlite3
import hmac
from datetime import datetime, timedelta
try:
    from polydebug_rpc import init_polydebug
    init_polydebug()  # запустится только при POLY_DEBUG=1
except Exception as e:
    print(f"[POLYDEBUG] init skipped: {e}")

# ========================
# Environment & constants
# ========================
APP_VERSION = os.environ.get("APP_VERSION", "0.3.102-sharefix")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "MetridexBot")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
WEBHOOK_HEADER_SECRET = os.environ.get("WEBHOOK_HEADER_SECRET", "")
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID")  # numeric string
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")
ALLOWED_CHAT_IDS = set([cid.strip() for cid in os.environ.get("ALLOWED_CHAT_IDS", "").split(",") if cid.strip()])

CACHE_TTL_SECONDS = int(os.environ.get("CACHE_TTL_SECONDS", "600"))
HTTP_TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "6.0"))
KNOWN_AUTORELOAD_SEC = int(os.environ.get("KNOWN_AUTORELOAD_SEC", "300"))
SCANNER_URL = os.environ.get("SCANNER_URL", "").strip()
ETH_RPC_URLS = os.environ.get("ETH_RPC_URLS", "").strip()

# Domain meta TTLs
try:
    DOMAIN_META_TTL = int(os.getenv("DOMAIN_META_TTL", "2592000"))      # 30 days
    DOMAIN_META_TTL_NEG = int(os.getenv("DOMAIN_META_TTL_NEG", "120"))  # 2 min for negative WB
except Exception:
    DOMAIN_META_TTL = 2592000
    DOMAIN_META_TTL_NEG = 120

LOC = locale_text
app = Flask(__name__)





# ===== Entitlements (SQLite) =====
DB_PATH = os.getenv("DB_PATH", "/tmp/metridex.db")

def _db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("""CREATE TABLE IF NOT EXISTS entitlements(
        chat_id TEXT NOT NULL,
        product TEXT NOT NULL,
        expires_at INTEGER,
        credits INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL
    )""")
    conn.commit()
    return conn
# ===== Watchlist (SQLite) =====
def _db_watch():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("""CREATE TABLE IF NOT EXISTS watchlist(
        chat_id TEXT NOT NULL,
        chain   TEXT,
        ca      TEXT NOT NULL,
        type    TEXT NOT NULL,
        threshold REAL,
        created_at INTEGER NOT NULL,
        active  INTEGER DEFAULT 1
    )""")
    conn.commit()
    return conn

def watch_add(chat_id: str, ca: str, wtype: str, threshold: float|None=None, chain: str|None=None):
    ca=(ca or "").lower(); wtype=(wtype or "price").lower(); now_ts=int(time.time())
    conn=_db_watch(); _ensure_watch_index(conn)
    try:
        conn.execute("UPDATE watchlist SET threshold=?, active=1 WHERE chat_id=? AND ca=? AND type=? AND IFNULL(chain,'')=IFNULL(?, '')",
                     (threshold, str(chat_id), ca, wtype, (chain or "")))
        if conn.total_changes==0:
            conn.execute("INSERT INTO watchlist(chat_id, chain, ca, type, threshold, created_at, active) VALUES (?,?,?,?,?,?,1)",
                         (str(chat_id), (chain or ""), ca, wtype, threshold, now_ts))
    except Exception:
        try:
            conn.execute("INSERT OR REPLACE INTO watchlist(chat_id, chain, ca, type, threshold, created_at, active) VALUES (?,?,?,?,?,?,1)",
                         (str(chat_id), (chain or ""), ca, wtype, threshold, now_ts))
        except Exception:
            pass
    conn.commit()

def watch_remove(chat_id: str, ca: str|None=None):
    conn = _db_watch()
    if ca:
        conn.execute("UPDATE watchlist SET active=0 WHERE chat_id=? AND ca=? AND active=1", (str(chat_id), (ca or "").lower()))
    else:
        conn.execute("UPDATE watchlist SET active=0 WHERE chat_id=? AND active=1", (str(chat_id),))
    conn.commit()

def watch_list(chat_id: str):
    conn = _db_watch()
    cur = conn.execute("SELECT chain, ca, type, IFNULL(threshold,''), active, created_at FROM watchlist WHERE chat_id=? ORDER BY created_at DESC", (str(chat_id),))
    return cur.fetchall()

def _ds_price_change_1h(ca_l: str) -> float|None:
    try:
        changes = _ds_token_changes(ca_l) or {}
        v = changes.get("h1")
        if not v: return None
        return float(str(v).replace("%","").replace("+",""))
    except Exception:
        return None

def _ds_pair_for(ca_l: str):
    try:
        p, chain = _ds_resolve_pair_and_chain(ca_l)
        pair_addr = None
        if isinstance(p, dict):
            pair_addr = p.get("pairAddress") or p.get("pair")
        return pair_addr, chain
    except Exception:
        return None, None

def _trigger_check(rec):
    chain, ca, wtype, thr, active, created = rec
    if not active: return None
    ca_l = (ca or "").lower()
    if wtype == "price":
        pct = _ds_price_change_1h(ca_l)
        if pct is None: return None
        thr = float(thr or 5.0)
        if abs(pct) >= thr:
            sign = "↑" if pct > 0 else "↓"
            return f"📈 PriceΔ 1h {sign}{abs(pct):.2f}% — {ca_l}"
    elif wtype in ("lp_top","new_lock"):
        pair, ch = _ds_pair_for(ca_l)
        if not pair or not ch: return None
        st = _infer_lp_status(pair, ch) or {}
        th = (st.get("top_holder") or "").lower()
        dead = float(st.get("dead_pct") or 0.0)
        uncx = float(st.get("uncx_pct") or 0.0)
        tf   = float(st.get("team_finance_pct") or 0.0)
        if wtype == "lp_top":
            if th and th not in (KNOWN_CUSTODIANS.get(ch, {}) or {}) and (float(st.get("top_holder_pct") or 0.0) >= 50.0):
                return f"🔔 LP top-holder ≥50% EOA — {th}\nPair: {pair} on {ch}\nToken: {ca_l}"
        else:
            if (uncx + tf) >= 10.0:
                return f"🔒 New/raised LP lock detected (UNCX+TF≈{uncx+tf:.1f}%) — {ca_l}\nPair: {pair} on {ch}"
    return None

_WATCH_LOOP_EVERY = int(os.getenv("WATCH_LOOP_EVERY","360"))
_watch_thread_started = False

def _watch_loop():
    while True:
        try:
            conn = _db_watch()
            rows = conn.execute("SELECT chain, ca, type, threshold, active, created_at, chat_id FROM watchlist WHERE active=1").fetchall()
            for chain, ca, wtype, thr, active, created, chat_id in rows:
                msg = _trigger_check((chain, ca, wtype, thr, active, created))
                if msg:
                    try: _send_text(chat_id, msg, logger=app.logger)
                    except Exception: pass
            time.sleep(_WATCH_LOOP_EVERY)
        except Exception:
            try: time.sleep(_WATCH_LOOP_EVERY)
            except Exception: pass

def _ensure_watch_loop():
    global _watch_thread_started
    if _watch_thread_started: return
    t = threading.Thread(target=_watch_loop, daemon=True)
    t.start()
    _watch_thread_started = True


def grant_entitlement(chat_id: str, product: str, now_ts: int | None = None):
    now_ts = now_ts or int(datetime.utcnow().timestamp())
    conn = _db()
    if product in ("pro", "teams"):
        exp = now_ts + 30*24*3600
        conn.execute("INSERT INTO entitlements(chat_id, product, expires_at, credits, created_at) VALUES (?,?,?,?,?)",
                     (str(chat_id), product, exp, 0, now_ts))
    elif product == "daypass":
        exp = now_ts + 24*3600
        conn.execute("INSERT INTO entitlements(chat_id, product, expires_at, credits, created_at) VALUES (?,?,?,?,?)",
                     (str(chat_id), product, exp, 0, now_ts))
    elif product == "deep":
        conn.execute("INSERT INTO entitlements(chat_id, product, expires_at, credits, created_at) VALUES (?,?,?,?,?)",
                     (str(chat_id), product, None, 1, now_ts))
    conn.commit()

def get_entitlements(chat_id: str):
    conn = _db()
    cur = conn.execute("SELECT product, expires_at, credits FROM entitlements WHERE chat_id=? ORDER BY created_at DESC", (str(chat_id),))
    rows = cur.fetchall()
    out = []
    now_ts = int(datetime.utcnow().timestamp())
    for p, exp, cr in rows:
        if p in ("pro","daypass","teams"):
            if exp is None or exp > now_ts:
                out.append((p, exp, cr))
        else:
            out.append((p, exp, cr))
    return out

def has_active(chat_id: str, product: str) -> bool:
    now_ts = int(datetime.utcnow().timestamp())
    for p, exp, _ in get_entitlements(chat_id):
        if p == product and (exp is None or exp > now_ts):
            return True
    return False

def pop_deep_credit(chat_id: str) -> bool:
    conn = _db()
    cur = conn.execute("""SELECT rowid, credits FROM entitlements
                          WHERE chat_id=? AND product='deep' AND credits>0
                          ORDER BY created_at ASC LIMIT 1""", (str(chat_id),))
    row = _share_db().execute("SELECT token, chat_id, ca, ttl_hours, created_ts, revoked_ts FROM shared_links WHERE token=?", (token,)).fetchone()
