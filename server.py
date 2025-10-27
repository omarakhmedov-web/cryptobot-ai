# -*- coding: utf-8 -*-
"""
Drop-in replacement for server.py:on_callback to fix silent WATCHLIST button.
Usage: replace your existing `def on_callback(cb):` in server.py with the function below.
No new ENV. Other actions unchanged.
Build: 2025-10-27 (Asia/Baku)
"""
import json, os, re

def on_callback(cb):
    # --- Common context ---
    chat_id = (cb.get("message") or {}).get("chat", {}).get("id") or (cb.get("from") or {}).get("id")
    cb_id   = cb.get("id")
    data    = (cb.get("data") or "")
    current_msg_id = (cb.get("message") or {}).get("message_id")

    # Parse callback data
    m = parse_cb(data)
    if not m:
        answer_callback_query(cb_id, "Unsupported action", True)
        return jsonify({"ok": True})
    action, orig_msg_id, orig_chat_id = m

    if orig_msg_id == 0:
        orig_msg_id = current_msg_id
    if chat_id != orig_chat_id and orig_chat_id != 0:
        answer_callback_query(cb_id, "This control expired.", True)
        return jsonify({"ok": True})

    # --- Lightweight handler: WATCHLIST (fix) ---
    if action == "WATCHLIST":
        # Read watch DB (JSON). Supported shapes:
        # 1) { "<chat_id>": ["0x..", ...] }
        # 2) { "<chat_id>": {"tokens": ["0x..", ...]} }
        # 3) ["0x..", ...]
        db_path = os.environ.get("WATCH_DB_PATH", "./watch_db.json")
        items = []
        try:
            with open(db_path, "r", encoding="utf-8") as f:
                dataj = json.load(f)
            if isinstance(dataj, dict):
                raw = dataj.get(str(chat_id)) or dataj.get(int(chat_id)) or dataj.get("tokens") or []
                if isinstance(raw, dict) and "tokens" in raw:
                    items = list(raw.get("tokens") or [])
                elif isinstance(raw, list):
                    items = list(raw)
            elif isinstance(dataj, list):
                items = list(dataj)
        except Exception:
            items = []

        def _esc_md(s):
            s = str(s)
            for ch in r"_*[]()~`>#+-=|{}.!":
                s = s.replace(ch, "\\" + ch)
            return s

        if not items:
            try:
                answer_callback_query(cb_id, "Watchlist is empty.", False)
            except Exception:
                pass
            try:
                send_message(chat_id,
                             "*Your watchlist is empty.*\nAdd tokens with `/watch 0x...`",
                             parse_mode="MarkdownV2",
                             disable_web_page_preview=True)
            except Exception:
                pass
            return jsonify({"ok": True})

        # Compact pretty list (masked addresses)
        norm = []
        for x in items:
            try:
                t = str(x).strip()
            except Exception:
                t = None
            if not t:
                continue
            if t.startswith("0x") and len(t) > 14:
                t = t[:10] + "…" + t[-6:]
            norm.append(t)

        lines = [f"{i+1}) {t}" for i, t in enumerate(norm[:50])]
        text = "*Your Watchlist*\n" + _esc_md("\n".join(lines))
        send_message(chat_id, text, parse_mode="MarkdownV2", disable_web_page_preview=True)
        answer_callback_query(cb_id, "Watchlist sent.", False)
        return jsonify({"ok": True})

    # --- Idempotency (heavy actions only) ---
    heavy_actions = {"DETAILS", "ONCHAIN", "REPORT", "REPORT_PDF", "WHY", "WHYPP", "LP"}
    idem_key = f"cb:{chat_id}:{orig_msg_id}:{action}"
    if action in heavy_actions:
        if cache_get(idem_key):
            answer_callback_query(cb_id, "Please wait…", False)
            return jsonify({"ok": True})
        cache_set(idem_key, "1", ttl_sec=CALLBACK_DEDUP_TTL_SEC)

    bundle = load_bundle(chat_id, orig_msg_id) or {}
    links = bundle.get("links")

    # --- Existing actions (unchanged) ---
    if action == "DETAILS":
        answer_callback_query(cb_id, "More details sent.", False)
        send_message(chat_id, bundle.get("details", "(no details)"),
                     reply_markup=build_keyboard(chat_id, orig_msg_id, links, ctx="details"))

    elif action == "WHY":
        txt = bundle.get("why") or "*Why?*\n• No specific risk factors detected"
        send_message(chat_id, txt, reply_markup=None)
        answer_callback_query(cb_id, "Why? posted.", False)

    elif action == "WHYPP":
        txt = bundle.get("whypp") or "*Why++* n/a"
        MAX = 3500
        if len(txt) <= MAX:
            send_message(chat_id, txt, reply_markup=None)
        else:
            chunk = txt[:MAX]
            txt = txt[MAX:]
            send_message(chat_id, chunk, reply_markup=None)
            i = 1
            while txt:
                i += 1
                chunk_part = txt[:MAX]
                txt = txt[MAX:]
                prefix = f"Why++ ({i})\n"
                send_message(chat_id, prefix + chunk_part, reply_markup=None)
        answer_callback_query(cb_id, "Why++ posted.", False)

    elif action == "LP":
        text = bundle.get("lp", "LP lock: n/a")
        send_message(chat_id, text, reply_markup=None)
        answer_callback_query(cb_id, "LP lock posted.", False)

    elif action == "REPORT":
        try:
            # dynamic, human-friendly filename
            mkt = (bundle.get('market') or {})
            pair_sym = (mkt.get('pairSymbol') or 'Metridex')
            ts_ms = mkt.get('asof') or 0
            try:
                from datetime import datetime as _dt
                ts_str = _dt.utcfromtimestamp(int(ts_ms)/1000.0).strftime("%Y-%m-%d_%H%M")
            except Exception:
                ts_str = "now"
            import re as _re
            safe_pair = _re.sub(r"[^A-Za-z0-9._-]+", "_", str(pair_sym))
            fname = f"{safe_pair}_Report_{ts_str}.html"

            html_bytes = _build_html_report_safe(bundle)
            send_document(chat_id, fname, html_bytes, caption='Metridex QuickScan report', content_type='text/html; charset=utf-8')
            answer_callback_query(cb_id, 'Report exported.', False)
        except Exception:
            answer_callback_query(cb_id, 'Report failed.', False)

    elif action == "REPORT_PDF":
        try:
            pdf_bytes, fname = _build_pdf_report_safe(bundle)
            send_document(chat_id, fname, pdf_bytes, caption='Metridex QuickScan report (PDF)', content_type='application/pdf')
            answer_callback_query(cb_id, 'PDF exported.', False)
        except Exception:
            answer_callback_query(cb_id, 'PDF failed.', False)

    elif action == "ONCHAIN":
        # (kept logic: inspector -> v2 fallback)
        mkt = (bundle.get('market') if isinstance(bundle, dict) else None) or {}
        # Normalize chain
        chain = (mkt.get('chain') or mkt.get('chainId') or '').strip().lower()
        if chain.isdigit():
            chain = {'1':'eth','56':'bsc','137':'polygon'}.get(chain, chain)
        if chain in ('matic','pol','poly'):
            chain = 'polygon'
        token_addr = mkt.get('tokenAddress')
        try:
            oc = onchain_inspector.inspect_token(chain, token_addr, mkt.get('pairAddress'))
        except Exception as _e:
            oc = {'ok': False, 'error': str(_e)}
        ok = bool((oc or {}).get('ok'))
        if not ok or not (oc.get('codePresent') is True or oc.get('name') or (oc.get('decimals') is not None)):
            try:
                from onchain_v2 import check_contract_v2
                from renderers_onchain_v2 import render_onchain_v2
                info = check_contract_v2(chain, token_addr, timeout_s=2.5)
                text = render_onchain_v2(chain, token_addr, info)
                send_message(chat_id, text, reply_markup=build_keyboard(chat_id, orig_msg_id, bundle.get('links') if isinstance(bundle, dict) else {}, ctx='onchain'))
                answer_callback_query(cb_id, 'On-chain ready.', False)
            except Exception:
                send_message(chat_id, "On-chain\ninspection failed")
                answer_callback_query(cb_id, 'On-chain failed.', False)
        else:
            text = format_onchain_text(oc, mkt)
            send_message(chat_id, text, reply_markup=build_keyboard(chat_id, orig_msg_id, bundle.get('links') if isinstance(bundle, dict) else {}, ctx='onchain'))
            answer_callback_query(cb_id, 'On-chain ready.', False)

    elif action == "COPY_CA":
        mkt = (bundle.get("market") or {})
        token = (mkt.get("tokenAddress") or "—")
        send_message(chat_id, f"*Contract address*\n`{token}`", reply_markup=_mk_copy_keyboard(token, links))
        answer_callback_query(cb_id, "Address ready to copy.", False)

    elif action.startswith("DELTA_"):
        mkt = (bundle.get('market') or {})
        ch = (mkt.get('priceChanges') or {})
        label = {"DELTA_M5":"Δ5m","DELTA_1H":"Δ1h","DELTA_6H":"Δ6h","DELTA_24H":"Δ24h"}.get(action, "Δ")
        def _pct(v):
            try:
                n = float(v)
                arrow = "▲" if n > 0 else ("▼" if n < 0 else "•")
                return f"{arrow} {n:+.2f}%"
            except Exception:
                return "—"
        if action == "DELTA_M5":
            val = ch.get("m5")
        elif action == "DELTA_1H":
            val = ch.get("h1")
        elif action == "DELTA_6H":
            val = ch.get("h6") or ch.get("6h")
        else:
            val = ch.get("h24") or ch.get("24h")
        send_message(chat_id, f"*{label}*: {_pct(val)}", reply_markup=None)
        answer_callback_query(cb_id, f"{label} posted.", False)

    else:
        # Fallback
        answer_callback_query(cb_id, "Unsupported action", True)

    return jsonify({"ok": True})
