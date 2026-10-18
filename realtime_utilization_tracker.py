##########################################################################
#                                                                       ##
# INTEL CORPORATION PROPRIETARY INFORMATION                             ##
# This software is supplied under the terms of a license agreement or   ##
# nondisclosure agreement with Intel Corporation and may not be copied  ##
# or disclosed except in accordance with the terms of that agreement.   ##
#                                                                       ##
# Copyright (c) 2026 Intel Corporation. All Rights Reserved.            ##
#                                                                       ##
##########################################################################
"""
realtime_utilization_tracker.py
-------------------------------
Lightweight web dashboard that shows the *live* state and host utilization
for a list of iConsole system IDs.

Data source : https://pse-console-data.intel.com/  (and pse-console-auth)
Auth flow   : Same Azure AD login + ~/.iconsole_creds storage pattern used
              by get_vid_from_iconsole.py / get_chassis_from_iconsole.py.

Quick start
-----------
    pip install flask requests
    python realtime_utilization_tracker.py
    # then open http://localhost:5000

System IDs are read from (in this order):
    1. --ids arguments on the command line
    2. A plain-text file `system_ids.txt` (one ID per line) next to this script
    3. An interactive prompt
"""

from __future__ import annotations

import argparse
import base64
import csv
import getpass
import io
import json
import os
import sys
import threading
import time
import webbrowser
from datetime import datetime, timedelta, timezone

import urllib3
import requests

try:
    from flask import Flask, jsonify, render_template_string, Response, request
except ImportError:
    sys.exit("[ERROR] flask is required.  Install it with:  pip install flask")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AUTH_URL      = "https://pse-console-auth.intel.com"
DATA_URL      = "https://pse-console-data.intel.com"
QUERY_BOT_URL = "https://pse-console-query-bot-relay.intel.com"  # utilization metrics live here
ICONSOLE_UI_URL = "https://console.intel.com"   # user-facing iConsole web app
PROXIES     = {"http": "", "https": ""}
TIMEOUT     = 30
CREDS_FILE  = os.path.join(os.path.expanduser("~"), ".iconsole_creds")
IDS_FILE    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "system_ids.txt")

# How often the background poller refreshes data (seconds)
POLL_INTERVAL_SEC = 60

# Default historical window (days) used when computing averages.
DAYS_WINDOW = 7

# Utilization comes from the iConsole utilization-agent chatbot, not from
# pse-console-data.intel.com. The agent returns per-day host_utilization
# samples for one or more system IDs.
UTIL_AGENT_PATH = "/api/v2/chatbot/conversation"

# ---------------------------------------------------------------------------
# Shared mutable state (guarded by _LOCK)
# ---------------------------------------------------------------------------
_LOCK             = threading.Lock()
_SYSTEMS_CACHE    : dict[str, dict] = {}
_SYSTEM_IDS       : list[str]       = []     # tracked IDs (mutable at runtime)
_LAST_REFRESH_UTC : str | None      = None
_TOKEN_HOLDER     : dict            = {"token": None, "email": None, "password": None}
_REFRESH_EVENT    : threading.Event = threading.Event()


# ---------------------------------------------------------------------------
# HTTP helper (same pattern as the other iConsole scripts in this repo)
# ---------------------------------------------------------------------------

def _request(method: str, url: str, session: requests.Session, **kwargs):
    fn = getattr(session, method)
    try:
        return fn(url, timeout=TIMEOUT, proxies=PROXIES, **kwargs)
    except requests.exceptions.SSLError:
        try:
            return fn(url, timeout=TIMEOUT, proxies=PROXIES, verify=False, **kwargs)
        except requests.exceptions.RequestException as exc:
            print(f"[ERROR] {method.upper()} {url}: {exc}")
            return None
    except requests.exceptions.RequestException as exc:
        print(f"[ERROR] {method.upper()} {url}: {exc}")
        return None


# ---------------------------------------------------------------------------
# Credential storage  (compatible with get_vid_from_iconsole.py)
# ---------------------------------------------------------------------------

def _load_saved_creds():
    if not os.path.exists(CREDS_FILE):
        return None
    try:
        raw = open(CREDS_FILE, "r").read().strip()
        decoded = base64.b64decode(raw.encode()).decode("utf-8")
        email, password = decoded.split("\n", 1)
        return email, password
    except Exception:
        return None


def _save_creds(email: str, password: str) -> None:
    encoded = base64.b64encode(f"{email}\n{password}".encode()).decode()
    with open(CREDS_FILE, "w") as fh:
        fh.write(encoded)
    try:
        import stat
        os.chmod(CREDS_FILE, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass


def _delete_saved_creds() -> None:
    if os.path.exists(CREDS_FILE):
        os.remove(CREDS_FILE)
        print(f"  Saved credentials deleted from {CREDS_FILE}")


def prompt_credentials() -> tuple[str, str]:
    """Reuse stored creds (with U/R/D menu) or prompt fresh + offer to save."""
    print("\n--- Authentication (Intel Azure AD) ---")
    saved = _load_saved_creds()

    if saved:
        email, _ = saved
        print(f"  Saved credentials found for: {email}")
        while True:
            choice = input("  [U]se saved / [R]e-enter / [D]elete saved: ").strip().lower()
            if choice in ("u", ""):
                print("  Using saved credentials.")
                return saved
            if choice == "r":
                break
            if choice == "d":
                _delete_saved_creds()
                break
            print("  Please enter U, R, or D.")

    email = input("Intel email (e.g. first.last@intel.com): ").strip()
    if not email:
        print("[ERROR] Email cannot be empty.")
        sys.exit(1)
    password = getpass.getpass(f"Password for {email}: ")
    if not password:
        print("[ERROR] Password cannot be empty.")
        sys.exit(1)

    if not os.path.exists(CREDS_FILE):
        store = input("Save credentials for future runs? [y/N]: ").strip().lower()
        if store == "y":
            _save_creds(email, password)
            print(f"  Credentials saved to {CREDS_FILE}")
        else:
            print("  Credentials NOT saved. You will be prompted on every run.")

    return email, password


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def login(email: str, password: str) -> str:
    url = f"{AUTH_URL}/api/v1/aad/login"
    session = requests.Session()
    resp = _request(
        "post", url, session,
        json={"email": email, "password": password},
        headers={"Content-Type": "application/json"},
    )
    if resp is None:
        sys.exit("[ERROR] Could not reach the authentication service.")
    if resp.status_code != 200:
        sys.exit(f"[ERROR] Login failed ({resp.status_code}): {resp.text[:300]}")
    token = resp.json().get("access_token")
    if not token:
        sys.exit(f"[ERROR] No access_token in response: {resp.text[:300]}")
    return token


def _make_session(token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
        "Accept":        "application/json",
    })
    return s


def _refresh_token() -> str:
    """Re-login using stored credentials in _TOKEN_HOLDER."""
    email = _TOKEN_HOLDER["email"]
    password = _TOKEN_HOLDER["password"]
    token = login(email, password)
    _TOKEN_HOLDER["token"] = token
    return token


# ---------------------------------------------------------------------------
# Inventory + utilization fetch
# ---------------------------------------------------------------------------

def _get_json(session: requests.Session, path: str):
    """GET DATA_URL+path; return (status_code, parsed_or_text)."""
    url = f"{DATA_URL}{path}"
    resp = _request("get", url, session)
    if resp is None:
        return None, None
    try:
        return resp.status_code, resp.json()
    except ValueError:
        return resp.status_code, resp.text


def _extract_inventory_summary(record: dict) -> dict:
    """Pull the small set of fields the dashboard displays."""
    if not isinstance(record, dict):
        return {}
    hostname = record.get("hostname") or ""
    # Try a handful of paths for "current state" / "power state".
    state = ""
    for path in (("state",), ("status",), ("system_state",), ("power_state",),
                 ("last_state",), ("active_task",)):
        node = record
        for k in path:
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(k)
        if node:
            state = str(node)
            break

    processor = ""
    qdfs: list[str] = []
    cpu_block = record.get("cpu") if isinstance(record.get("cpu"), dict) else {}
    cpus = cpu_block.get("cpus") if isinstance(cpu_block.get("cpus"), dict) else {}
    for k in sorted(cpus.keys()):
        entry = cpus[k]
        if not isinstance(entry, dict):
            continue
        if not processor and entry.get("product"):
            processor = str(entry["product"])
        q = entry.get("qdf")
        if q and str(q).strip() and str(q) not in qdfs:
            qdfs.append(str(q).strip())
    qdf = ", ".join(qdfs)

    return {
        "hostname":  hostname,
        "state":     state,
        "processor": processor,
        "qdf":       qdf,
    }


# The Mongo-backed system-details endpoint does NOT accept a `fields=` filter
# (the allow-list rejects most names), so we just request the full document and
# pluck what we need from its nested structure:
#   tags.{val_team, label, group, domain, pool, activity, ...}
#   nga_params.{notes, activity, project, recipe, pool, automation_status}
#   processor / system_state / cluster_pool / etc. live at the top level.
_DETAILS_FIELDS = ""  # unused – kept for backwards compat


def _to_str_list(v) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return ", ".join(str(x).strip() for x in v if x is not None and str(x).strip())
    return str(v).strip()


def _fetch_system_details(session: requests.Session, system_id: str) -> dict:
    """
    Call /api/v1/systems/system-details/{id} and return a flat dict with the
    tag/identity fields the dashboard cares about.  Returns {} on any error.
    """
    path = f"/api/v1/systems/system-details/{system_id}"
    status, body = _get_json(session, path)
    if status == 401:
        try:
            _refresh_token()
            session = _make_session(_TOKEN_HOLDER["token"])
            status, body = _get_json(session, path)
        except SystemExit:
            return {}
    if status != 200 or not isinstance(body, dict):
        return {}

    tags = body.get("tags") if isinstance(body.get("tags"), dict) else {}
    nga  = body.get("nga_params") if isinstance(body.get("nga_params"), dict) else {}

    return {
        "val_team":     _to_str_list(tags.get("val_team")),
        "label":        _to_str_list(tags.get("label")),
        "domain":       _to_str_list(tags.get("domain")),
        "pool":         _to_str_list(tags.get("pool")),
        "group":        _to_str_list(tags.get("group")),
        "activity":     _to_str_list(tags.get("activity")),
        "nga_notes":    _to_str_list(nga.get("notes")),
        "nga_activity": _to_str_list(nga.get("activity")),
        "processor_d":  _to_str_list(body.get("processor")),
        "sut_state":    _to_str_list(body.get("system_state")),
    }


_HOST_UTIL_KEYS = ("host_utilization", "host_util", "host_util_pct",
                   "host_utilization_pct", "host_pct")
_SUT_UTIL_KEYS  = ("sut_utilization", "sut_util", "sut_util_pct",
                   "sut_utilization_pct", "sut_pct",
                   "target_utilization", "target_util", "target_util_pct",
                   "target_pct", "dut_utilization", "dut_util")
_GENERIC_UTIL_KEYS = ("utilization", "utilization_pct", "util",
                      "value", "percent")
_RECURSE_KEYS = ("data", "result", "results", "items", "samples",
                 "history", "latest")


def _coerce_pct(v) -> float | None:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        s = v.strip().rstrip("%")
        try:
            return float(s)
        except ValueError:
            return None
    return None


def _extract_util_pcts(record) -> tuple[float | None, float | None]:
    """
    Return (host_pct, sut_pct) extracted from an arbitrary utilization
    response. Both may be None.  If a payload only carries a generic value
    (no explicit host/sut key) the value is returned as host.
    """
    if record is None:
        return None, None
    # Scalar / string payload -> treat as host
    if isinstance(record, (int, float, str)):
        return _coerce_pct(record), None
    if isinstance(record, list) and record:
        return _extract_util_pcts(record[-1])
    if not isinstance(record, dict):
        return None, None

    host = sut = None
    for k in _HOST_UTIL_KEYS:
        if k in record:
            v = _coerce_pct(record[k])
            if v is not None:
                host = v
                break
    for k in _SUT_UTIL_KEYS:
        if k in record:
            v = _coerce_pct(record[k])
            if v is not None:
                sut = v
                break

    if host is None and sut is None:
        for k in _GENERIC_UTIL_KEYS:
            if k in record:
                v = _coerce_pct(record[k])
                if v is not None:
                    host = v
                    break

    if host is None and sut is None:
        for k in _RECURSE_KEYS:
            if k in record:
                h, s = _extract_util_pcts(record[k])
                if h is not None or s is not None:
                    return h, s
    return host, sut


def _collect_samples(record) -> list[dict]:
    """
    Walk a payload and return a flat list of per-sample dicts that look like
    daily utilization rows. Each element is the dict the API returned
    (preserving any 'date' / 'host_utilization' / 'sut_utilization' keys).
    """
    out: list[dict] = []
    if isinstance(record, list):
        for item in record:
            out.extend(_collect_samples(item))
        return out
    if not isinstance(record, dict):
        return out
    # If this dict itself has a util/date-ish key set, treat as a sample.
    looks_like_sample = any(
        k in record for k in (*_HOST_UTIL_KEYS, *_SUT_UTIL_KEYS, *_GENERIC_UTIL_KEYS)
    ) and any(k in record for k in ("date", "day", "timestamp", "ts", "time"))
    if looks_like_sample:
        out.append(record)
    for k in _RECURSE_KEYS:
        if k in record:
            out.extend(_collect_samples(record[k]))
    return out


def _avg(values: list[float]) -> float | None:
    vals = [v for v in values if v is not None]
    if not vals:
        return None
    return round(sum(vals) / len(vals), 2)


def _extract_activity(record) -> str:
    if isinstance(record, dict):
        for key in ("activity", "current_activity", "task", "active_task"):
            if record.get(key):
                return str(record[key])
        for key in ("data", "result", "results", "items", "samples",
                    "history", "latest"):
            if key in record:
                v = _extract_activity(record[key])
                if v:
                    return v
    if isinstance(record, list) and record:
        return _extract_activity(record[-1])
    return ""


def _post_util_agent(session: requests.Session, message: str) -> tuple[int | None, dict | None]:
    """
    POST a single user message to the iConsole utilization chatbot agent and
    return (status_code, parsed_json).  Uses the same Bearer token already on
    the session.  This service lives on QUERY_BOT_URL, not DATA_URL.
    """
    url = f"{QUERY_BOT_URL}{UTIL_AGENT_PATH}"
    body = {
        "agent_type": "utilization",
        "messages": [{
            "sender":     "user",
            "agent_type": "utilization",
            "message":    message,
        }],
    }
    resp = _request("post", url, session, json=body)
    if resp is None:
        return None, None
    try:
        return resp.status_code, resp.json()
    except ValueError:
        return resp.status_code, None


def _fetch_daily_samples(session: requests.Session, system_id: str, days: int
                         ) -> tuple[list[dict], str]:
    """
    Ask the utilization agent for per-day host_utilization samples for a
    single system over the past `days` days.

    Returns (samples, error). Each sample is a dict:
        {"date": "YYYY-MM-DD", "host_utilization": float, "activity": str}
    """
    msg = (f"Get host utilization for system {system_id} for the past "
           f"{days} days. Return one sample per day with date, "
           f"host_utilization and activity.")

    status, payload = _post_util_agent(session, msg)
    if status == 401:
        try:
            _refresh_token()
            session = _make_session(_TOKEN_HOLDER["token"])
            status, payload = _post_util_agent(session, msg)
        except SystemExit as e:
            return [], f"re-auth failed: {e}"
    if status is None:
        return [], "network error"
    if status != 200 or not isinstance(payload, dict):
        return [], f"util HTTP {status}"
    if payload.get("error"):
        return [], str(payload["error"])

    raw = payload.get("data") or []
    out: list[dict] = []
    for s in raw:
        if not isinstance(s, dict):
            continue
        if s.get("system_id") and str(s["system_id"]).lower() != system_id.lower():
            continue
        pct = _coerce_pct(s.get("host_utilization"))
        if pct is None:
            continue
        out.append({
            "date":             s.get("date") or "",
            "host_utilization": round(pct, 2),
            "activity":         s.get("activity") or s.get("nga_activity") or "",
            "processor":        s.get("processor") or "",
            "hw_config":        s.get("hw_config") or "",
        })
    # Sort oldest -> newest by date
    out.sort(key=lambda x: x.get("date") or "")
    return out, ""


def _summarize_samples(samples: list[dict]) -> tuple[float | None, float | None, str, str]:
    """
    Reduce daily samples to (today_pct, avg_pct, latest_activity, latest_date).
    today_pct = sample for today's UTC date if present, else value of the
    most-recent sample. avg_pct = mean across all returned samples.
    """
    if not samples:
        return None, None, "", ""
    today_iso = datetime.now(timezone.utc).date().isoformat()
    today_pct = next((s["host_utilization"] for s in samples
                      if s.get("date") == today_iso), None)
    latest = samples[-1]
    if today_pct is None:
        today_pct = latest["host_utilization"]
    avg_pct = round(sum(s["host_utilization"] for s in samples) / len(samples), 2)
    activity = ""
    for s in reversed(samples):
        if s.get("activity"):
            activity = s["activity"]
            break
    return today_pct, avg_pct, activity, latest.get("date", "")


def fetch_one(session: requests.Session, system_id: str, days: int) -> dict:
    """Fetch inventory + utilization for one system, returning a flat dict."""
    inv_status, inv_body = _get_json(session, f"/api/v1/inventory/system/{system_id}")
    summary = _extract_inventory_summary(inv_body) if inv_status == 200 else {}

    # Pull tag/identity fields (val_team, label, nga_notes, ...) from the
    # Mongo-backed system-details endpoint – they are NOT in the Elastic
    # inventory record above.
    details = _fetch_system_details(session, system_id)

    samples, util_err = _fetch_daily_samples(session, system_id, days)
    today_pct, avg_pct, activity, latest_date = _summarize_samples(samples)

    err = ""
    if inv_status is None:
        err = "network error"
    elif inv_status == 401:
        err = "401 unauthorized (token expired)"
    elif inv_status == 404:
        err = "system not found"
    elif inv_status != 200:
        err = f"inventory HTTP {inv_status}"
    elif util_err and not samples:
        err = f"utilization: {util_err}"

    return {
        "system_id":             system_id,
        "hostname":              summary.get("hostname", "") or system_id,
        "processor":             summary.get("processor", "")
                                  or details.get("processor_d", "")
                                  or (samples[-1]["processor"] if samples else ""),
        "qdf":                   summary.get("qdf", ""),
        "val_team":              details.get("val_team", ""),
        "label":                 details.get("label", ""),
        "nga_notes":             details.get("nga_notes", ""),
        "nga_activity":          details.get("nga_activity", ""),
        "domain":                details.get("domain", ""),
        "pool":                  details.get("pool", ""),
        "group":                 details.get("group", ""),
        "state":                 summary.get("state", "") or details.get("sut_state", ""),
        "activity":              activity or details.get("activity", ""),
        # Real-time / today's reading
        "utilization_today":     today_pct,
        # N-day historical mean
        "utilization_avg":       avg_pct,
        "latest_sample_date":    latest_date,
        "daily_samples":         samples,           # for the per-day breakdown
        "days_window":           days,
        "sample_count":          len(samples),
        "iconsole_url":          f"{ICONSOLE_UI_URL}/dc/system/{system_id}/summary",
        "error":                 err,
        "fetched_at_utc":        datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _normalize_id(raw) -> str:
    """
    Clean a user-supplied system ID:
      * coerce to str
      * strip ASCII whitespace AND zero-width / non-breaking unicode chars
      * collapse internal whitespace
      * remove any trailing comma/semicolon left over from paste
    Case is preserved (the verifier handles case-insensitive matching).
    """
    if raw is None:
        return ""
    s = str(raw)
    # Strip BOM, zero-width spaces, non-breaking spaces, etc.
    for ch in ("\u200b", "\u200c", "\u200d", "\ufeff", "\u00a0"):
        s = s.replace(ch, "")
    s = s.strip().strip(",;\"'`")
    # Drop any remaining internal whitespace (system IDs never contain spaces)
    s = "".join(s.split())
    return s


def verify_system_exists(session: requests.Session, system_id: str
                         ) -> tuple[bool, str, str]:
    """
    Probe the inventory endpoint to confirm a system_id exists in iConsole.

    Tries the ID as-given first, then lower-case, then upper-case so that a
    user typing 'CS16CA101FS0603' still matches the canonical lower-case
    record (and vice versa).

    Returns (exists, message, canonical_id).
    """
    tried: list[str] = []
    for candidate in (system_id, system_id.lower(), system_id.upper()):
        if not candidate or candidate in tried:
            continue
        tried.append(candidate)

        status, body = _get_json(session, f"/api/v1/inventory/system/{candidate}")
        if status == 401:
            try:
                _refresh_token()
                session = _make_session(_TOKEN_HOLDER["token"])
                status, body = _get_json(session,
                                         f"/api/v1/inventory/system/{candidate}")
            except SystemExit as e:
                return False, f"re-auth failed: {e}", system_id

        if status == 200 and isinstance(body, dict):
            # Prefer the canonical ID echoed back by the API if present.
            canonical = (body.get("system_id")
                         or body.get("id")
                         or body.get("name")
                         or candidate)
            canonical = str(canonical).strip() or candidate
            return True, "ok", canonical
        if status is None:
            return False, "network error", system_id
        if status not in (404,):
            return False, f"HTTP {status}", system_id

    return False, "not found in iConsole", system_id


# ---------------------------------------------------------------------------
# Background poller
# ---------------------------------------------------------------------------

def _poll_loop() -> None:
    global _LAST_REFRESH_UTC
    while True:
        try:
            with _LOCK:
                ids_snapshot = list(_SYSTEM_IDS)
                days = DAYS_WINDOW
            session = _make_session(_TOKEN_HOLDER["token"])
            results: dict[str, dict] = {}
            for sid in ids_snapshot:
                row = fetch_one(session, sid, days)
                if row["error"].startswith("401"):
                    print("[INFO] Token expired – refreshing.")
                    try:
                        _refresh_token()
                        session = _make_session(_TOKEN_HOLDER["token"])
                        row = fetch_one(session, sid, days)
                    except SystemExit as e:
                        row["error"] = f"re-auth failed: {e}"
                results[sid] = row
            with _LOCK:
                for stale in [k for k in _SYSTEMS_CACHE if k not in _SYSTEM_IDS]:
                    _SYSTEMS_CACHE.pop(stale, None)
                _SYSTEMS_CACHE.update(results)
                _LAST_REFRESH_UTC = datetime.now(timezone.utc).isoformat(timespec="seconds")
            print(f"[POLL] Refreshed {len(results)} systems (window={days}d) at {_LAST_REFRESH_UTC}")
        except Exception as exc:
            print(f"[POLL] Unexpected error: {exc}")
        _REFRESH_EVENT.wait(timeout=POLL_INTERVAL_SEC)
        _REFRESH_EVENT.clear()


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)

INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>iConsole - Real-time System Utilization</title>
  <style>
    :root {
      --bg: #0e1726;
      --card: #182338;
      --card2: #1f2c47;
      --text: #e6edf7;
      --muted: #8aa0c2;
      --ok: #2ecc71;
      --warn: #f5b041;
      --bad: #e74c3c;
      --idle: #5d6d7e;
      --accent: #4ea3ff;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; background: var(--bg); color: var(--text);
      font: 14px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    header {
      padding: 14px 22px;
      background: linear-gradient(135deg, #1c2a4a, #0e1726);
      border-bottom: 1px solid #243454;
      display: flex; flex-direction: column; gap: 10px;
    }
    .top-row {
      display:flex; justify-content:space-between; align-items:center;
      flex-wrap:wrap; gap:12px;
    }
    header h1 { margin: 0; font-size: 18px; font-weight: 600; }
    header .meta { color: var(--muted); font-size: 12px; }
    .controls { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
    .controls input, .controls select, .add-row input, .add-row button {
      background:#0a1322; border:1px solid #2a3a5e; color:var(--text);
      padding:7px 10px; border-radius:6px; font-size:13px;
    }
    .controls input { min-width:220px; }
    .add-row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
    .add-row input { min-width:340px; }
    .add-row button {
      cursor:pointer; background: var(--accent); border-color: var(--accent);
      color:#0a1322; font-weight:600;
    }
    .add-row button.secondary {
      background:#0a1322; color:var(--text); font-weight:500;
    }
    .add-row button:hover { filter:brightness(1.1); }
    .add-row .hint { color:var(--muted); font-size:11px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(310px, 1fr));
      gap: 12px; padding: 16px;
    }
    .card {
      background: var(--card); border: 1px solid #2a3a5e; border-radius: 10px;
      padding: 14px; display: flex; flex-direction: column; gap: 8px;
      transition: transform .12s ease;
    }
    .card:hover { transform: translateY(-2px); }
    .card .top { display:flex; justify-content:space-between; align-items:flex-start; gap:8px; }
    .card .sid { font-weight:600; font-size:14px; word-break:break-all; }
    .card .host { color:var(--muted); font-size:12px; }
    .card .proc { color:var(--muted); font-size:11px; font-style:italic; }
    .card .actions { display:flex; gap:6px; }
    .icon-btn {
      cursor:pointer; background:transparent; border:1px solid #2a3a5e;
      color:var(--muted); border-radius:6px; padding:2px 7px; font-size:12px;
    }
    .icon-btn:hover { color:var(--bad); border-color:var(--bad); }
    .iconsole-link {
      color: var(--accent); text-decoration: none; font-size: 11px;
      border: 1px solid var(--accent); border-radius: 6px; padding: 2px 7px;
    }
    .iconsole-link:hover { background: rgba(78,163,255,.12); }
    .pill {
      font-size: 11px; padding: 3px 8px; border-radius: 999px;
      background: #2a3a5e; color: #cfd9ec; white-space: nowrap;
    }
    .pill.ok   { background: rgba(46,204,113,.18); color: var(--ok); }
    .pill.bad  { background: rgba(231,76,60,.18);  color: var(--bad); }
    .pill.warn { background: rgba(245,176,65,.18); color: var(--warn); }
    .pill.idle { background: rgba(93,109,126,.25); color: #c2cee0; }
    .util-block { margin-top:6px; }
    .util-row {
      display:flex; justify-content:space-between; align-items:baseline;
      margin-top:6px;
    }
    .util-row .label { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.04em; }
    .util-row .num { font-size:18px; font-weight:700; }
    .bar {
      height: 8px; background: #0a1322; border-radius: 4px; overflow: hidden;
      border: 1px solid #243454; margin-top: 4px;
    }
    .bar > div { height:100%; transition: width .4s ease; }
    .bar .b-ok   { background: var(--ok); }
    .bar .b-warn { background: var(--warn); }
    .bar .b-bad  { background: var(--bad); }
    .bar .b-idle { background: var(--idle); }
    .activity { color: var(--muted); font-size:11px; margin-top:4px; }
    .tag-grid {
      display:grid; grid-template-columns: 1fr; gap:3px; margin-top:6px;
      padding:6px 8px; background:#0a1322; border:1px solid #243454; border-radius:6px;
    }
    .tag { display:flex; gap:8px; font-size:11px; line-height:1.3; }
    .tag-k {
      color:var(--muted); text-transform:uppercase; letter-spacing:.04em;
      min-width:62px; flex-shrink:0;
    }
    .tag-v { color:var(--text); word-break:break-word; }
    .meta-row {
      display:flex; justify-content:space-between; align-items:center;
      color: var(--muted); font-size: 11px; margin-top: 4px;
    }
    .err { color: var(--bad); font-size: 12px; }
    .empty {
      grid-column: 1 / -1; text-align:center; padding:40px; color:var(--muted);
      border:1px dashed #2a3a5e; border-radius:10px;
    }
    .toast {
      position:fixed; bottom:18px; right:18px; background:#1f2c47;
      border:1px solid #2a3a5e; padding:10px 14px; border-radius:8px;
      color:var(--text); font-size:13px; opacity:0; transition:opacity .25s;
      pointer-events:none; max-width:420px; white-space:pre-wrap;
    }
    .toast.show { opacity:1; }
    .toast.err  { border-color:var(--bad); color:var(--bad); }
    .sparkline { display:flex; gap:2px; align-items:flex-end; height:36px; margin-top:6px; }
    .spark-bar { flex:1; min-width:6px; background:var(--idle); border-radius:2px 2px 0 0; position:relative; }
    .spark-bar.b-ok   { background: var(--ok); }
    .spark-bar.b-warn { background: var(--warn); }
    .spark-bar.b-bad  { background: var(--bad); }
    .spark-bar.today  { outline: 1px solid var(--accent); }
    .spark-bar:hover::after {
      content: attr(data-tip); position:absolute; bottom:100%; left:50%;
      transform:translateX(-50%); background:#0a1322; color:var(--text);
      border:1px solid #2a3a5e; border-radius:4px; padding:2px 6px;
      font-size:11px; white-space:nowrap; pointer-events:none; z-index:5;
    }
    footer { text-align:center; color:var(--muted); padding:12px; font-size:11px; }
  </style>
</head>
<body>
  <header>
    <div class="top-row">
      <div>
        <h1>iConsole &mdash; Real-time System Utilization</h1>
        <div class="meta">
          Source: <a href="https://console.intel.com" target="_blank" rel="noopener"
                     style="color:var(--accent);text-decoration:none">console.intel.com</a>
          &middot; Client refresh every <span id="refresh-sec">10</span>s
          &middot; Last server poll: <span id="last-refresh">never</span>
          &middot; Tracking <span id="sys-count">0</span> systems
        </div>
      </div>
      <div class="controls">
        <input id="filter" placeholder="Filter by ID / hostname / state / QDF / val team / label..." />
        <select id="days">
          <option value="1">Window: 1 day</option>
          <option value="3">Window: 3 days</option>
          <option value="7" selected>Window: 7 days</option>
          <option value="14">Window: 14 days</option>
          <option value="30">Window: 30 days</option>
          <option value="60">Window: 60 days</option>
          <option value="90">Window: 90 days</option>
        </select>
        <select id="sort">
          <option value="today_desc" selected>Sort: Today &darr;</option>
          <option value="today_asc">Sort: Today &uarr;</option>
          <option value="avg_desc">Sort: {N}d Avg &darr;</option>
          <option value="avg_asc">Sort: {N}d Avg &uarr;</option>
          <option value="id">Sort: System ID</option>
          <option value="state">Sort: State</option>
        </select>
      </div>
    </div>
    <div class="add-row">
      <input id="new-ids" placeholder="Add system IDs (comma, space, or newline separated)..." />
      <button id="btn-add">Add</button>
      <button id="btn-refresh" class="secondary" title="Force a server poll now">Refresh now</button>
      <button id="btn-export-xlsx" class="secondary" title="Export all tracked systems to Excel">Export Excel</button>
      <span class="hint">Tip: Each card has a &times; button to remove it, and a &darr; button to export only that system.</span>
    </div>
  </header>

  <div id="grid" class="grid"></div>
  <footer>Auto-refreshing dashboard &middot; data cached server-side every {{ poll_interval }}s</footer>
  <div id="toast" class="toast"></div>

<script>
const CLIENT_REFRESH_MS = 10_000;
document.getElementById("refresh-sec").textContent = CLIENT_REFRESH_MS / 1000;

function utilClass(p) {
  if (p === null || p === undefined) return "idle";
  if (p >= 75) return "ok";
  if (p >= 40) return "warn";
  if (p >  0) return "bad";
  return "idle";
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => (
    {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]
  ));
}

function utilRow(label, pct) {
  const cls = utilClass(pct);
  const w   = pct === null || pct === undefined ? 0 : Math.max(0, Math.min(100, pct));
  const txt = pct === null || pct === undefined ? "n/a" : pct.toFixed(2) + "%";
  return `
    <div class="util-row"><span class="label">${label}</span><span class="num">${txt}</span></div>
    <div class="bar"><div class="b-${cls}" style="width:${w}%"></div></div>
  `;
}

function sparkline(samples, todayIso) {
  if (!samples || !samples.length) return "";
  const bars = samples.map(s => {
    const p = s.host_utilization;
    const cls = utilClass(p);
    const h = Math.max(2, Math.round(p));
    const isToday = s.date === todayIso ? "today" : "";
    const tip = `${s.date}: ${p.toFixed(2)}%${s.activity ? '  ['+s.activity+']' : ''}`;
    return `<div class="spark-bar b-${cls} ${isToday}" style="height:${h}%" data-tip="${escapeHtml(tip)}"></div>`;
  }).join("");
  return `<div class="sparkline" title="Daily host utilization">${bars}</div>`;
}

function renderCard(row) {
  const stateClass = row.error ? "bad"
                    : (row.state || "").toLowerCase().includes("idle") ? "idle"
                    : (row.state ? "ok" : "warn");
  const days = row.days_window || CURRENT_DAYS;
  const iconsoleUrl = row.iconsole_url || ('https://console.intel.com/dc/system/' + row.system_id + '/summary');

  const tagsHtml = `
    <div class="tag-grid">
      <div class="tag"><span class="tag-k">QDF</span><span class="tag-v">${escapeHtml(row.qdf || "—")}</span></div>
      <div class="tag"><span class="tag-k">Val Team</span><span class="tag-v">${escapeHtml(row.val_team || "—")}</span></div>
      <div class="tag"><span class="tag-k">Label</span><span class="tag-v">${escapeHtml(row.label || "—")}</span></div>
      <div class="tag"><span class="tag-k">NGA Notes</span><span class="tag-v">${escapeHtml(row.nga_notes || "—")}</span></div>
      <div class="tag"><span class="tag-k">NGA Activity</span><span class="tag-v">${escapeHtml(row.nga_activity || "—")}</span></div>
    </div>`;

  return `
    <div class="card">
      <div class="top">
        <div>
          <div class="sid">
            <a href="${escapeHtml(iconsoleUrl)}" target="_blank" rel="noopener noreferrer"
               style="color:inherit;text-decoration:none" title="Open ${escapeHtml(row.system_id)} in iConsole"
               >${escapeHtml(row.system_id)}</a>
          </div>
          <div class="host">${escapeHtml(row.hostname || "—")}</div>
          <div class="proc">${escapeHtml(row.processor || "")}</div>
        </div>
        <div class="actions">
          <span class="pill ${stateClass}">${escapeHtml(row.state || (row.error ? "ERROR" : "unknown"))}</span>
          <a class="iconsole-link" href="${escapeHtml(iconsoleUrl)}"
             target="_blank" rel="noopener noreferrer" title="Open in iConsole">iConsole ↗</a>
          <button class="icon-btn" title="Export Excel" data-export-xlsx="${escapeHtml(row.system_id)}">⬇ XLSX</button>
          <button class="icon-btn" title="Remove" data-remove="${escapeHtml(row.system_id)}">×</button>
        </div>
      </div>
      ${tagsHtml}
      ${row.error ? `<div class="err">${escapeHtml(row.error)}</div>` : ""}
      <div class="util-block">
        ${utilRow("Today (real-time)",  row.utilization_today)}
        ${utilRow(`Last ${days}d average`, row.utilization_avg)}
        ${sparkline(row.daily_samples, TODAY_ISO)}
      </div>
      ${row.activity ? `<div class="activity">Activity: ${escapeHtml(row.activity)}</div>` : ""}
      <div class="meta-row">
        <span>updated: ${escapeHtml((row.fetched_at_utc || "").replace("T"," ").replace("+00:00","Z"))}</span>
        ${row.sample_count ? `<span>${row.sample_count} samples</span>` : ""}
      </div>
    </div>
  `;
}

function primaryPct(r) {
  return r.utilization_today ?? r.utilization_avg;
}

function compare(a, b, mode) {
  switch (mode) {
    case "today_asc":  return (a.utilization_today ?? -1) - (b.utilization_today ?? -1);
    case "today_desc": return (b.utilization_today ?? -1) - (a.utilization_today ?? -1);
    case "avg_asc":    return (a.utilization_avg   ?? -1) - (b.utilization_avg   ?? -1);
    case "avg_desc":   return (b.utilization_avg   ?? -1) - (a.utilization_avg   ?? -1);
    case "id":         return a.system_id.localeCompare(b.system_id);
    case "state":      return (a.state || "").localeCompare(b.state || "");
  }
  return 0;
}

let LAST_DATA = [];
let CURRENT_DAYS = {{ days_window }};
let TODAY_ISO = new Date().toISOString().slice(0,10);

function render() {
  const filter = document.getElementById("filter").value.trim().toLowerCase();
  const sort   = document.getElementById("sort").value;
  let rows = LAST_DATA.slice();
  if (filter) {
    rows = rows.filter(r =>
      (r.system_id || "").toLowerCase().includes(filter) ||
      (r.hostname  || "").toLowerCase().includes(filter) ||
      (r.state     || "").toLowerCase().includes(filter) ||
      (r.activity  || "").toLowerCase().includes(filter) ||
      (r.qdf       || "").toLowerCase().includes(filter) ||
      (r.val_team  || "").toLowerCase().includes(filter) ||
      (r.label     || "").toLowerCase().includes(filter) ||
      (r.nga_notes || "").toLowerCase().includes(filter) ||
      (r.nga_activity || "").toLowerCase().includes(filter)
    );
  }
  rows.sort((a,b) => compare(a,b,sort));
  const grid = document.getElementById("grid");
  if (!rows.length) {
    grid.innerHTML = `<div class="empty">No systems are being tracked. Add some above to begin.</div>`;
  } else {
    grid.innerHTML = rows.map(renderCard).join("");
  }
  document.getElementById("sys-count").textContent = LAST_DATA.length;
}

function toast(msg, isErr=false) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.toggle("err", !!isErr);
  t.classList.add("show");
  clearTimeout(window.__tt);
  window.__tt = setTimeout(() => t.classList.remove("show"),
                           isErr ? 6000 : 3500);
}

async function refresh() {
  try {
    const r = await fetch("/api/data", {cache: "no-store"});
    const j = await r.json();
    LAST_DATA = j.systems || [];
    if (j.days_window) {
      CURRENT_DAYS = j.days_window;
      const sel = document.getElementById("days");
      if (sel.value != String(CURRENT_DAYS)) sel.value = String(CURRENT_DAYS);
      // Refresh "{N}d Avg" labels
      const sortSel = document.getElementById("sort");
      for (const opt of sortSel.options) {
        opt.text = opt.text.replace(/\d+d Avg/, CURRENT_DAYS + "d Avg")
                           .replace(/\{N\}d Avg/, CURRENT_DAYS + "d Avg");
      }
    }
    TODAY_ISO = new Date().toISOString().slice(0,10);
    document.getElementById("last-refresh").textContent =
      (j.last_refresh_utc || "never").replace("T"," ").replace("+00:00"," UTC");
    render();
  } catch (e) { console.error(e); }
}

async function changeWindow() {
  const v = parseInt(document.getElementById("days").value, 10);
  try {
    const r = await fetch("/api/window", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({days: v}),
    });
    const j = await r.json();
    if (!r.ok) { toast(j.error || "Failed", true); return; }
    CURRENT_DAYS = j.days;
    toast(`Window set to ${j.days} days. Repolling...`);
    setTimeout(refresh, 1500);
  } catch (e) { toast("Network error: " + e.message, true); }
}

async function addSystems() {
  const input = document.getElementById("new-ids");
  const raw = input.value.trim();
  if (!raw) return;
  const ids = raw.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean);
  toast(`Validating ${ids.length} system(s)...`);
  try {
    const r = await fetch("/api/systems", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({add: ids}),
    });
    const j = await r.json();
    if (!r.ok) { toast(j.error || "Add failed", true); return; }
    if (j.added.length) {
      input.value = "";
      let msg = `Added ${j.added.length} system(s). Polling...`;
      if (j.corrected && j.corrected.length) {
        const fixes = j.corrected.map(x => `${x.input} → ${x.canonical}`).join(", ");
        msg += `\nAuto-corrected: ${fixes}`;
      }
      toast(msg);
    }
    if (j.invalid && j.invalid.length) {
      const lines = j.invalid.map(x => `\u2022 ${x.id}: ${x.reason}`).join("\n");
      toast(`Skipped ${j.invalid.length} invalid:\n${lines}`, true);
    } else if (j.skipped && j.skipped.length && !j.added.length) {
      toast(`Already tracking: ${j.skipped.join(", ")}`, true);
    }
    refresh();
  } catch (e) { toast("Network error: " + e.message, true); }
}

async function removeSystem(id) {
  if (!confirm(`Remove ${id} from tracking?`)) return;
  try {
    const r = await fetch("/api/systems", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({remove: [id]}),
    });
    const j = await r.json();
    if (!r.ok) { toast(j.error || "Remove failed", true); return; }
    toast(`Removed ${id}`);
    refresh();
  } catch (e) { toast("Network error: " + e.message, true); }
}

async function forceRefresh() {
  try {
    await fetch("/api/refresh", {method: "POST"});
    toast("Refresh triggered");
    setTimeout(refresh, 1500);
  } catch (e) { toast("Network error: " + e.message, true); }
}

document.getElementById("filter").addEventListener("input", render);
document.getElementById("sort").addEventListener("change", render);
document.getElementById("days").addEventListener("change", changeWindow);
document.getElementById("btn-add").addEventListener("click", addSystems);
document.getElementById("btn-refresh").addEventListener("click", forceRefresh);
document.getElementById("btn-export-xlsx").addEventListener("click",
  () => exportData("xlsx", null));
document.getElementById("new-ids").addEventListener("keydown", e => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); addSystems(); }
});
document.getElementById("grid").addEventListener("click", e => {
  const t = e.target;
  if (!t || !t.dataset) return;
  if (t.dataset.remove)      { removeSystem(t.dataset.remove); return; }
  if (t.dataset.exportXlsx)  { exportData("xlsx", t.dataset.exportXlsx); return; }
});

function exportData(fmt, id) {
  const params = new URLSearchParams({fmt: fmt, daily: "1"});
  if (id) params.set("ids", id);
  const url = "/api/export?" + params.toString();
  const a = document.createElement("a");
  a.href = url;
  a.download = "";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  toast(id ? `Exporting ${id} as Excel...`
           : `Exporting all tracked systems as Excel...`);
}

refresh();
setInterval(refresh, CLIENT_REFRESH_MS);
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(INDEX_HTML,
                                  poll_interval=POLL_INTERVAL_SEC,
                                  days_window=DAYS_WINDOW)


@app.route("/api/data")
def api_data():
    with _LOCK:
        return jsonify({
            "last_refresh_utc": _LAST_REFRESH_UTC,
            "days_window":      DAYS_WINDOW,
            "systems":          list(_SYSTEMS_CACHE.values()),
            "tracked_ids":      list(_SYSTEM_IDS),
        })


@app.route("/api/window", methods=["GET", "POST"])
def api_window():
    """GET -> {"days": N}.  POST {"days": N} sets the historical window."""
    global DAYS_WINDOW
    from flask import request
    if request.method == "GET":
        return jsonify({"days": DAYS_WINDOW})
    payload = request.get_json(silent=True) or {}
    try:
        n = int(payload.get("days"))
    except (TypeError, ValueError):
        return jsonify({"error": "days must be an integer"}), 400
    if n < 1 or n > 365:
        return jsonify({"error": "days must be between 1 and 365"}), 400
    with _LOCK:
        DAYS_WINDOW = n
    _REFRESH_EVENT.set()
    return jsonify({"days": n})


@app.route("/api/systems", methods=["GET", "POST"])
def api_systems():
    """
    GET  -> {"ids": [...]}
    POST -> body {"add": [...], "remove": [...]}  (either key optional)
            returns {"ids": [...], "added": [...], "removed": [...],
                     "skipped": [...], "invalid": [{id, reason}, ...]}
    """
    from flask import request
    if request.method == "GET":
        with _LOCK:
            return jsonify({"ids": list(_SYSTEM_IDS)})

    payload = request.get_json(silent=True) or {}
    add_raw    = payload.get("add")    or []
    remove_raw = payload.get("remove") or []
    if isinstance(add_raw,    str): add_raw    = [add_raw]
    if isinstance(remove_raw, str): remove_raw = [remove_raw]

    # Snapshot existing IDs (without holding the lock during HTTP calls)
    with _LOCK:
        existing = set(_SYSTEM_IDS)

    # --- Validate each candidate ID against the iConsole inventory API ---
    session = _make_session(_TOKEN_HOLDER["token"])
    to_add: list[str] = []          # canonical IDs to add
    skipped: list[str] = []         # already tracked
    invalid: list[dict] = []        # not found / network error
    corrected: list[dict] = []      # {input, canonical}  - case/whitespace fix
    for raw_sid in add_raw:
        sid = _normalize_id(raw_sid)
        if not sid:
            continue
        if sid in existing or sid in to_add:
            skipped.append(sid)
            continue
        ok, reason, canonical = verify_system_exists(session, sid)
        if ok:
            if canonical != sid:
                corrected.append({"input": sid, "canonical": canonical})
                print(f"[INFO] Auto-corrected '{sid}' -> '{canonical}'")
            if canonical in existing or canonical in to_add:
                skipped.append(canonical)
            else:
                to_add.append(canonical)
        else:
            invalid.append({"id": sid, "reason": reason})
            print(f"[WARN] Refused to add '{sid}': {reason}")

    added: list[str] = []
    removed: list[str] = []
    with _LOCK:
        for sid in to_add:
            if sid not in _SYSTEM_IDS:
                _SYSTEM_IDS.append(sid)
                added.append(sid)
        for raw_sid in remove_raw:
            sid = _normalize_id(raw_sid)
            if sid in _SYSTEM_IDS:
                _SYSTEM_IDS.remove(sid)
                _SYSTEMS_CACHE.pop(sid, None)
                removed.append(sid)
        ids_now = list(_SYSTEM_IDS)

    if added or removed:
        _REFRESH_EVENT.set()
    return jsonify({
        "ids":       ids_now,
        "added":     added,
        "removed":   removed,
        "skipped":   skipped,
        "invalid":   invalid,
        "corrected": corrected,
    })


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    _REFRESH_EVENT.set()
    return jsonify({"ok": True})


# Columns written to the export, in order.
_EXPORT_SUMMARY_COLS = [
    "system_id", "hostname", "state", "activity",
    "processor", "qdf", "val_team", "label",
    "nga_notes", "nga_activity", "domain", "pool", "group",
    "utilization_today", "utilization_avg", "days_window",
    "latest_sample_date", "sample_count",
    "iconsole_url", "fetched_at_utc", "error",
]
_EXPORT_DAILY_COLS = [
    "system_id", "hostname", "date",
    "host_utilization", "sut_utilization", "activity", "processor",
]


def _row_for_summary(r: dict) -> list:
    return [r.get(c, "") for c in _EXPORT_SUMMARY_COLS]


def _rows_for_daily(r: dict) -> list[list]:
    rows = []
    for s in (r.get("daily_samples") or []):
        rows.append([
            r.get("system_id", ""),
            r.get("hostname", ""),
            s.get("date", ""),
            s.get("host_utilization"),
            s.get("sut_utilization"),
            s.get("activity", ""),
            s.get("processor", ""),
        ])
    return rows


def _build_csv(systems: list[dict], include_daily: bool) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["# Summary"])
    w.writerow(_EXPORT_SUMMARY_COLS)
    for r in systems:
        w.writerow(_row_for_summary(r))
    if include_daily:
        w.writerow([])
        w.writerow(["# Daily samples"])
        w.writerow(_EXPORT_DAILY_COLS)
        for r in systems:
            for row in _rows_for_daily(r):
                w.writerow(row)
    return buf.getvalue()


def _build_xlsx(systems: list[dict], include_daily: bool) -> bytes | None:
    """Return XLSX bytes, or None if openpyxl is unavailable."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill
    except ImportError:
        return None
    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    ws.append(_EXPORT_SUMMARY_COLS)
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="2C3E50")
    for r in systems:
        ws.append(_row_for_summary(r))
    # Auto-size-ish (cap at 40)
    for col_cells in ws.columns:
        col_letter = col_cells[0].column_letter
        max_len = max((len(str(c.value)) for c in col_cells if c.value is not None), default=10)
        ws.column_dimensions[col_letter].width = min(max_len + 2, 40)

    if include_daily:
        ws2 = wb.create_sheet("Daily samples")
        ws2.append(_EXPORT_DAILY_COLS)
        for cell in ws2[1]:
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill("solid", fgColor="2C3E50")
        for r in systems:
            for row in _rows_for_daily(r):
                ws2.append(row)
        for col_cells in ws2.columns:
            col_letter = col_cells[0].column_letter
            max_len = max((len(str(c.value)) for c in col_cells if c.value is not None), default=10)
            ws2.column_dimensions[col_letter].width = min(max_len + 2, 40)

    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


@app.route("/api/export")
def api_export():
    """
    Query params:
      fmt   = csv | xlsx   (default: csv)
      ids   = comma-separated system_ids (omit/empty = all tracked)
      daily = 1 to include the daily-samples sheet/section (default: 1)
    """
    fmt   = (request.args.get("fmt") or "csv").lower()
    daily = (request.args.get("daily") or "1").lower() not in ("0", "false", "no")
    ids_raw = request.args.get("ids") or ""
    wanted = {_normalize_id(x) for x in ids_raw.split(",") if x.strip()}

    with _LOCK:
        all_rows = list(_SYSTEMS_CACHE.values())
    rows = [r for r in all_rows if not wanted or r.get("system_id") in wanted]

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = ("iconsole_" + (next(iter(wanted)) if len(wanted) == 1 else
                            ("bulk_" + str(len(rows)) + "sys")))
    fname = f"{base}_{ts}"

    if fmt == "xlsx":
        data = _build_xlsx(rows, daily)
        if data is None:
            # openpyxl missing -> fall back to CSV
            text = _build_csv(rows, daily)
            return Response(text, mimetype="text/csv",
                            headers={"Content-Disposition":
                                     f'attachment; filename="{fname}.csv"',
                                     "X-Export-Fallback": "openpyxl-not-installed"})
        return Response(data,
                        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        headers={"Content-Disposition": f'attachment; filename="{fname}.xlsx"'})

    text = _build_csv(rows, daily)
    return Response(text, mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{fname}.csv"'})


# ---------------------------------------------------------------------------
# System ID input  (always interactive unless --ids provided)
# ---------------------------------------------------------------------------

def collect_system_ids(arg_ids: list[str] | None) -> list[str]:
    if arg_ids:
        ids: list[str] = []
        for raw in arg_ids:
            for piece in str(raw).replace(",", " ").split():
                sid = _normalize_id(piece)
                if sid and sid not in ids:
                    ids.append(sid)
        print(f"[INFO] Using {len(ids)} system IDs from --ids.")
        return ids

    print("\n--- Systems to track ---")
    print("Enter system IDs separated by spaces, commas or newlines.")
    print("Submit a blank line to finish (you can also start empty and add")
    print("systems later from the web UI).")
    ids: list[str] = []
    while True:
        try:
            s = input("  > ").strip()
        except EOFError:
            break
        if not s:
            break
        for piece in s.replace(",", " ").replace(";", " ").split():
            sid = _normalize_id(piece)
            if sid and sid not in ids:
                ids.append(sid)
    print(f"[INFO] Starting with {len(ids)} system(s). "
          f"You can add more from the dashboard.")
    return ids


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global POLL_INTERVAL_SEC, DAYS_WINDOW, _LAST_REFRESH_UTC
    parser = argparse.ArgumentParser(
        description="Real-time iConsole system utilization web dashboard."
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="Host/IP to bind the web server to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000,
                        help="Port for the web server (default: 5000)")
    parser.add_argument("--ids", nargs="*",
                        help="Initial system IDs (skips the interactive prompt).")
    parser.add_argument("--interval", type=int, default=POLL_INTERVAL_SEC,
                        help=f"Background poll interval in seconds (default: {POLL_INTERVAL_SEC})")
    parser.add_argument("--days", type=int, default=DAYS_WINDOW,
                        help=f"Historical utilization window in days (default: {DAYS_WINDOW}).")
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not auto-open the dashboard in the default browser.")
    args = parser.parse_args()

    POLL_INTERVAL_SEC = max(10, int(args.interval))
    DAYS_WINDOW       = max(1, min(365, int(args.days)))

    system_ids = collect_system_ids(args.ids)

    email, password = prompt_credentials()
    print("[INFO] Authenticating...")
    token = login(email, password)
    _TOKEN_HOLDER.update({"token": token, "email": email, "password": password})
    print("[INFO] Authentication OK.")

    # Seed the tracked-ID list (after validating each ID against iConsole)
    valid_ids: list[str] = []
    if system_ids:
        print(f"[INFO] Verifying {len(system_ids)} system ID(s) exist in iConsole...")
        session = _make_session(token)
        for sid in system_ids:
            ok, reason, canonical = verify_system_exists(session, sid)
            if ok:
                if canonical not in valid_ids:
                    valid_ids.append(canonical)
                if canonical != sid:
                    print(f"  [OK]   {sid}  -> {canonical}  (auto-corrected)")
                else:
                    print(f"  [OK]   {sid}")
            else:
                print(f"  [SKIP] {sid}  ({reason})")
        if not valid_ids:
            print("[INFO] No valid IDs supplied at startup. "
                  "You can add systems from the dashboard.")

    with _LOCK:
        _SYSTEM_IDS.extend(valid_ids)

    if valid_ids:
        print(f"[INFO] Priming cache for {len(valid_ids)} system(s) (window={DAYS_WINDOW}d)...")
        session = _make_session(token)
        primed = {sid: fetch_one(session, sid, DAYS_WINDOW) for sid in valid_ids}
        with _LOCK:
            _SYSTEMS_CACHE.update(primed)
            _LAST_REFRESH_UTC = datetime.now(timezone.utc).isoformat(timespec="seconds")

    poller = threading.Thread(target=_poll_loop, name="iconsole-poller", daemon=True)
    poller.start()

    url = f"http://{args.host}:{args.port}"
    # If user bound to 0.0.0.0, open localhost in the browser instead.
    open_url = url.replace("://0.0.0.0:", "://127.0.0.1:")
    print(f"\n[INFO] Dashboard ready: {url}")
    print(f"[INFO] Background poll every {POLL_INTERVAL_SEC}s. "
          f"Historical window: {DAYS_WINDOW} day(s). Ctrl+C to stop.\n")

    if not args.no_browser:
        # Open the browser shortly after the server starts listening.
        def _open():
            time.sleep(1.2)
            try:
                webbrowser.open(open_url, new=2)
                print(f"[INFO] Opened {open_url} in default browser.")
            except Exception as exc:
                print(f"[WARN] Could not auto-open browser: {exc}")
        threading.Thread(target=_open, daemon=True).start()

    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
