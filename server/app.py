"""Torn Raffles backend.

GitHub Pages can only serve static files, so everything that must be shared and
trustworthy (roles, who is included, the event log, and later the prize draws
themselves) lives here. Every permission is enforced on this side; the page only
reflects what the server allows.

API keys are used once at login to ask Torn who the person is, then forgotten.
They are never written to disk or logged.

The log is append-only: SQLite triggers refuse UPDATE/DELETE, and each entry
carries a SHA-256 of itself plus the previous entry, so any later edit to the
database breaks the chain and shows up on the Log tab.

Environment:
  RAFFLES_ADMIN_ID        Torn player ID of the admin (required)
  RAFFLES_ALLOWED_ORIGIN  comma separated origins allowed to call the API
  RAFFLES_DATA_DIR        folder holding raffles.db
  RAFFLES_TORN_BASE       Torn API base URL (overridden only for testing)
"""

import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from functools import wraps

from flask import Flask, g, jsonify, request

ADMIN_ID = int(os.environ["RAFFLES_ADMIN_ID"])
ALLOWED_ORIGINS = {o.strip() for o in os.environ.get(
    "RAFFLES_ALLOWED_ORIGIN", "https://lordxerra.github.io").split(",") if o.strip()}
DATA_DIR = os.environ.get("RAFFLES_DATA_DIR", "data")
TORN_BASE = os.environ.get("RAFFLES_TORN_BASE", "https://api.torn.com/v2")
DB_PATH = os.path.join(DATA_DIR, "raffles.db")

KEY_RE = re.compile(r"^[A-Za-z0-9]{16}$")
SESSION_SECONDS = 12 * 3600
ROSTER_MAX_AGE = 60             # seconds between roster refreshes from Torn
FAIL_WINDOW = 600               # repeated bad keys can get the NAS IP blocked by
FAIL_LIMIT_IP = 10              # Torn, which would also take War Codex down, so
FAIL_LIMIT_ALL = 30             # failed logins are capped per IP and overall
LOG_PAGE = 500
HISTORY_PAGE = 50
MAX_PRIZES = 10
MAX_PRIZE_LENGTH = 60
GENESIS = "0" * 64

app = Flask(__name__)
write_lock = threading.Lock()
fail_lock = threading.Lock()
failures = {}                   # ip -> deque of timestamps
all_failures = deque()


class TornError(Exception):
    def __init__(self, message, status=502):
        super().__init__(message)
        self.message = message
        self.status = status


# ---------------------------------------------------------------- database

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS members (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    level INTEGER,
    position TEXT,
    role TEXT NOT NULL DEFAULT 'member',
    included INTEGER NOT NULL DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    member_id INTEGER NOT NULL,
    expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS log (
    seq INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    actor_id INTEGER,
    actor_name TEXT,
    action TEXT NOT NULL,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS log_no_update BEFORE UPDATE ON log
    BEGIN SELECT RAISE(ABORT, 'log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS log_no_delete BEFORE DELETE ON log
    BEGIN SELECT RAISE(ABORT, 'log is append-only'); END;
"""


def connect():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


def db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = connect()
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.close()


def get_setting(key):
    row = db().execute("SELECT v FROM settings WHERE k=?", (key,)).fetchone()
    return row["v"] if row else None


def set_setting(key, value):
    db().execute("INSERT INTO settings(k,v) VALUES(?,?) "
                 "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, str(value)))


# ---------------------------------------------------------------- event log

def entry_hash(seq, ts, actor_id, actor_name, action, detail, prev_hash):
    payload = json.dumps([seq, ts, actor_id, actor_name, action, detail, prev_hash],
                         separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def add_log(action, detail, actor_id=None, actor_name=None):
    """Append to the chain. Call with write_lock held; the caller commits."""
    last = db().execute("SELECT seq, hash FROM log ORDER BY seq DESC LIMIT 1").fetchone()
    seq = last["seq"] + 1 if last else 1
    prev_hash = last["hash"] if last else GENESIS
    ts = int(time.time())
    text = json.dumps(detail, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
    digest = entry_hash(seq, ts, actor_id, actor_name, action, text, prev_hash)
    db().execute("INSERT INTO log(seq,ts,actor_id,actor_name,action,detail,prev_hash,hash) "
                 "VALUES(?,?,?,?,?,?,?,?)",
                 (seq, ts, actor_id, actor_name, action, text, prev_hash, digest))


def verify_chain():
    prev_hash = GENESIS
    expected = 1
    for row in db().execute("SELECT * FROM log ORDER BY seq"):
        digest = entry_hash(row["seq"], row["ts"], row["actor_id"], row["actor_name"],
                            row["action"], row["detail"], prev_hash)
        if row["seq"] != expected or row["prev_hash"] != prev_hash or row["hash"] != digest:
            return {"ok": False, "broken_at": row["seq"]}
        prev_hash = row["hash"]
        expected += 1
    return {"ok": True, "entries": expected - 1, "head": prev_hash}


# ---------------------------------------------------------------- Torn API

def torn_get(path, key):
    # The key goes in a header, not the URL, so it can't end up in any log.
    # Torn's Cloudflare rejects urllib's default User-Agent.
    req = urllib.request.Request(f"{TORN_BASE}{path}?comment=TornRaffles",
                                 headers={"Authorization": f"ApiKey {key}",
                                          "User-Agent": "TornRaffles/0.01",
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            data = json.loads(res.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError):
        raise TornError("Couldn't reach the Torn API. Try again in a moment.") from None
    if isinstance(data, dict) and "error" in data:
        code = data["error"].get("code")
        if code == 2:
            raise TornError("Torn says that API key is incorrect.", 401)
        if code == 5:
            raise TornError("Torn rate limit reached. Wait a minute and try again.", 429)
        if code in (10, 13, 18):
            raise TornError("That key is paused or its owner is inactive or in federal jail.", 401)
        raise TornError(f"Torn API error: {data['error'].get('error', 'unknown')}")
    return data


def fetch_profile(key):
    profile = torn_get("/user/profile", key).get("profile") or {}
    if not profile.get("id"):
        raise TornError("Torn returned no profile for that key.")
    return profile


def sync_roster(key, faction_id, force=False):
    """Bring members in line with Torn. Call with write_lock held; caller commits."""
    last = float(get_setting("roster_synced") or 0)
    if not force and time.time() - last < ROSTER_MAX_AGE:
        return
    fetched = torn_get(f"/faction/{faction_id}/members", key).get("members") or []
    if not fetched:
        return      # never treat an empty reply as everyone having left

    known = {r["id"]: r for r in db().execute("SELECT * FROM members")}
    first_run = not known
    seen = set()
    for m in fetched:
        pid = int(m["id"])
        seen.add(pid)
        name, level, position = m.get("name") or str(pid), m.get("level"), m.get("position")
        role = "admin" if pid == ADMIN_ID else "member"
        row = known.get(pid)
        if row is None:
            db().execute("INSERT INTO members(id,name,level,position,role) VALUES(?,?,?,?,?)",
                         (pid, name, level, position, role))
            if not first_run:
                add_log("member.joined", {"id": pid, "name": name})
        else:
            db().execute("UPDATE members SET name=?, level=?, position=?, active=1 WHERE id=?",
                         (name, level, position, pid))
            if not row["active"]:
                add_log("member.joined", {"id": pid, "name": name})

    for pid, row in known.items():
        if row["active"] and pid not in seen:
            db().execute("UPDATE members SET active=0, included=0, role='member' WHERE id=?", (pid,))
            db().execute("DELETE FROM sessions WHERE member_id=?", (pid,))
            add_log("member.left", {"id": pid, "name": row["name"]})

    if first_run:
        add_log("roster.created", {"faction_id": faction_id, "members": len(seen)})
    set_setting("roster_synced", time.time())


# ---------------------------------------------------------------- HTTP plumbing

@app.after_request
def add_cors(res):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        res.headers["Access-Control-Allow-Origin"] = origin
        res.headers["Vary"] = "Origin"
        res.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        res.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return res


@app.errorhandler(TornError)
def on_torn_error(err):
    return jsonify(error=err.message), err.status


def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() or request.remote_addr or "?"


def too_many_failures(ip):
    cutoff = time.time() - FAIL_WINDOW
    with fail_lock:
        while all_failures and all_failures[0] < cutoff:
            all_failures.popleft()
        hits = failures.get(ip)
        while hits and hits[0] < cutoff:
            hits.popleft()
        return len(all_failures) >= FAIL_LIMIT_ALL or (hits and len(hits) >= FAIL_LIMIT_IP)


def record_failure(ip):
    now = time.time()
    with fail_lock:
        all_failures.append(now)
        failures.setdefault(ip, deque()).append(now)


def current_member():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    digest = hashlib.sha256(header[7:].encode()).hexdigest()
    return db().execute(
        "SELECT m.* FROM sessions s JOIN members m ON m.id = s.member_id "
        "WHERE s.token_hash=? AND s.expires>? AND m.active=1",
        (digest, int(time.time()))).fetchone()


def require(*roles):
    """Allow any signed-in member, or only the given roles."""
    def wrap(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            me = current_member()
            if me is None:
                return jsonify(error="Please sign in again."), 401
            if roles and me["role"] not in roles:
                return jsonify(error="You don't have permission to do that."), 403
            g.me = me
            return fn(*args, **kwargs)
        return inner
    return wrap


def member_json(row):
    return {"id": row["id"], "name": row["name"], "level": row["level"],
            "position": row["position"], "role": row["role"], "included": bool(row["included"])}


def state_json(me):
    rows = db().execute("SELECT * FROM members WHERE active=1 ORDER BY name COLLATE NOCASE")
    return {
        "me": member_json(me),
        "faction": {"id": int(get_setting("faction_id")), "name": get_setting("faction_name")},
        "members": [member_json(r) for r in rows],
    }


# ---------------------------------------------------------------- routes

@app.route("/api/health")
def health():
    return jsonify(ok=True)


@app.route("/api/login", methods=["POST"])
def login():
    ip = client_ip()
    if too_many_failures(ip):
        return jsonify(error="Too many failed sign-ins. Try again in a few minutes."), 429

    key = str((request.get_json(silent=True) or {}).get("key", "")).strip()
    if not KEY_RE.match(key):
        return jsonify(error="An API key is 16 letters and numbers."), 400

    try:
        profile = fetch_profile(key)
    except TornError as err:
        if err.status == 401:
            record_failure(ip)
        raise
    player_id = int(profile["id"])
    player_name = profile.get("name") or str(player_id)
    player_faction = int(profile.get("faction_id") or 0)

    with write_lock:
        faction_id = int(get_setting("faction_id") or 0)
        if player_id == ADMIN_ID:
            if not player_faction:
                return jsonify(error="You aren't in a faction according to Torn."), 403
            if player_faction != faction_id:
                info = torn_get(f"/faction/{player_faction}/basic", key).get("basic") or {}
                set_setting("faction_id", player_faction)
                set_setting("faction_name", info.get("name") or "")
                add_log("faction.set", {"faction_id": player_faction, "name": info.get("name")},
                        player_id, player_name)
                faction_id = player_faction
                set_setting("roster_synced", 0)
        elif not faction_id:
            return jsonify(error="The site isn't set up yet. The admin needs to sign in first."), 403
        elif player_faction != faction_id:
            record_failure(ip)
            add_log("login.refused", {"id": player_id, "name": player_name,
                                      "faction_id": player_faction}, player_id, player_name)
            db().commit()
            return jsonify(error=f"This site is only for members of {get_setting('faction_name')}."), 403

        known = db().execute("SELECT id FROM members WHERE id=? AND active=1",
                             (player_id,)).fetchone()
        sync_roster(key, faction_id, force=known is None)
        me = db().execute("SELECT * FROM members WHERE id=? AND active=1", (player_id,)).fetchone()
        if me is None:
            db().commit()
            return jsonify(error="Torn doesn't list you in the faction yet. Try again shortly."), 403

        token = secrets.token_urlsafe(32)
        db().execute("DELETE FROM sessions WHERE expires<?", (int(time.time()),))
        db().execute("INSERT INTO sessions(token_hash,member_id,expires) VALUES(?,?,?)",
                     (hashlib.sha256(token.encode()).hexdigest(), player_id,
                      int(time.time()) + SESSION_SECONDS))
        db().commit()
    return jsonify(token=token, **state_json(me))


@app.route("/api/state")
@require()
def state():
    return jsonify(state_json(g.me))


@app.route("/api/log")
@require()
def log_view():
    rows = db().execute("SELECT * FROM log ORDER BY seq DESC LIMIT ?", (LOG_PAGE,)).fetchall()
    entries = [{"seq": r["seq"], "ts": r["ts"], "actor_id": r["actor_id"],
                "actor_name": r["actor_name"], "action": r["action"],
                "detail": json.loads(r["detail"]), "hash": r["hash"]} for r in rows]
    return jsonify(entries=entries, chain=verify_chain())


@app.route("/api/members/<int:member_id>/role", methods=["POST"])
@require("admin")
def set_role(member_id):
    role = (request.get_json(silent=True) or {}).get("role")
    if role not in ("member", "planner"):
        return jsonify(error="Role must be member or planner."), 400
    with write_lock:
        target = db().execute("SELECT * FROM members WHERE id=? AND active=1",
                              (member_id,)).fetchone()
        if target is None:
            return jsonify(error="That player isn't in the faction."), 404
        if target["role"] == "admin":
            return jsonify(error="The admin's role can't be changed."), 400
        if target["role"] != role:
            db().execute("UPDATE members SET role=? WHERE id=?", (role, member_id))
            add_log("role.changed", {"id": member_id, "name": target["name"],
                                     "from": target["role"], "to": role},
                    g.me["id"], g.me["name"])
            db().commit()
    return jsonify(state_json(g.me))


@app.route("/api/members/<int:member_id>/included", methods=["POST"])
@require("admin", "planner")
def set_included(member_id):
    included = 1 if (request.get_json(silent=True) or {}).get("included") else 0
    with write_lock:
        target = db().execute("SELECT * FROM members WHERE id=? AND active=1",
                              (member_id,)).fetchone()
        if target is None:
            return jsonify(error="That player isn't in the faction."), 404
        if target["included"] != included:
            db().execute("UPDATE members SET included=? WHERE id=?", (included, member_id))
            add_log("included.changed", {"id": member_id, "name": target["name"],
                                         "included": bool(included)},
                    g.me["id"], g.me["name"])
            db().commit()
    return jsonify(state_json(g.me))


@app.route("/api/members/included", methods=["POST"])
@require("admin", "planner")
def set_all_included():
    included = 1 if (request.get_json(silent=True) or {}).get("included") else 0
    with write_lock:
        changed = db().execute("UPDATE members SET included=? WHERE active=1 AND included<>?",
                               (included, included)).rowcount
        if changed:
            add_log("included.all", {"included": bool(included), "changed": changed},
                    g.me["id"], g.me["name"])
            db().commit()
    return jsonify(state_json(g.me))


def event_json(row):
    return {"seq": row["seq"], "ts": row["ts"], "actor_name": row["actor_name"],
            "detail": json.loads(row["detail"]), "hash": row["hash"]}


@app.route("/api/wheel/spin", methods=["POST"])
@require("admin", "planner")
def wheel_spin():
    """Draw every winner at once and seal them in the log before anything animates.

    The wheel on the page only replays this result, so nobody can stop a run or
    re-roll after seeing an early winner they don't like.
    """
    body = request.get_json(silent=True) or {}
    raw = body.get("prizes")
    prizes = [str(p).strip() for p in raw if str(p).strip()] if isinstance(raw, list) else []
    unique = bool(body.get("unique"))
    if not 1 <= len(prizes) <= MAX_PRIZES:
        return jsonify(error=f"Enter between 1 and {MAX_PRIZES} prizes."), 400
    if any(len(p) > MAX_PRIZE_LENGTH for p in prizes):
        return jsonify(error=f"Prizes can be up to {MAX_PRIZE_LENGTH} characters."), 400

    with write_lock:
        rows = db().execute("SELECT id, name FROM members WHERE active=1 AND included=1 "
                            "ORDER BY name COLLATE NOCASE").fetchall()
        entrants = [{"id": r["id"], "name": r["name"]} for r in rows]
        if not entrants:
            return jsonify(error="Tick at least one member first."), 400
        if unique and len(entrants) < len(prizes):
            return jsonify(error=f"{len(prizes)} prizes but only {len(entrants)} entrants "
                                 "who can each win once."), 400
        rng = secrets.SystemRandom()
        winners = (rng.sample(entrants, len(prizes)) if unique
                   else [rng.choice(entrants) for _ in prizes])
        results = [{"prize": prize, **winner} for prize, winner in zip(prizes, winners)]
        add_log("wheel.spun", {"entrants": entrants, "results": results, "unique": unique},
                g.me["id"], g.me["name"])
        db().commit()
        row = db().execute("SELECT * FROM log ORDER BY seq DESC LIMIT 1").fetchone()
    return jsonify(event_json(row))


@app.route("/api/wheel/history")
@require()
def wheel_history():
    rows = db().execute("SELECT * FROM log WHERE action='wheel.spun' ORDER BY seq DESC LIMIT ?",
                        (HISTORY_PAGE,)).fetchall()
    return jsonify(events=[event_json(r) for r in rows])


init_db()
