from flask import Flask, request, render_template, g, jsonify
from flask_cors import CORS
import sqlite3
import logging
import os
import threading
import time
import requests as http_requests
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests from dashboard/admin panel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "honeypot.db")
LOG_PATH = os.path.join(BASE_DIR, "requests.log")

SUPABASE_URL      = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
ORG_ID            = os.getenv("ORG_ID", "")  # The org this sensor belongs to

SUPABASE_HEADERS = {
    "apikey": SUPABASE_ANON_KEY,
    "Authorization": f"Bearer {SUPABASE_ANON_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(message)s"
)
logger = logging.getLogger("honeypot")

# ─────────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA synchronous=NORMAL")
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def get_sync_db():
    """Separate connection for the background sync thread (not Flask's g context)."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

def init_db():
    db = sqlite3.connect(DB_PATH)
    cursor = db.cursor()

    # ── Original honeypot tables ──────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'employee'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attack_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT,
            attacker   TEXT,
            username   TEXT,
            password   TEXT,
            user_agent TEXT,
            result     TEXT
        )
    """)

    # Seed fake users for sqlmap to dump
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        fake_users = [
            ("admin",   "Admin@1234",  "admin"),
            ("john",    "john123",     "employee"),
            ("priya",   "priya@456",   "employee"),
            ("manager", "Mgr#2024",    "manager"),
        ]
        cursor.executemany(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            fake_users
        )
        print("[DB] Seeded fake users into honeypot.db")

    # ── NEW: Cloud sync tables ────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS local_alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            attacker   TEXT NOT NULL,
            timestamp  TEXT NOT NULL,
            payload    TEXT,
            endpoint   TEXT DEFAULT '/login',
            severity   TEXT DEFAULT 'high',
            method     TEXT DEFAULT 'signature',
            synced     INTEGER DEFAULT 0
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS local_threat_ips (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address   TEXT UNIQUE NOT NULL,
            attack_count INTEGER DEFAULT 1,
            first_seen   TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            synced       INTEGER DEFAULT 0
        )
    """)

    db.commit()
    db.close()


# ─────────────────────────────────────────────
# SUPABASE SYNC LOGIC (background thread)
# ─────────────────────────────────────────────

def upsert_threat_ip(conn, ip, timestamp):
    """Insert or increment the attack count for a threat IP in local DB."""
    existing = conn.execute(
        "SELECT id, attack_count FROM local_threat_ips WHERE ip_address = ?", (ip,)
    ).fetchone()

    if existing:
        conn.execute(
            "UPDATE local_threat_ips SET attack_count = attack_count + 1, last_seen = ?, synced = 0 WHERE ip_address = ?",
            (timestamp, ip)
        )
    else:
        conn.execute(
            "INSERT INTO local_threat_ips (ip_address, attack_count, first_seen, last_seen, synced) VALUES (?, 1, ?, ?, 0)",
            (ip, timestamp, timestamp)
        )
    conn.commit()


def sync_to_supabase():
    """Read unsynced rows, push to Supabase, mark synced. Auto-ban IPs >= 3 attacks."""
    if not SUPABASE_URL or not SUPABASE_ANON_KEY or not ORG_ID or ORG_ID == "your-org-uuid-here":
        print("[SYNC] Skipped — ORG_ID not configured in .env")
        return

    conn = get_sync_db()
    try:
        # ── 1. Push unsynced alerts ──────────────────────────
        alerts = conn.execute(
            "SELECT * FROM local_alerts WHERE synced = 0"
        ).fetchall()

        for row in alerts:
            payload = {
                "org_id":           ORG_ID,
                "threat_ip":        row["attacker"],
                "target_endpoint":  row["endpoint"],
                "payload":          row["payload"],
                "detection_method": row["method"],
                "severity":         row["severity"],
                "detected_at":      row["timestamp"],
            }
            resp = http_requests.post(
                f"{SUPABASE_URL}/rest/v1/alert_logs",
                headers=SUPABASE_HEADERS,
                json=payload,
                timeout=10
            )
            if resp.status_code in (200, 201):
                conn.execute(
                    "UPDATE local_alerts SET synced = 1 WHERE id = ?", (row["id"],)
                )
                print(f"[SYNC] Alert #{row['id']} synced ✓")
            else:
                print(f"[SYNC] Alert #{row['id']} failed: {resp.status_code} {resp.text[:120]}")

        conn.commit()

        # ── 2. Push/update threat IPs ────────────────────────
        ips = conn.execute(
            "SELECT * FROM local_threat_ips WHERE synced = 0"
        ).fetchall()

        for row in ips:
            count = row["attack_count"]

            # Upsert into Supabase threat_ips
            payload = {
                "org_id":       ORG_ID,
                "ip_address":   row["ip_address"],
                "attack_count": count,
                "first_seen":   row["first_seen"],
                "last_seen":    row["last_seen"],
                "is_banned":    count >= 3,
                "ban_method":   "automatic" if count >= 3 else None,
                "banned_at":    row["last_seen"] if count >= 3 else None,
            }
            resp = http_requests.post(
                f"{SUPABASE_URL}/rest/v1/threat_ips",
                headers={**SUPABASE_HEADERS, "Prefer": "resolution=merge-duplicates,return=representation"},
                json=payload,
                timeout=10
            )
            if resp.status_code in (200, 201):
                conn.execute(
                    "UPDATE local_threat_ips SET synced = 1 WHERE ip_address = ?", (row["ip_address"],)
                )
                if count >= 3:
                    print(f"[SYNC] IP {row['ip_address']} auto-banned (count={count}) ✓")
                else:
                    print(f"[SYNC] IP {row['ip_address']} updated ✓")
            else:
                print(f"[SYNC] IP {row['ip_address']} failed: {resp.status_code} {resp.text[:120]}")

        conn.commit()

    except Exception as e:
        print(f"[SYNC] Error: {e}")
    finally:
        conn.close()


def sync_loop():
    """Background thread: sync every 30 seconds."""
    while True:
        time.sleep(30)
        print("[SYNC] Running scheduled sync...")
        sync_to_supabase()


# ─────────────────────────────────────────────
# ROUTES — Original Honeypot
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("login.html", message=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", message=None)

    username    = request.form.get("username", "")
    password    = request.form.get("password", "")
    attacker_ip = request.remote_addr
    user_agent  = request.headers.get("User-Agent", "unknown")
    timestamp   = datetime.now(timezone.utc).isoformat()

    log_line = (
        f"[{timestamp}] IP={attacker_ip} | "
        f"user={repr(username)} | pass={repr(password)} | "
        f"UA={user_agent[:60]}"
    )
    logger.info(log_line)
    print(log_line)

    raw_query = (
        f"SELECT * FROM users WHERE username='{username}' "
        f"AND password='{password}'"
    )

    result_message = "Login failed. Invalid credentials."
    query_result   = "FAILED"

    try:
        db     = get_db()
        cursor = db.execute(raw_query)   # Intentionally vulnerable
        user   = cursor.fetchone()

        if user:
            result_message = f"Welcome, {user['username']}! Role: {user['role']}. Login successful."
            query_result   = "SUCCESS"
        else:
            result_message = "Login failed. Invalid credentials."

    except sqlite3.OperationalError as e:
        result_message = f"Database error: {str(e)}"
        query_result   = f"SQL_ERROR: {str(e)}"
        print(f"[SQL ERROR] {e} | payload: username={repr(username)}")

    # Log to attack_log
    try:
        db = get_db()
        db.execute(
            "INSERT INTO attack_log (timestamp, attacker, username, password, user_agent, result) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, attacker_ip, username, password, user_agent[:120], query_result)
        )
        db.commit()
    except Exception as e:
        print(f"[LOG ERROR] Could not write to attack_log: {e}")

    return render_template("login.html", message=result_message)


@app.route("/logs")
def show_logs():
    try:
        db      = get_db()
        entries = db.execute(
            "SELECT * FROM attack_log ORDER BY id DESC LIMIT 50"
        ).fetchall()

        html  = "<h2>Attack Log (last 50)</h2><table border='1' cellpadding='6'>"
        html += "<tr><th>#</th><th>Time</th><th>Attacker IP</th>"
        html += "<th>Username payload</th><th>Password</th><th>Result</th></tr>"

        for row in entries:
            html += (
                f"<tr><td>{row['id']}</td>"
                f"<td>{row['timestamp']}</td>"
                f"<td><b>{row['attacker']}</b></td>"
                f"<td><code>{row['username']}</code></td>"
                f"<td><code>{row['password']}</code></td>"
                f"<td>{row['result']}</td></tr>"
            )
        html += "</table>"
        return html

    except Exception as e:
        return f"Log error: {e}"


# ─────────────────────────────────────────────
# ROUTES — NEW: ESP32 Alert Ingest
# ─────────────────────────────────────────────

@app.route("/api/esp32/alert", methods=["POST"])
def esp32_alert():
    """
    ESP32 POSTs JSON here when it detects a SQLi:
    { "attacker_ip": "192.168.1.7", "payload": "...", "score": 2 }
    """
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    attacker = data.get("attacker_ip", "unknown")
    payload  = data.get("payload",     "")
    score    = data.get("score",       2)
    timestamp = datetime.now(timezone.utc).isoformat()

    severity = "critical" if score >= 2 else "medium"

    try:
        db = get_db()
        db.execute(
            "INSERT INTO local_alerts (attacker, timestamp, payload, severity, method, synced) "
            "VALUES (?, ?, ?, ?, 'signature', 0)",
            (attacker, timestamp, payload, severity)
        )
        db.commit()

        # Also update local threat IP tracking
        upsert_threat_ip(db, attacker, timestamp)
        db.commit()

        print(f"[ESP32] Alert from {attacker} | score={score} | saved locally ✓")
        return jsonify({"status": "ok", "message": "Alert logged"}), 201

    except Exception as e:
        print(f"[ESP32] Error saving alert: {e}")
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# ROUTES — NEW: Manual Sync Trigger
# ─────────────────────────────────────────────

@app.route("/api/sync", methods=["POST"])
def manual_sync():
    """Manually trigger a Supabase sync (useful for testing)."""
    threading.Thread(target=sync_to_supabase, daemon=True).start()
    return jsonify({"status": "ok", "message": "Sync triggered"}), 200


# ─────────────────────────────────────────────
# ROUTES — NEW: Organization Registration
# ─────────────────────────────────────────────

@app.route("/api/register", methods=["POST", "OPTIONS"])
def register_org():
    """
    POST /api/register — Insert a pending registration into Supabase organizations table.
    The landing page calls this directly via the Supabase JS SDK, but this
    Flask endpoint is provided as a fallback.
    """
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "No data provided"}), 400

    required = ["org_name", "contact_name", "work_email"]
    for field in required:
        if not data.get(field):
            return jsonify({"error": f"Missing field: {field}"}), 400

    payload = {
        "org_name":     data.get("org_name"),
        "contact_name": data.get("contact_name"),
        "work_email":   data.get("work_email"),
        "role":         data.get("role", ""),
        "company_size": data.get("company_size", ""),
        "use_case":     data.get("use_case", ""),
        "status":       "pending"
    }

    try:
        resp = http_requests.post(
            f"{SUPABASE_URL}/rest/v1/organizations",
            headers=SUPABASE_HEADERS,
            json=payload,
            timeout=10
        )
        if resp.status_code in (200, 201):
            return jsonify({"status": "ok", "message": "Registration received!"}), 201
        else:
            return jsonify({"error": resp.text}), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  PhantomIDS HONEYPOT + SYNC ENGINE")
    print("  WARNING: Deliberately vulnerable app")
    print("  Run ONLY on isolated lab network")
    print("=" * 55)

    init_db()

    print(f"\n[DB]   honeypot.db ready at: {DB_PATH}")
    print(f"[LOG]  requests.log at:      {LOG_PATH}")
    print(f"[SUPABASE] URL: {SUPABASE_URL or 'NOT SET'}")
    print(f"[SUPABASE] ORG_ID: {ORG_ID or 'NOT SET — alerts will not sync'}")
    print(f"\n[*] Starting on http://0.0.0.0:5000")
    print(f"[*] Honeypot login : http://192.168.1.6:5000/login")
    print(f"[*] Attack log     : http://192.168.1.6:5000/logs")
    print(f"[*] ESP32 alert API: POST http://192.168.1.6:5000/api/esp32/alert")
    print(f"[*] Manual sync    : POST http://192.168.1.6:5000/api/sync")
    print(f"\n[SYNC] Background sync thread starting (every 30s)...\n")

    # Start background sync thread
    sync_thread = threading.Thread(target=sync_loop, daemon=True)
    sync_thread.start()

    app.run(host="0.0.0.0", port=5000, debug=False)