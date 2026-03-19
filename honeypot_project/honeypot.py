from flask import Flask, request, render_template, g
import sqlite3
import logging
import os
from datetime import datetime

app = Flask(__name__)

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH    = os.path.join(BASE_DIR, "honeypot.db")
LOG_PATH   = os.path.join(BASE_DIR, "requests.log")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(message)s"
)
logger = logging.getLogger("honeypot")

def get_db():

    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")  # WAL = Write-Ahead Log
        g.db.execute("PRAGMA synchronous=NORMAL") # faster writes, still safe
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    cursor = db.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'employee'
        )
    """)

    # Attack log table (stored in DB as well as flat log file)
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

    # Seed some fake users — gives sqlmap real data to dump
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

    db.commit()
    db.close()

# Routes
@app.route("/")
def index():
    """Redirect root to login page."""
    return render_template("login.html", message=None)


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html", message=None)

    username   = request.form.get("username", "")
    password   = request.form.get("password", "")
    attacker_ip = request.remote_addr
    user_agent  = request.headers.get("User-Agent", "unknown")
    timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
        cursor = db.execute(raw_query)   
        user   = cursor.fetchone()

        if user:
            result_message = (
                f"Welcome, {user['username']}! "
                f"Role: {user['role']}. Login successful."
            )
            query_result = "SUCCESS"
        else:
            result_message = "Login failed. Invalid credentials."

    except sqlite3.OperationalError as e:
        result_message = f"Database error: {str(e)}"
        query_result   = f"SQL_ERROR: {str(e)}"
        print(f"[SQL ERROR] {e} | payload: username={repr(username)}")

    try:
        log_db = get_db()
        log_db.execute(
            "INSERT INTO attack_log "
            "(timestamp, attacker, username, password, user_agent, result) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, attacker_ip, username, password,
             user_agent[:120], query_result)
        )
        log_db.commit()
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

        html = "<h2>Attack Log (last 50)</h2><table border='1' cellpadding='6'>"
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


if __name__ == "__main__":
    print("=" * 55)
    print("  SQLi HONEYPOT — NIS Project 316317")
    print("  WARNING: Deliberately vulnerable app")
    print("  Run ONLY on isolated lab network")
    print("=" * 55)

    init_db()   

    print(f"\n[DB]  honeypot.db ready at: {DB_PATH}")
    print(f"[LOG] requests.log at:      {LOG_PATH}")
    print(f"\n[*] Starting on http://0.0.0.0:5000")
    print(f"[*] Login page : http://192.168.1.6:5000/login")
    print(f"[*] Attack log : http://192.168.1.6:5000/logs")
    print(f"\n[*] Waiting for attacks...\n")

    app.run(host="0.0.0.0", port=5000, debug=False)