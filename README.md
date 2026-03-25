# PhantomIDS

A network security research project combining a deliberately vulnerable web honeypot with a hardware-based intrusion detection system (IDS) built on the ESP32 microcontroller. The system is designed to attract, log, and detect SQL injection attacks in a controlled lab environment.

---

## Project Overview

PhantomIDS consists of two independent but interconnected components:

1. **Honeypot** — A Flask web application that intentionally exposes a vulnerable login endpoint to lure and record attacker behavior.
2. **IDS (PhantomIDS)** — An ESP32-based hardware device that sits in front of the honeypot, inspects incoming HTTP traffic in real time, and triggers physical alerts when SQL injection payloads are detected.

The two components operate on the same local network. The ESP32 acts as a transparent proxy: it receives all traffic, analyzes it, forwards it to the honeypot, and relays the response back to the client — all without the attacker's knowledge.

---

## Network Architecture

```
Attacker (192.168.1.7)
        |
        | HTTP :5000
        v
  ESP32 PhantomIDS (192.168.1.30)   <-- IDS layer
        |
        | Forwards raw request
        v
  Honeypot Flask App (192.168.1.6:5000)
        |
        | Logs to honeypot.db + requests.log
        v
  Response relayed back to attacker
```

---

## Component 1 — Honeypot (`honeypot_project/`)

### Purpose

The honeypot mimics a corporate employee login portal ("CorpNet Employee Portal v2.1"). It is intentionally built with a raw, unsanitized SQL query to allow tools like `sqlmap` to successfully enumerate and dump the database. This gives attackers a convincing target while every interaction is silently recorded.

### Stack

- Python 3 / Flask
- SQLite3 (WAL mode for concurrent write safety)
- Jinja2 templating

### Database Schema

Two tables are initialized on first run:

**`users`** — Seeded with fake credentials to give sqlmap real data to extract.

| Column   | Type    | Notes                        |
|----------|---------|------------------------------|
| id       | INTEGER | Primary key, autoincrement   |
| username | TEXT    | Fake username                |
| password | TEXT    | Plaintext (intentional)      |
| role     | TEXT    | admin / manager / employee   |

Pre-seeded accounts:

| Username | Password   | Role     |
|----------|------------|----------|
| admin    | Admin@1234 | admin    |
| john     | john123    | employee |
| priya    | priya@456  | employee |
| manager  | Mgr#2024   | manager  |

**`attack_log`** — Every login attempt is recorded here regardless of outcome.

| Column     | Type | Notes                              |
|------------|------|------------------------------------|
| id         | INTEGER | Primary key                    |
| timestamp  | TEXT    | Date and time of the request   |
| attacker   | TEXT    | Source IP address              |
| username   | TEXT    | Raw username field value       |
| password   | TEXT    | Raw password field value       |
| user_agent | TEXT    | Truncated to 120 characters    |
| result     | TEXT    | SUCCESS / FAILED / SQL_ERROR   |

### Vulnerable Query

The login route constructs its SQL query via direct string interpolation — no parameterization, no escaping:

```python
raw_query = (
    f"SELECT * FROM users WHERE username='{username}' "
    f"AND password='{password}'"
)
```

This is the intentional attack surface. Any standard SQLi payload injected into the username or password field will be executed directly against the database.

### Routes

| Route    | Method     | Description                                      |
|----------|------------|--------------------------------------------------|
| `/`      | GET        | Redirects to the login page                      |
| `/login` | GET / POST | Renders login form; processes and logs submissions |
| `/logs`  | GET        | Displays the last 50 attack log entries as HTML  |

### Logging

All requests are logged in two places simultaneously:

- **`requests.log`** — Flat text file with timestamp, IP, username payload, password payload, and User-Agent (first 60 characters).
- **`honeypot.db` → `attack_log` table** — Structured database record with the same fields plus the query result.

### Running the Honeypot

```bash
cd honeypot_project
pip install flask
python honeypot.py
```

The server binds to `0.0.0.0:5000`. On first run it initializes the database and seeds the fake user accounts.

> This application must only be run on an isolated lab or virtual network. It is deliberately insecure and should never be exposed to the internet or any production environment.

---

## Component 2 — Hardware IDS (`SQLI_IDSDETECTION/`)

### Purpose

PhantomIDS is an ESP32-based device that acts as a transparent HTTP proxy and real-time SQL injection detector. It intercepts all traffic destined for the honeypot, analyzes the request body for SQLi indicators, triggers physical alerts (LED, buzzer, LCD), and then forwards the original request to the honeypot unchanged.

### Hardware Requirements

| Component              | Details                              |
|------------------------|--------------------------------------|
| ESP32 development board | Any standard 38-pin variant         |
| 16x2 I2C LCD display   | I2C address `0x27`                   |
| Red LED                | Connected to GPIO 25                 |
| Green LED              | Connected to GPIO 26                 |
| Active buzzer          | Connected to GPIO 13                 |

### Firmware (`IDS_Detection.ino`)

Written in Arduino C++ using the ESP32 Arduino core.

**Libraries required:**
- `WiFi.h` (bundled with ESP32 Arduino core)
- `LiquidCrystal_I2C` (install via Arduino Library Manager)

### Detection Logic

The IDS uses a two-signal scoring system. Each incoming POST request body is URL-decoded and evaluated against two independent checks:

| Signal | Check | Description |
|--------|-------|-------------|
| Signal 1 | Quote detection | Presence of `'` or `"` in the decoded body |
| Signal 2 | Keyword matching | Presence of any SQL keyword from a 20-entry list |

**SQL keyword list:**
`OR`, `AND`, `UNION`, `SELECT`, `INSERT`, `DROP`, `DELETE`, `UPDATE`, `FROM`, `WHERE`, `SLEEP`, `BENCHMARK`, `HAVING`, `ORDER BY`, `--`, `/*`, `#`, `1=1`, `1 =1`, `xp_`

**Scoring thresholds:**

| Score | Classification | Response |
|-------|---------------|----------|
| 0     | Clean         | Green LED on, LCD shows monitoring status |
| 1     | Warning       | Single buzzer beep, brief LCD warning, returns to idle |
| 2     | Critical Alert | Red LED on, triple buzzer burst, LCD shows "SQLI DETECTED" + attacker IP, alert counter incremented |

GET requests are passed through without analysis since they carry no body.

### Proxy Behavior

After analysis, the ESP32 opens a TCP connection to the honeypot, forwards the complete raw HTTP request, waits for the response, and relays it back to the original client. This makes the IDS completely transparent to the attacker — the honeypot still receives and logs every request normally.

If the honeypot is unreachable, the IDS returns a `502 Bad Gateway` response to the client and logs a warning to the serial console.

### LCD Display States

| State | Line 1 | Line 2 |
|-------|--------|--------|
| Boot | `PhantomIDS v1.0` | `Starting...` |
| Armed / Idle | `Monitoring :5000` | `A:<n> W:<n> R:<n>` |
| Warning | `WARN: Suspicious` | `IP:.<last octet>` |
| Critical Alert | `!!SQLI DETECTED!` | `IP:<attacker IP>` |
| Post-alert summary | `Alerts: <n>` | `Warns: <n>` |

### Configuration

Before flashing, update the following constants in `IDS_Detection.ino`:

```cpp
const char* SSID        = "<WiFi Name>";
const char* PASSWORD    = "<WiFi Password>";
const char* HONEYPOT_IP = "192.168.1.6";   // IP of the machine running honeypot.py
```

The ESP32 is configured with a static IP of `192.168.1.30`. Adjust `local_IP`, `gateway`, and `subnet` to match your lab network if needed.

### Serial Monitor Output

The firmware outputs detailed per-request diagnostics at 115200 baud, including the raw and decoded body, extracted username payload, signal score, and alert classification.

---

## IDS Detection Screenshot

The following screenshot shows the PhantomIDS hardware setup and LCD output during an active sqlmap scan against the honeypot:

![PhantomIDS Hardware Detection](SQLI_IDSDETECTION/Screenshot%202026-03-22%20112502.png)

---

## Live Attack Evidence

The `requests.log` file captures a real sqlmap scan session conducted on 2026-03-21. The attacker at `192.168.1.7` ran `sqlmap/1.9.11#stable` against the honeypot login endpoint. The log contains the full enumeration sequence including:

- Initial connection and fingerprinting probes
- Boolean-based blind injection tests (`AND 1=1`, `AND 2860=2860`)
- Error-based injection attempts using `CASE WHEN` expressions
- `RLIKE` regex-based inference payloads
- `CHR()` character-encoding evasion techniques
- Oracle `CTXSYS.DRITHSX.SN` error-based probes
- URL-encoded payloads including XSS and `xp_cmdshell` attempts embedded in query parameters

All of these were captured by the honeypot and simultaneously detected and classified by the ESP32 IDS.

---

## Repository Structure

```
.
├── honeypot_project/
│   ├── honeypot.py          # Flask honeypot application
│   ├── honeypot.db          # SQLite database (auto-created)
│   ├── requests.log         # Flat-file attack log
│   └── templates/
│       └── login.html       # Fake corporate login page
│
└── SQLI_IDSDETECTION/
    ├── IDS_Detection.ino    # ESP32 Arduino firmware
    └── Screenshot 2026-03-22 112502.png
```

---

## Security Notice

This project is built for educational and research purposes in a controlled, isolated lab environment. The honeypot application is deliberately vulnerable. Do not deploy either component on a public network, production system, or any environment outside a dedicated security research lab.
