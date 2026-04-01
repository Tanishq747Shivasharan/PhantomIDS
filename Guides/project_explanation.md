# PhantomIDS — Complete Project Explanation
### From Scratch to End-to-End (For Oral Preparation)

---

## 1. What is PhantomIDS?

PhantomIDS is a **Hardware-as-a-Service (HaaS) Intrusion Detection System**.

In plain English:
> "It is a physical security device (ESP32 chip) that sits on a company's network, watches all incoming web traffic, and automatically detects + blocks cyber attacks — specifically **SQL Injection attacks**."

### The Big Idea
Most companies use expensive software firewalls (₹5 lakh+/year). We built a cheap hardware alternative using a ₹350 ESP32 chip + free Node.js software. The hardware is **physically separate** from the server — an attacker can't disable it through software.

---

## 2. Project Architecture

```
                                    INTERNET
                                       │
                              Attacker (sqlmap)
                                       │
                               HTTP Request (SQLi)
                                       │
              ┌────────────────────────▼───────────────────────┐
              │             ESP32 Hardware Sensor               │
              │  • Sniffs network packets (promiscuous mode)    │
              │  • Detects SQLi keywords (SELECT, UNION, etc.)  │
              │  • Fires Red LED + Buzzer on detection          │
              │  • Sends alert to Node.js server via Wi-Fi      │
              └────────────────────────┬───────────────────────┘
                                       │ HTTP POST /api/esp32/alert
                                       │
              ┌────────────────────────▼───────────────────────┐
              │           Node.js Backend (Port 5000)           │
              │                                                  │
              │  ┌─────────────────────────────────────────┐   │
              │  │  Threat Detection (Logistic Regression)  │   │
              │  │  • Input: request_rate, threat_count      │   │
              │  │  • Output: P(THREAT) via sigmoid()        │   │
              │  │  • Decision: P ≥ 0.5 → THREAT            │   │
              │  └──────────────────┬──────────────────────┘   │
              │                     │ THREAT label              │
              │  ┌──────────────────▼──────────────────────┐   │
              │  │  Prevention (Rule-Based 3-Strike Engine)  │   │
              │  │  • Count THREAT flags for this IP         │   │
              │  │  • strike_count ≥ 3 → permanently BAN    │   │
              │  └──────────────────────────────────────────┘   │
              │                                                  │
              │  • Stores everything in SQLite database          │
              │  • Serves Admin Dashboard (real-time web UI)     │
              └────────────────────────┬───────────────────────┘
                                       │
              ┌────────────────────────▼───────────────────────┐
              │              Admin Dashboard (Browser)          │
              │  • 4 tabs: Overview / Attack Log / IP Mgmt / ML │
              │  • Real-time stats, attack log, ban/unban IPs   │
              │  • Shows ML model details, accuracy, P(THREAT)   │
              └────────────────────────────────────────────────┘
```

---

## 3. Technology Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Hardware | ESP32 (C++/Arduino) | Cheap, has Wi-Fi, runs 24/7 |
| Backend | Node.js + Express | Fast, JavaScript everywhere |
| Database | SQLite (better-sqlite3) | No setup needed, serverless |
| ML | Logistic Regression (pure JS) | No heavy libraries, academic-friendly |
| Frontend | Vanilla HTML/CSS/JS | No framework needed, loads fast |
| Auth | express-session + bcryptjs | Secure admin login |

---

## 4. Directory Structure — Every File Explained

```
PhantomIDS/
│
├── firmware/                         ← HARDWARE CODE (runs on ESP32 chip)
│   └── IDS_Detection.ino             ← Main ESP32 firmware (C++/Arduino)
│
└── server/                           ← SOFTWARE CODE (runs on laptop/server)
    │
    ├── server.js                     ← Entry point. Starts Express server.
    ├── package.json                  ← Project dependencies + npm scripts
    │
    ├── data/
    │   └── training_data.csv         ← Labeled dataset for training ML model
    │
    ├── src/
    │   ├── db/
    │   │   └── database.js           ← Initializes SQLite. Creates tables.
    │   │
    │   ├── ml/
    │   │   ├── models.js             ← ML engine: Logistic Regression + 3-Strike rule
    │   │   └── model.json            ← Trained model weights saved after training
    │   │
    │   ├── middleware/
    │   │   └── threatDetector.js     ← Runs on EVERY request. Calls ML model.
    │   │
    │   └── routes/
    │       ├── auth.js               ← Login / Logout / Session check
    │       ├── honeypot.js           ← Fake login page + ESP32 alert receiver
    │       ├── dashboard.js          ← All dashboard API routes (/api/stats, etc.)
    │       └── mlStatus.js           ← ML-specific APIs (/api/ml/status, etc.)
    │
    ├── public/
    │   ├── dashboard.html            ← Admin dashboard (full web UI)
    │   ├── index.html                ← Landing page
    │   └── login.html                ← Admin login page
    │
    └── scripts/
        ├── train-model.js            ← ML training script (gradient descent)
        └── attack-sim.js             ← Simulates sqlmap SQL injection attack
```

---

## 5. File-by-File Explanation

### `firmware/IDS_Detection.ino` (ESP32 Hardware)
- Written in C++ using Arduino framework
- Connects to Wi-Fi network
- Sets the network interface to **promiscuous mode** — meaning it reads ALL packets on the network, not just ones addressed to it (like a spy)
- For every HTTP request it sees, it checks the payload for SQL injection keywords: `'`, `UNION`, `SELECT`, `DROP`, `--`, etc.
- If keywords found → scores the packet (higher score = more suspicious)
- Fires **Red LED** (attack detected) or keeps **Green LED** on (monitoring)
- Beeps **Buzzer** on detection
- Sends `POST /api/esp32/alert` to the Node.js server with: attacker IP, payload, score

---

### `server/server.js` (Main Entry Point)
- This is the first file Node.js runs
- It does 4 things:
  1. Initializes the database (creates tables if they don't exist)
  2. Sets up Express middleware (JSON parsing, session handling, threat detector)
  3. Registers all URL routes (honeypot, auth, dashboard, ML)
  4. Starts listening on port 5000
- The **threat detector middleware** is the key — it runs on every single HTTP request automatically

---

### `src/db/database.js` (Database)
- Uses **SQLite** (a file-based database — no MySQL server needed)
- Creates 3 tables:

```sql
TABLE admins          → stores username + bcrypt hashed password
TABLE attack_log      → every detected attack (ip, payload, timestamp, status)
TABLE ip_tracker      → per-IP stats (request_count, threat_count, window_start, status)
```

- `ip_tracker` is the key table — the ML model reads from this table to get request_rate and threat_count

---

### `src/ml/models.js` (ML Engine — MOST IMPORTANT)

This file has two components:

**Component 1: Logistic Regression (Detection)**

```
At server startup:
  → reads model.json from disk
  → loads weights [w1=4.948, w2=3.853] and bias=-2.044

For every new request from an IP:
  Step 1: Get request_rate from ip_tracker table
  Step 2: Normalize: rate_norm = (rate - 1) / (80 - 1)
  Step 3: Normalize: strikes_norm = (strikes - 0) / (3 - 0)
  Step 4: z = 4.948 × rate_norm + 3.853 × strikes_norm − 2.044
  Step 5: P(THREAT) = 1 / (1 + e^−z)        ← sigmoid function
  Step 6: if P ≥ 0.5 → label = THREAT
          else       → label = NORMAL
```

**Component 2: 3-Strike Rule Engine (Prevention)**

```
Input: the label from Logistic Regression
  if label == THREAT:
    strike_count += 1
    if strike_count >= 3:
      → status = BANNED  (permanent)
    else:
      → status = THREAT  (watching)
```

**Why rule-based for prevention?**
> Because banning an IP is an irreversible, high-stakes action. A simple, deterministic rule (3 strikes) is more reliable and transparent than an ML model that might make probabilistic mistakes.

---

### `src/middleware/threatDetector.js` (The Gatekeeper)
- This function runs on literally every HTTP request to the server
- It reads the requester's IP, looks up `ip_tracker`, calls `ML_MODEL_1.predict()`, gets back a label
- If THREAT → increments strike count → calls `ML_MODEL_2` logic → potentially bans
- Logs `[ML-Model1] THREAT flagged` to console with confidence % and reason

---

### `src/routes/honeypot.js` (The Trap)
- Serves a fake corporate login page at `/login` and `/honeypot`
- The login form is **intentionally vulnerable to SQL injection** (uses raw string concatenation)
- Every login attempt (real or malicious) is logged to `attack_log`
- Also handles `POST /api/esp32/alert` — the endpoint the ESP32 hardware calls when it detects an attack
- Has `GET /api/esp32/status` — the dashboard polls this to show sensor ONLINE/OFFLINE

---

### `src/routes/dashboard.js` (Admin APIs)
- All the API endpoints the dashboard JS calls:

| Endpoint | What it returns |
|----------|----------------|
| `GET /api/stats` | Total attacks, unique IPs, banned IPs |
| `GET /api/attacks` | Paginated attack log (with filter) |
| `GET /api/top-ips` | Top attacking IPs by request count |
| `GET /api/timeline` | Hourly attack counts for the chart |
| `GET /api/severity-breakdown` | Count of NORMAL/THREAT/BANNED |
| `POST /api/ban/:ip` | Manually ban an IP |
| `POST /api/unban/:ip` | Manually unban an IP |
| `DELETE /api/clear-logs` | Reset all data |

---

### `src/routes/mlStatus.js` (ML APIs)
- Exposes ML model internals via API:

| Endpoint | Returns |
|----------|---------|
| `GET /api/ml/status` | Model metadata, accuracy, recent bans |
| `GET /api/ml/analyze/:ip` | Full sigmoid calculation for a specific IP |
| `GET /api/ml/feed` | Last 20 THREAT/BANNED IPs with ML reasoning |

---

### `scripts/train-model.js` (Training Pipeline)
- Reads `data/training_data.csv`
- Normalizes features (min-max scaling)
- Trains Logistic Regression using **Gradient Descent** for 3000 epochs
- Saves weights + metrics to `src/ml/model.json`
- Output: Accuracy 86.14%, F1 Score 87.93%

---

### `scripts/attack-sim.js` (Attack Simulator)
- Used for DEMO purposes when real attacker not available
- Fires 22 real sqlmap-style SQL payloads at the honeypot:
  - Boolean blind (`admin' AND 1=1--`)
  - UNION attacks (`' UNION SELECT username,password FROM users--`)
  - Error-based, time-based (SLEEP), stacked queries, etc.
- Runs 3 rounds × 22 payloads = 66 total requests across 4 fake IPs
- With `--esp32` flag, also simulates ESP32 hardware alerts

---

### `public/dashboard.html` (Admin Dashboard)
- 4-tab single-page application:
  - **Overview**: live stat cards, ESP32 sensor status, attack timeline chart, top attackers
  - **Attack Log**: paginated table with SQL payloads, filter by THREAT/BANNED, ban button
  - **IP Management**: all tracked IPs with search, ban/unban per IP
  - **ML Engine**: Logistic Regression details (formula, weights, accuracy), prevention engine, severity pie chart, live threat feed
- Polls APIs every 3-5 seconds for real-time updates

---

## 6. How Data Flows (End to End)

```
1. Attacker sends:  POST /login  {username: "' OR 1=1--"}

2. Express receives request
   ↓
3. threatDetector.js runs (middleware):
   → reads ip_tracker for this IP
   → calls ML_MODEL_1.predict({ requestCount, windowMs, threatCount })
   → sigmoid(4.948 × rate_norm + 3.853 × strikes_norm − 2.044)
   → returns { label: 'THREAT', probability: 0.73, confidence: 0.46 }
   → if THREAT: increment strike_count in ip_tracker
   → if strike_count ≥ 3: UPDATE ip_tracker SET status='BANNED'

4. honeypot.js route handler:
   → logs attack to attack_log table
   → returns HTTP 200 (so attacker thinks they succeeded!)

5. Dashboard (browser):
   → polls /api/stats every 3 seconds
   → sees Total Attacks = 1, Threat IPs = 1
   → shows attack in Attack Log with payload

6. If ESP32 also detected it:
   → ESP32 sends POST /api/esp32/alert
   → dashboard shows ESP32 ONLINE, last ping time
   → Red LED on board is already blinking
```

---

## 7. How to Run the Project

### Prerequisites
- Node.js installed (v18+)
- The `server/node_modules` folder exists (run `npm install` if not)

### Step 1 — Install Dependencies (only once)
```bash
cd C:\Users\JYOTI\Downloads\PhantomIDS\PhantomIDS\server
npm install
```

### Step 2 — Start the Server
```bash
cd C:\Users\JYOTI\Downloads\PhantomIDS\PhantomIDS\server
npm start
```
You'll see the trained model load:
```
[ML-Model1] ✓  Logistic Regression loaded
            Weights → w1=4.948536  w2=3.853035  bias=-2.044437
            Accuracy: 86.14%  |  F1: 87.93%
```

### Step 3 — Open Admin Dashboard
```
http://localhost:5000/login
Username: phantom_admin
Password: PhantomAdmin@2024
```

### Step 4 — Run Attack Simulation (Demo)
Open a **second terminal**:
```bash
cd C:\Users\JYOTI\Downloads\PhantomIDS\PhantomIDS\server
node scripts/attack-sim.js --esp32
```

### Step 5 — Watch Dashboard Update Live
- Stats update every 3 seconds
- Click "ML Engine" tab to see P(THREAT) values
- Click "IP Management" to ban/unban IPs

---

## 8. How to Retrain the Model

Use this when you want to add more training data or improve accuracy.

### Step 1 — Add Data to CSV
Edit `data/training_data.csv`. Add rows in this format:
```csv
request_rate,threat_count,label
5,0,NORMAL
50,3,THREAT
```
Rules for labeling:
- `NORMAL` → request_rate ≤ 20 AND threat_count = 0 (typical safe user)
- `THREAT` → request_rate > 20 OR threat_count ≥ 2 (bot/attacker behavior)

### Step 2 — Train the Model
```bash
cd C:\Users\JYOTI\Downloads\PhantomIDS\PhantomIDS\server
npm run train
# or with custom settings:
node scripts/train-model.js --epochs 5000 --lr 0.05
```

You'll see:
```
Epoch     0 / 3000  →  Loss: 0.691706
Epoch   600 / 3000  →  Loss: 0.472281
...
✓ Accuracy : 86.14%
✓ Weights  : w1=4.949  w2=3.853  bias=-2.044
```

### Step 3 — Restart the Server
```bash
npm start
```
The server automatically loads the new `model.json` on startup.

---

## 9. The Logistic Regression — Step by Step Math

This is what the model computes for every IP request:

**Given:**
- `request_rate` = 50 req/min (fast IP — attacker)
- `threat_count` = 2 (already flagged twice)

**Step 1: Normalize**
```
rate_norm   = (50 - 1) / (80 - 1) = 49 / 79 = 0.620
strike_norm = (2 - 0)  / (3 - 0)  = 2  / 3  = 0.667
```

**Step 2: Linear combination**
```
z = w1 × rate_norm + w2 × strike_norm + bias
z = 4.948 × 0.620 + 3.853 × 0.667 + (−2.044)
z = 3.068 + 2.570 − 2.044
z = 3.594
```

**Step 3: Sigmoid**
```
P(THREAT) = 1 / (1 + e^−3.594)
           = 1 / (1 + 0.0274)
           = 1 / 1.0274
           = 0.973  →  97.3% probability of THREAT
```

**Step 4: Decision**
```
P(THREAT) = 0.973 ≥ 0.5  →  Label = THREAT ✓
```

**Then Rule Engine:**
```
strike_count was 2 → becomes 3
3 ≥ BAN_THRESHOLD (3) → AUTO-BAN triggered ✓
```

---

## 10. Expected Oral Questions & Answers

**Q: Why did you use Logistic Regression and not a Neural Network?**
> Logistic Regression is interpretable — we can explain exactly why an IP was flagged (show the weights, the formula, the probability). Neural networks are black boxes. For a security system, explainability matters. Also, our dataset is small (101 rows) — neural networks would overfit badly.

**Q: What are the two features you used?**
> `request_rate` (requests per minute) and `threat_count` (how many times this IP was previously flagged as THREAT). Together they capture both current behavior and historical reputation.

**Q: What is sigmoid function?**
> `sigmoid(z) = 1 / (1 + e^−z)`. It maps any real number to a value between 0 and 1. We interpret this as a probability — P(THREAT). If z is very negative, output is close to 0 (NORMAL). If z is very positive, output is close to 1 (THREAT).

**Q: What is gradient descent?**
> An optimization algorithm that iteratively adjusts the model's weights to minimize prediction error. In each iteration ("epoch"), we compute how wrong our predictions are (cross-entropy loss), then nudge weights slightly in the direction that reduces that error. After 3000 iterations, the weights converge to optimal values.

**Q: Why is the prevention engine rule-based and not ML?**
> Banning an IP is an irreversible, high-stakes action. A simple deterministic rule (3 strikes = ban) is more reliable, transparent, and fair than a probabilistic ML model that might make errors. The ML model is used for detection (NORMAL/THREAT), but the consequential action (BAN) uses a rule to avoid false positives.

**Q: What happens if the ESP32 goes offline?**
> The Node.js backend runs the threat detection completely independently. The ESP32 is a second layer of hardware confirmation. The system detects attacks in software even without the hardware sensor.

**Q: How accurate is your ML model?**
> 86.14% accuracy on training data, F1 score of 87.93%. The model was trained on 101 labeled samples covering NORMAL IPs (1–20 req/min, 0 strikes) and THREAT IPs (21+ req/min or 2+ strikes).

**Q: What is SQL Injection?**
> SQL Injection is a cyber attack where an attacker puts SQL code inside a web form (like a username field). For example: `' OR 1=1--` in a username field might bypass a login. `' UNION SELECT password FROM users--` might dump the entire database. PhantomIDS detects these patterns.

**Q: What is the role of the honeypot?**
> The honeypot is a fake login page that is deliberately vulnerable. Its purpose is to attract attackers, let them think they're succeeding, while we silently log everything they do — IP address, the exact SQL payload, timestamp. It's a trap.

**Q: What database does PhantomIDS use?**
> SQLite — a lightweight file-based database. No separate database server needed. All data is stored in a single `.db` file. Good for demonstrations and small-scale deployments.

**Q: What is the cost of your hardware?**
> Under ₹800 total:
> - ESP32: ₹350
> - Breadboard: ₹50
> - Red LED + Green LED: ₹20
> - Buzzer: ₹30
> - Resistors + wires: ₹30
>
> Compare this to enterprise WAF solutions that cost ₹5 lakh+/year.
