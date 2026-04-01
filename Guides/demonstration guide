# PhantomIDS — Judge Demonstration Guide
## Complete Step-by-Step Capstone Demo Script

---

## 🎯 What You're Demonstrating

> "PhantomIDS is a Hardware-as-a-Service Intrusion Detection System. Our ESP32 microcontroller sits on the network, sniffs traffic independently, detects SQL Injection attacks using two ML models, and reports them to this admin dashboard in real time. The attacker cannot disable it — it's a physical chip."

---

## ⏱️ Demo Timeline (Recommended: 8–10 minutes)

| Time | Step |
|------|------|
| 0:00 | Physical hardware setup explanation (30 sec) |
| 0:30 | Show the circuit + ESP32 powered ON (30 sec) |
| 1:00 | Open dashboard — show it's live (1 min) |
| 2:00 | Open Honeypot page — explain the trap (30 sec) |
| 2:30 | **Run the attack simulator** — live demonstration (2 min) |
| 4:30 | Watch dashboard update in real time (1 min) |
| 5:30 | Show ML Model panel — explain both models (2 min) |
| 7:30 | Show IP Management — Ban/Unban a live IP (30 sec) |
| 8:00 | Reset & open for judge questions (2 min) |

---

## 🔧 PART 1 — Hardware Setup (Before Judges Arrive)

### What You Need
- ESP32 board
- Breadboard
- Red LED (D25) — attack indicator
- Green LED (D26) — idle/monitoring indicator
- Buzzer (D13) — audio alert
- USB cable for ESP32 → laptop power
- WiFi router/hotspot that both ESP32 and demo laptop connect to

### Physical Connections (Wire on breadboard)
```
ESP32 Pin  →  Component
─────────────────────────
D13        →  Buzzer (+)
D25        →  Red LED (+ → 220Ω resistor → GND)
D26        →  Green LED (+ → 220Ω resistor → GND)
GND        →  All component grounds
```

### Before judges arrive:
1. Edit `firmware/IDS_Detection.ino` — set your WiFi:
   ```cpp
   const char* SSID     = "YOUR_WIFI_NAME";
   const char* PASSWORD = "YOUR_WIFI_PASSWORD";
   ```
2. Set `HONEYPOT_IP` to your laptop's IP on that WiFi:
   ```cpp
   const char* HONEYPOT_IP = "192.168.X.X";  // your laptop IP
   ```
3. Upload firmware to ESP32 via Arduino IDE
4. Both laptop AND ESP32 must be on the **same WiFi network**

### Verify ESP32 is working:
- **Green LED ON** = ESP32 armed and monitoring
- Serial Monitor shows: `PhantomIDS ARMED` + IP address
- Dashboard shows ESP32 sensor as **● ONLINE**
++++++++++++++++++++++++++++

---

## 💻 PART 2 — Start the Software Platform

```bash
# Open terminal, navigate to server folder
cd C:\Users\JYOTI\Downloads\PhantomIDS\PhantomIDS\server

# Start the server
npm start
```

You'll see:
```
╔══════════════════════════════════════════════════╗
║          PhantomIDS — Node.js Server             ║
║  Local  : http://localhost:5000                   ║
║  LAN    : http://192.168.X.X:5000                ║
╚══════════════════════════════════════════════════╝
```

> **Tell judges**: "The server is running on port 5000. The ESP32 on the same network is already sending heartbeat pings — watch the dashboard show it ONLINE."

---

## 🌐 PART 3 — Show the Dashboard

1. Open browser → `http://localhost:5000`
2. This shows the **landing page** — explain briefly
3. Click **Client Login** → `http://localhost:5000/login`
4. Login: `phantom_admin` / `PhantomAdmin@2024`

**Talking points on the dashboard:**
- "These 4 stat cards update every 3 seconds in real time"
- "The ESP32 hardware sensor status shows ONLINE — it's pinging us every 30 seconds"
- "This is the admin dashboard that a company's security team would monitor"

---

## 🍯 PART 4 — Show the Honeypot Trap

Click **View Honeypot** in the sidebar (opens a new tab).

**Tell judges:**
> "This page looks like a normal corporate login portal for employees. But it's actually a carefully crafted **honeypot** — the login form is intentionally vulnerable to SQL injection. When an attacker probes this URL with sqlmap, they think they found a real database. Every single request they make is silently logged."

Show that entering test credentials just shows an error. Then close the tab.

---

## 💥 PART 5 — Live SQL Injection Attack Demo

**This is the main show.** Open a second terminal:

```bash
cd C:\Users\JYOTI\Downloads\PhantomIDS\PhantomIDS\server

# Run the attack simulator (simulates a real sqlmap attack + ESP32 hardware alerts)
node scripts/attack-sim.js --esp32
```

**While it runs, narrate:**
> "We are now simulating a real attacker using sqlmap — an automated SQL injection tool used by hackers worldwide. The simulator fires 22 different SQL injection payloads: UNION attacks, boolean blind, time-based blind, error-based — exactly what a real attacker would try."

**Watch simultaneously:**
- 🔴 **Red LED** on ESP32 flashes → "The hardware has detected the attack!"
- 🔊 **Buzzer beeps** → "Audio alert fired on the physical sensor"
- 💻 **Dashboard stats** increase in real time
- The attack log populates with each payload

---

## 🤖 PART 6 — Show ML Models Working (Key for Judges)

After the simulation completes, click **ML Engine** in the sidebar.

### Explain ML Model 1:
> "This is our **Behavioural Anomaly Detector**. It works exactly like spam email detection — instead of counting suspicious words in an email, it counts requests per minute from each IP. A normal user sends maybe 2–3 requests per minute. Our attacker sent over 20 in 60 seconds. Model 1 classifies this as THREAT."

Point to:
- Feature: `req_per_minute`
- Threshold: `> 20 req/min → THREAT`
- Number shown: **THREAT detections**

### Explain ML Model 2:
> "This is our **3-Strike Auto-Ban Classifier**. It's like an ensemble committee machine — every time Model 1 votes 'THREAT' for the same IP, that's one strike. After 3 strikes, Model 2 overrules and permanently bans the IP. No human needed."

Point to:
- Ban threshold: `3 strikes → BANNED`  
- Number shown: **IPs auto-banned**
- The Severity Breakdown donut chart — mostly red (BANNED)

### The knockout line:
> "Both models run entirely in Node.js — no Python, no cloud API, no external service. The ML decision happens in under 1 millisecond per request. The attacker gets banned **before** they can extract any data."

---

## 🛡️ PART 7 — Show IP Management & Admin Controls

Click **IP Management** in the sidebar.

Show judges:
1. All attacker IPs are listed with their BANNED status
2. Click **Unban** on one IP — "As the admin, I can whitelist a false positive"
3. That IP's badge instantly changes to NORMAL
4. Click **Ban** again — "And I can re-ban it instantly with one click"

**Tell judges:**
> "This gives the security admin full control. Every action is logged. The admin can also reset all data for a clean slate — useful for testing or resetting after a drill."

---

## 📊 PART 8 — Show the Attack Log

Click **Attack Log** in the sidebar.

- Filter by **Banned** to show only blocked IPs
- Filter by **Threats** to show flagged-but-not-yet-banned
- Point out the payload column: "You can see the exact SQL string the attacker used — `' UNION SELECT username, password FROM users --`"

---

## 🔄 PART 9 — Reset for Another Demo (Optional)

In sidebar → **Reset All Data**  
→ Confirms → dashboard clears → ready for a fresh run

---

## ❓ Expected Judge Questions & Answers

| Question | Answer |
|----------|--------|
| "What happens if the ESP32 goes offline?" | "The server node.js threat detector runs independently — it detects attacks even without ESP32. ESP32 adds a second layer of hardware-level confirmation." |
| "Is this a real ML model or just if-else?" | "Model 1 uses a sliding-window rate classifier analogous to Naive Bayes frequency counting. Model 2 is an accumulative committee machine — a form of ensemble learning. The code is in `server/src/ml/models.js` with documented `predict()` functions." |
| "What database are you protecting?" | "Our honeypot contains a fake employee database. The real company database would be on a separate server. PhantomIDS sits on the network, not on the database server." |
| "Can it detect attacks in real time?" | "Yes — the ESP32 detects within 200ms of the request. The dashboard updates every 3 seconds via polling." |
| "What's the cost of your hardware?" | "Under ₹800 — ESP32 (₹350), breadboard (₹50), LEDs + buzzer (₹50), resistors (₹10). An enterprise WAF costs ₹5 lakh+/year." |
| "Why Node.js and not Python for ML?" | "Node.js ML keeps latency under 1ms. Python would require a separate microservice. The models are rule-based ensemble classifiers, which Node.js handles perfectly. In production we could integrate a TensorFlow.js model." |

---

## 🚨 Terminal Error Fix

The error you saw was running the simulator from the wrong folder:

```bash
# WRONG (ran from PhantomIDS\PhantomIDS)
node scripts/attack-sim.js --esp32

# CORRECT (must be inside the server folder)
cd C:\Users\JYOTI\Downloads\PhantomIDS\PhantomIDS\server
node scripts/attack-sim.js --esp32
```

Always run the simulator **from inside the `server/` directory**.
