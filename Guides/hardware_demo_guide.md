# PhantomIDS — Hardware Connection & Live Demo Guide
## Full Step-by-Step: From Zero to Working Hardware + Software

---

## 🧰 What You Need (Checklist)

Before starting, make sure you have ALL of these:

| Component | Qty | Purpose |
|-----------|-----|---------|
| ESP32 Development Board | 1 | The brain — network sniffer |
| Breadboard | 1 | Holds all components |
| Red LED | 1 | Attack detected indicator |
| Green LED | 1 | Idle / monitoring indicator |
| Active Buzzer (not piezo) | 1 | Audio alert on attack |
| 220Ω Resistors | 2 | Protect LEDs from burning |
| Jumper Wires | ~10 | Connections |
| USB-A to Micro-USB cable | 1 | Power + upload code to ESP32 |
| Laptop with Arduino IDE | 1 | Upload firmware |
| WiFi Router / Mobile Hotspot | 1 | Both ESP32 + laptop on same network |

---

## ⚡ PHASE 1 — Wire the Circuit

### Pin Connections (ESP32 → Component)

```
ESP32 Pin    →    Component
──────────────────────────────────────────────────
GPIO 13      →    Buzzer (+) positive leg
GPIO 25      →    Red LED (+) → 220Ω resistor → GND
GPIO 26      →    Green LED (+) → 220Ω resistor → GND
GND (any)   →    Buzzer (−) negative leg
GND (any)   →    Both LED resistor other ends
```

### Breadboard Layout (Visual)

```
  ESP32
  ┌─────────┐
  │  GPIO13 ├──────────────────────→ [BUZZER +]
  │  GPIO25 ├──→ [220Ω] ──→ [RED LED +]
  │  GPIO26 ├──→ [220Ω] ──→ [GREEN LED +]
  │     GND ├──────────────────────→ [All – legs] 
  └─────────┘
```

### Important: Buzzer Type
- Use an **Active Buzzer** (has a built-in oscillator — just give it power and it beeps)
- Passive buzzer needs PWM signal and won't work with this code
- Active buzzer: one leg is + (longer / marked), other is −

### Quick Check Before Powering
- Red LED long leg → resistor → GPIO 25
- Green LED long leg → resistor → GPIO 26
- Buzzer + leg → GPIO 13
- All – legs → any GND pin on ESP32

---

## 💻 PHASE 2 — Set Up Arduino IDE on Your Laptop

### Step 1: Install Arduino IDE
- Download from: https://www.arduino.cc/en/software
- Install version 2.x (latest)

### Step 2: Add ESP32 Board Support
1. Open Arduino IDE
2. Go to **File → Preferences**
3. In "Additional boards manager URLs" paste:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
4. Click OK
5. Go to **Tools → Board → Boards Manager**
6. Search **esp32**
7. Install **"esp32 by Espressif Systems"** (version 2.x)

### Step 3: Install Required Library
The firmware uses an LCD display library:
1. Go to **Tools → Manage Libraries**
2. Search: **LiquidCrystal I2C**
3. Install: **"LiquidCrystal I2C" by Frank de Brabander**

> ⚠️ If you don't have an LCD display, that's okay — just comment out the LCD lines. See Phase 3 Step 3.

### Step 4: Select Your Board
1. Connect ESP32 to laptop via USB
2. Go to **Tools → Board → ESP32 Arduino → ESP32 Dev Module**
3. Go to **Tools → Port** → select the COM port that appeared (e.g., COM3, COM4)
   - If no port appears: install CP210x USB driver from: https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers

---

## 🔧 PHASE 3 — Configure the Firmware

### Step 1: Find Your Laptop's IP Address

**On Windows:**
```
Press Win + R → type cmd → Enter
Then type: ipconfig
```

Look for your **WiFi adapter** section:
```
Wireless LAN adapter Wi-Fi:
   IPv4 Address. . . . : 192.168.1.13   ← THIS IS YOUR LAPTOP IP
```

Write this number down. You will put it in the firmware.

### Step 2: Update WiFi Settings in the .ino File

Open `firmware/IDS_Detection.ino` in Arduino IDE.

Change **lines 5, 6, and 7**:

```cpp
// Line 5: Your WiFi name EXACTLY (case sensitive)
const char* SSID = "YOUR_WIFI_NAME";

// Line 6: Your WiFi password
const char* PASSWORD = "YOUR_WIFI_PASSWORD";

// Line 7: YOUR LAPTOP'S IP ADDRESS (from ipconfig above)
const char* HONEYPOT_IP = "192.168.1.13";   // ← replace with your actual IP
```

> ⚠️ Critical: Both ESP32 and your laptop MUST be on the same WiFi network.
> If you use a mobile hotspot, connect your laptop to the hotspot too.

### Step 3: If No LCD Display (Optional Fix)
If you don't have an I2C LCD, comment out these lines to avoid errors:

Find and add `//` in front of every `lcd.` line. For example:
```cpp
// lcd.init();
// lcd.backlight();
// lcd.setCursor(0, 0); lcd.print("PhantomIDS ARMED");
```

Or easier: just leave them — the code will still work, LCD lines will just be ignored if hardware isn't there (it may show some warning but won't crash).

---

## 📤 PHASE 4 — Upload Firmware to ESP32

### Step 1: Open the File
- In Arduino IDE: **File → Open**
- Navigate to: `C:\Users\JYOTI\Downloads\PhantomIDS\PhantomIDS\firmware\IDS_Detection.ino`

### Step 2: Verify (Compile)
- Click the ✓ (checkmark) button in Arduino IDE
- Wait for "Done compiling" message
- If errors: check that esp32 board package and LiquidCrystal_I2C library are installed

### Step 3: Upload
- Click the → (right arrow / Upload) button
- You'll see "Connecting..." in the console
- **If it gets stuck on "Connecting...":**
  - Hold the **BOOT button** on the ESP32 while clicking Upload
  - Release BOOT when you see "Uploading..." in the console
- Wait for: "Done uploading" ✅

### Step 4: Open Serial Monitor
- Go to **Tools → Serial Monitor**
- Set baud rate to **115200** (bottom right dropdown)
- You should see:
  ```
  ========================================
    PhantomIDS — FULL IDS + CLOUD MODE
  ========================================
  [WiFi] Connecting.....
  [WiFi] Connected! IP: 192.168.1.30
  [WiFi] RSSI: -45 dBm
  [IDS]  Detection engine  : ACTIVE
  [PING] Heartbeat sent to server ✓
  ```

> ✅ If you see "Connected!" and "Heartbeat sent" — ESP32 is working!
> ❌ If you see "WiFi FAILED" — wrong WiFi name/password in the firmware

---

## 🖥️ PHASE 5 — Start the Node.js Server

On your laptop, open a terminal (PowerShell or Command Prompt):

```bash
cd C:\Users\JYOTI\Downloads\PhantomIDS\PhantomIDS\server
npm start
```

You'll see:
```
[ML-Model1] ✓  Logistic Regression loaded
            Weights → w1=4.948  w2=3.853  bias=-2.044
            Accuracy: 86.14%
╔══════════════════════════════════════════════════╗
║  Local  : http://localhost:5000                   ║
║  LAN    : http://192.168.1.13:5000                ║
╚══════════════════════════════════════════════════╝
```

> ⚠️ The LAN address must match what you put in `HONEYPOT_IP` in the firmware.

---

## ✅ PHASE 6 — Verify Everything is Connected

### Check 1: Dashboard Shows ESP32 ONLINE

1. Open browser → `http://localhost:5000/login`
2. Login: `phantom_admin` / `PhantomAdmin@2024`
3. Look at the ESP32 banner on the Overview page
4. It should show: **● ONLINE** with a recent "Last Ping" time

If it shows OFFLINE:
- ESP32 can't reach your server
- Check: Is laptop IP in firmware correct?
- Check: Firewall — Windows might be blocking port 5000

### Fix Windows Firewall (If ESP32 Can't Reach Server)
```
Search "Windows Defender Firewall" → Advanced Settings
→ Inbound Rules → New Rule
→ Port → TCP → 5000 → Allow
```

Or quickly test with:
```bash
# Run this in a SECOND terminal
netsh advfirewall firewall add rule name="PhantomIDS" dir=in action=allow protocol=TCP localport=5000
```

### Check 2: Green LED is ON
- When the ESP32 boots and connects, Green LED should glow constantly
- This means: "Idle — monitoring for attacks"

### Check 3: Serial Monitor Shows Idle
```
[PING] Heartbeat sent to server ✓
```
This appears every 30 seconds confirming live connection.

---

## 💥 PHASE 7 — Run the Live Attack Demo

Now for the exciting part. You have two options:

---

### Option A: Use the Built-in Attack Simulator (Easiest)

Open a **second terminal** on your laptop:

```bash
cd C:\Users\JYOTI\Downloads\PhantomIDS\PhantomIDS\server
node scripts/attack-sim.js --esp32
```

> ⚠️ Note: The simulator sends requests DIRECTLY to your Node.js server on localhost.
> It does NOT go through the ESP32 hardware.
> Use Option B for the true hardware path.

---

### Option B: Real Attack Through ESP32 (Full Hardware Path) ✅

This is the TRUE demo. Traffic goes: **Attacker → ESP32 → Node.js**

On a second terminal:
```bash
# Send SQL injection requests directly to the ESP32's IP
# (ESP32 listens on port 5000 and forwards to Node.js)

curl -X POST http://192.168.1.30:5000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=' OR 1=1--&password=test"
```

Or use the attack simulator pointed at the ESP32:
```bash
# Modify the target to ESP32's IP, not localhost
node scripts/attack-sim.js 192.168.1.30 5000
```

What happens:
1. Request hits **ESP32 on port 5000**
2. ESP32 scans payload → finds `' OR 1=1--`
3. **Red LED flashes** 🔴
4. **Buzzer beeps 3 times** 🔊
5. **LCD shows**: "!!SQLI DETECTED!! / IP:192.168.1.X"
6. ESP32 forwards request to **Node.js** with attacker's real IP
7. **Dashboard updates** — attack logged, ML model calculates P(THREAT)
8. After 3 attacks from same IP: **auto-banned** by rule engine

---

### Option C: Use sqlmap (Most Realistic for Judges) 🏆

If sqlmap is installed:
```bash
# Real sqlmap attack through ESP32
sqlmap -u "http://192.168.1.30:5000/login" \
       --data "username=test&password=test" \
       --level=3 --risk=2 \
       --batch --random-agent
```

With sqlmap, the buzzer will go crazy 🔊🔊🔊

---

## 🎯 PHASE 8 — The Perfect Demo Flow for Judges

Follow this exact sequence:

```
1. Show hardware physically (2 min)
   → "This is the ESP32. This is the breadboard with LEDs and buzzer."
   → "Green LED is ON — sensor is armed and monitoring the network."
   → Point to laptop: "This is our admin server running Node.js."

2. Show dashboard (1 min)
   → Open browser, show ESP32 banner: ● ONLINE
   → "The hardware is pinging our server every 30 seconds. You can see the last ping time."

3. Show the honeypot (30 sec)
   → Open /honeypot in new tab
   → "This is a fake login page — it's our trap for attackers."

4. Run the attack (2 min)
   → Run: node scripts/attack-sim.js 192.168.1.30 5000
   → "We're now simulating an sqlmap attack targeting the ESP32."
   → Hardware reacts: RED LED flashes, buzzer beeps
   → Dashboard updates in real time

5. Show ML Engine tab (2 min)
   → Click "ML Engine" in sidebar
   → "Our Logistic Regression model computed P(THREAT) = 97.3% for this IP."
   → Show the formula: sigmoid(w1·rate + w2·strikes + b)
   → Point to accuracy: 86.14%, F1: 87.93%

6. Show auto-ban (1 min)
   → IP Management tab
   → "After 3 THREAT detections, the rule engine permanently banned this IP."
   → Show the BANNED badge

7. Unban and repeat (optional, 1 min)
   → Click Unban
   → "Admin can instantly whitelist a false positive"
   → "Now let's do a fresh demo from scratch"
   → Click Reset All Data → run simulator again
```

---

## 🚨 Troubleshooting Quick Reference

| Problem | Fix |
|---------|-----|
| ESP32 shows OFFLINE on dashboard | Wrong `HONEYPOT_IP` in firmware. Run `ipconfig`, update, re-upload |
| "WiFi failed" in serial monitor | Wrong SSID/PASSWORD in firmware |
| COM port not appearing | Install CP210x driver. Try different USB cable (some are charge-only) |
| Buzzer not making sound | Using passive buzzer? Switch to active buzzer. Check GND connection |
| LED not lighting | Resistor missing? Check polarity (long leg = +) |
| Firewall blocking ESP32 → Server | Run: `netsh advfirewall firewall add rule name="Node5000" dir=in action=allow protocol=TCP localport=5000` |
| "Done uploading" but nothing works | Hold BOOT button during upload |
| Dashboard not loading | Server not started. Run `npm start` in server folder |

---

## 📱 Final Pre-Demo Checklist

Run through this 10 minutes before judges arrive:

- [ ] ESP32 powered via USB, Green LED glowing
- [ ] Serial Monitor shows: "Heartbeat sent to server ✓"
- [ ] `npm start` running in terminal — model loaded message visible
- [ ] Dashboard at `localhost:5000/dashboard` shows ESP32: ● ONLINE
- [ ] Click "Reset All Data" → stats all show 0 → clean slate
- [ ] Second terminal ready with attack command typed (don't press Enter yet)
- [ ] Browser zoomed in so judges can read the dashboard clearly
- [ ] ML Engine tab bookmarked / tab pre-opened

When judges say "show us" → hit Enter on the attack command. Everything will happen automatically.
