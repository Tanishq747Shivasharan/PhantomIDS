#include <WiFi.h>
#include <LiquidCrystal_I2C.h>

const char* SSID          = "<WiFi Name>";
const char* PASSWORD      = "<WiFi Password>";
const char* HONEYPOT_IP   = "192.168.1.6";
const int   HONEYPOT_PORT = 5000;
const int   LISTEN_PORT   = 5000;

IPAddress local_IP(192, 168, 1, 30);
IPAddress gateway(192, 168, 1,  1);
IPAddress subnet(255, 255, 255,  0);
IPAddress dns(8, 8, 8, 8);

LiquidCrystal_I2C lcd(0x27, 16, 2);

#define BUZZER_PIN  13   
#define LED_GREEN   26   
#define LED_RED     25   

WiFiServer server(LISTEN_PORT);

int totalRequests = 0;
int alertCount    = 0;
int warnCount     = 0;

const char* SQL_KEYWORDS[] = {
  " OR ", " AND ", "UNION", "SELECT", "INSERT",
  "DROP", "DELETE", "UPDATE", "FROM", "WHERE",
  "SLEEP", "BENCHMARK", "HAVING", "ORDER BY",
  "--", "/*", "#", "1=1", "1 =1", "xp_"
};
const int KEYWORD_COUNT = 20;

void setIdle() {
  digitalWrite(LED_GREEN, HIGH);
  digitalWrite(LED_RED,   LOW);
}

void setWarning() {
  digitalWrite(LED_GREEN, LOW);
  digitalWrite(LED_RED,   LOW);
  delay(200);
  digitalWrite(LED_GREEN, HIGH);
}

void setAlert() {
  digitalWrite(LED_GREEN, LOW);
  digitalWrite(LED_RED,   HIGH);
}

void blinkRed(int times) {
  for (int i = 0; i < times; i++) {
    digitalWrite(LED_RED, HIGH); delay(150);
    digitalWrite(LED_RED, LOW);  delay(150);
  }
}

void beep(int times, int ms = 80) {
  for (int i = 0; i < times; i++) {
    digitalWrite(BUZZER_PIN, HIGH); delay(ms);
    digitalWrite(BUZZER_PIN, LOW);  delay(ms);
  }
}

String urlDecode(const String& encoded) {
  String decoded = "";
  int len = encoded.length();
  for (int i = 0; i < len; i++) {
    if (encoded[i] == '%' && i + 2 < len) {
      char hex[3] = { encoded[i+1], encoded[i+2], '\0' };
      decoded += (char) strtol(hex, nullptr, 16);
      i += 2;
    } else if (encoded[i] == '+') {
      decoded += ' ';
    } else {
      decoded += encoded[i];
    }
  }
  return decoded;
}

bool hasQuote(const String& body) {
  return (body.indexOf("'") != -1 || body.indexOf("\"") != -1);
}

bool hasSQLKeyword(const String& body) {
  String upper = body;
  upper.toUpperCase();
  for (int i = 0; i < KEYWORD_COUNT; i++) {
    String kw = String(SQL_KEYWORDS[i]);
    kw.toUpperCase();
    if (upper.indexOf(kw) != -1) return true;
  }
  return false;
}

String extractBody(const String& raw) {
  int idx = raw.indexOf("\r\n\r\n");
  if (idx == -1) return "";
  return raw.substring(idx + 4);
}

String extractField(const String& body, const String& field) {
  String key = field + "=";
  int start = body.indexOf(key);
  if (start == -1) return "";
  start += key.length();
  int end = body.indexOf("&", start);
  if (end == -1) end = body.length();
  return body.substring(start, end);
}

void showAlert(int score, const String& attackerIP, const String& payload) {
  if (score >= 2) {

    setAlert();

    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("!!SQLI DETECTED!");

    String ipLine = "IP:" + attackerIP;
    if (ipLine.length() > 16) ipLine = ipLine.substring(ipLine.length() - 16);
    lcd.setCursor(0, 1);
    lcd.print(ipLine);

    for (int i = 0; i < 3; i++) {
      digitalWrite(BUZZER_PIN, HIGH);
      digitalWrite(LED_RED,    HIGH);
      delay(120);
      digitalWrite(BUZZER_PIN, LOW);
      digitalWrite(LED_RED,    LOW);
      delay(120);
    }

    delay(2000); 

    // Show running totals
    lcd.clear();
    lcd.setCursor(0, 0); lcd.print("Alerts: "); lcd.print(alertCount);
    lcd.setCursor(0, 1); lcd.print("Warns:  "); lcd.print(warnCount);
    delay(1500);

    setAlert();

  } else if (score == 1) {
    setWarning(); 

    lcd.clear();
    lcd.setCursor(0, 0); lcd.print("WARN: Suspicious");
    String ipSnip = "IP:" + attackerIP.substring(attackerIP.lastIndexOf('.'));
    lcd.setCursor(0, 1); lcd.print(ipSnip);

    beep(1); 
    delay(1000);

    setIdle(); 
  }
}

int detectSQLi(const String& body, String& decodedOut) {
  if (body.length() == 0) return 0;
  decodedOut      = urlDecode(body);
  bool signal1    = hasQuote(decodedOut);
  bool signal2    = hasSQLKeyword(decodedOut);
  return (signal1 ? 1 : 0) + (signal2 ? 1 : 0);
}

void setup() {
  Serial.begin(115200);
  delay(500);

  pinMode(BUZZER_PIN, OUTPUT); digitalWrite(BUZZER_PIN, LOW);
  pinMode(LED_GREEN,  OUTPUT); digitalWrite(LED_GREEN,  LOW);
  pinMode(LED_RED,    OUTPUT); digitalWrite(LED_RED,    LOW);

  Serial.println("\n[HW]   LED self-test...");
  digitalWrite(LED_GREEN, HIGH); delay(400);
  digitalWrite(LED_GREEN, LOW);
  digitalWrite(LED_RED,   HIGH); delay(400);
  digitalWrite(LED_RED,   LOW);
  beep(1);
  Serial.println("[HW]   LED self-test done");

  lcd.init();
  lcd.backlight();
  lcd.setCursor(0, 0); lcd.print("PhantomIDS v1.0 ");
  lcd.setCursor(0, 1); lcd.print("Starting...     ");

  WiFi.config(local_IP, gateway, subnet, dns);
  WiFi.begin(SSID, PASSWORD);

  Serial.println("========================================");
  Serial.println("  PhantomIDS — FULL IDS MODE");
  Serial.println("  Green LED D26 = idle/monitoring");
  Serial.println("  Red LED   D25 = attack detected");
  Serial.println("========================================");
  Serial.print("[WiFi] Connecting");

  int att = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(500); Serial.print(".");
    if (++att > 30) {
      Serial.println("\n[FATAL] WiFi failed — check credentials");
      lcd.setCursor(0, 1); lcd.print("WiFi FAILED!    ");
      while (true) delay(1000);
    }
  }

  Serial.println("\n[WiFi] Connected! IP: " + WiFi.localIP().toString());
  Serial.print("[WiFi] RSSI: "); Serial.print(WiFi.RSSI()); Serial.println(" dBm");
  Serial.println("[IDS]  Detection engine : ACTIVE");
  Serial.println("[IDS]  URL decoding     : ENABLED");
  Serial.println("[IDS]  Threshold        : 2 signals = ALERT");
  Serial.println("[IDS]  Keywords loaded  : " + String(KEYWORD_COUNT));
  Serial.println("[HW]   Green LED (D26)  : IDLE indicator");
  Serial.println("[HW]   Red LED   (D25)  : ALERT indicator");
  Serial.println("\n[IDS]  Listening on port " + String(LISTEN_PORT) + "...\n");

  server.begin();

  setIdle();

  lcd.clear();
  lcd.setCursor(0, 0); lcd.print("PhantomIDS ARMED");
  lcd.setCursor(0, 1); lcd.print("192.168.1.30    ");
  beep(2);
  delay(1500);

  lcd.setCursor(0, 0); lcd.print("Monitoring :5000");
  lcd.setCursor(0, 1); lcd.print("Alerts: 0       ");
}

void loop() {
  WiFiClient client = server.available();
  if (!client) return;

  totalRequests++;
  String attackerIP = client.remoteIP().toString();

  String rawRequest = "";
  unsigned long t0 = millis();
  while (client.connected() && (millis() - t0 < 3000)) {
    while (client.available()) {
      rawRequest += (char)client.read();
      if (rawRequest.length() > 4096) break;
    }
    if (rawRequest.indexOf("\r\n\r\n") != -1) {
      delay(10);
      while (client.available()) rawRequest += (char)client.read();
      break;
    }
  }

  String firstLine = rawRequest.substring(0, rawRequest.indexOf("\r\n"));
  String body      = extractBody(rawRequest);
  bool   isPOST    = firstLine.startsWith("POST");

  Serial.println("────────────────────────────────────────");
  Serial.print("[REQ #"); Serial.print(totalRequests);
  Serial.print("] "); Serial.print(attackerIP);
  Serial.print(" → "); Serial.println(firstLine);

  String decoded = "";
  int    score   = 0;

  if (isPOST && body.length() > 0) {
    score = detectSQLi(body, decoded);
    String userPayload = extractField(decoded, "username");

    Serial.print("[BODY] Raw     : "); Serial.println(body.substring(0, 80));
    Serial.print("[DEC]  Decoded : "); Serial.println(decoded.substring(0, 80));
    Serial.print("[USER] username: "); Serial.println(userPayload.substring(0, 60));
    Serial.print("[SCORE] Signals: "); Serial.print(score);

    if (score >= 2) {
      alertCount++;
      Serial.println(" → !! CRITICAL ALERT !!");
      Serial.print("[ALERT #"); Serial.print(alertCount); Serial.println("] SQLI DETECTED");
      Serial.print("[ALERT] Attacker : "); Serial.println(attackerIP);
      Serial.print("[ALERT] Payload  : "); Serial.println(userPayload.substring(0, 60));
      showAlert(2, attackerIP, userPayload);

    } else if (score == 1) {
      warnCount++;
      Serial.println(" → WARNING (1 signal)");
      showAlert(1, attackerIP, userPayload);

    } else {
      Serial.println(" → CLEAN");
      setIdle();
    }
  } else {
    Serial.println("[SKIP] GET — no body");
    setIdle(); 
  }

  WiFiClient hp;
  String hpResponse = "";

  if (hp.connect(HONEYPOT_IP, HONEYPOT_PORT)) {
    hp.print(rawRequest);
    delay(400);
    unsigned long t1 = millis();
    while (hp.connected() && (millis() - t1 < 3000)) {
      while (hp.available()) {
        hpResponse += (char)hp.read();
        if (hpResponse.length() > 4096) break;
      }
    }
    hp.stop();
  } else {
    hpResponse = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
    Serial.println("[FWD]  WARNING: honeypot unreachable!");
  }

  client.print(hpResponse);
  client.stop();

  if (score < 2) {
    lcd.setCursor(0, 0); lcd.print("Monitoring :5000");
    String line2 = "A:" + String(alertCount) +
                   " W:" + String(warnCount)  +
                   " R:" + String(totalRequests);
    while (line2.length() < 16) line2 += " ";
    lcd.setCursor(0, 1); lcd.print(line2.substring(0, 16));
  }

  Serial.println("────────────────────────────────────────\n");
}