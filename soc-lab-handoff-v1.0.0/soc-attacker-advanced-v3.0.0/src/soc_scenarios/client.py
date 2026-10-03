from __future__ import annotations

import json
import os
import shlex
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any


ALLOWED_HOSTS = {"soc_gateway", "gateway", "localhost", "127.0.0.1"}


@dataclass
class LabClient:
    scenario_id: str
    run_id: str
    dry_run: bool = False
    target: str = field(default_factory=lambda: os.environ.get("TARGET", "http://soc_gateway").rstrip("/"))
    target_host: str = field(default_factory=lambda: os.environ.get("TARGET_HOST", "soc_gateway"))
    target_port: int = field(default_factory=lambda: int(os.environ.get("TARGET_PORT", "80")))
    delay: float = field(default_factory=lambda: float(os.environ.get("SCENARIO_DELAY", "0.05")))
    results: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlparse(self.target)
        safe_mode = os.environ.get("SAFE_MODE", "true").lower() != "false"
        if safe_mode and (parsed.hostname or "") not in ALLOWED_HOSTS:
            raise ValueError("TARGET is outside the local SOC lab allowlist")
        if self.target_host not in ALLOWED_HOSTS:
            raise ValueError("TARGET_HOST is outside the local SOC lab allowlist")

    def _url(self, request_path: str) -> str:
        if not request_path.startswith("/"):
            request_path = "/" + request_path
        safe = "/%?=&:;,+@$'()[]{}*.-_~#\\%|<>\""
        return self.target + urllib.parse.quote(request_path, safe=safe)

    def request(self, method: str, request_path: str, *, headers: dict[str, str] | None = None,
                body: bytes | None = None, timeout: float = 5.0) -> dict[str, Any]:
        request_headers = {
            "User-Agent": "soc-attack-scenarios-v2/2.0",
            "X-SOC-Scenario": self.scenario_id,
            "X-SOC-Run-Id": self.run_id,
        }
        request_headers.update(headers or {})
        target = self._url(request_path)
        result: dict[str, Any] = {
            "type": "http", "method": method, "path": request_path,
            "target": target, "headers": request_headers,
            "body_bytes": len(body or b""),
            "body": (body or b"").decode("utf-8", errors="replace"),
        }
        command = ["curl", "-sS", "-X", method]
        for key, value in request_headers.items():
            command.extend(["-H", f"{key}: {value}"])
        if body:
            command.extend(["--data-binary", body.decode("utf-8", errors="replace")])
        command.append(target)
        result["attack_command"] = " ".join(shlex.quote(value) for value in command)
        if self.dry_run:
            result.update({"sent": False, "dry_run": True})
            self.results.append(result)
            print("DRY", method, target)
            return result
        started = time.perf_counter()
        try:
            request = urllib.request.Request(target, data=body, headers=request_headers, method=method)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                response_body = response.read(2048)
                result.update({"sent": True, "status": response.status, "response_bytes": len(response_body),
                               "response_excerpt": response_body.decode("utf-8", errors="replace")[:300]})
        except urllib.error.HTTPError as error:
            response_body = error.read(2048)
            result.update({"sent": True, "status": error.code, "response_bytes": len(response_body),
                           "response_excerpt": response_body.decode("utf-8", errors="replace")[:300]})
        except Exception as error:
            result.update({"sent": False, "error": type(error).__name__ + ": " + str(error)})
        result["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
        self.results.append(result)
        print(method, target, "->", result.get("status", result.get("error", "not sent")))
        time.sleep(self.delay)
        return result

    def json_request(self, method: str, request_path: str, payload: Any, *,
                     headers: dict[str, str] | None = None, timeout: float = 5.0) -> dict[str, Any]:
        request_headers = {"Content-Type": "application/json"}
        request_headers.update(headers or {})
        data = payload if isinstance(payload, str) else json.dumps(payload, separators=(",", ":"))
        return self.request(method, request_path, headers=request_headers, body=data.encode(), timeout=timeout)

    def upload(self, filename: str, content_type: str, content: str) -> dict[str, Any]:
        boundary = "----socv2-safe-upload-boundary"
        body = ("--" + boundary + "\r\n"
                + 'Content-Disposition: form-data; name="file"; filename="' + filename + '"\r\n'
                + "Content-Type: " + content_type + "\r\n\r\n"
                + content + "\r\n--" + boundary + "--\r\n").encode()
        return self.request("POST", "/lab/upload",
                            headers={"Content-Type": "multipart/form-data; boundary=" + boundary}, body=body)

    def command(self, argv: list[str], timeout: float = 20.0) -> dict[str, Any]:
        result: dict[str, Any] = {"type": "command", "argv": argv}
        if self.dry_run:
            result.update({"sent": False, "dry_run": True})
            self.results.append(result)
            print("DRY CMD", " ".join(argv))
            return result
        try:
            completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
            result.update({"sent": True, "returncode": completed.returncode,
                           "stdout": completed.stdout[-1000:], "stderr": completed.stderr[-1000:]})
        except Exception as error:
            result.update({"sent": False, "error": type(error).__name__ + ": " + str(error)})
        self.results.append(result)
        print("CMD", " ".join(argv), "->", result.get("returncode", result.get("error")))
        time.sleep(self.delay)
        return result

    def raw_http(self, payload: bytes) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": "raw_http", "bytes": len(payload),
            "payload": payload.decode("latin1", errors="replace"),
            "attack_command": "raw TCP payload to " + self.target_host + ":" + str(self.target_port),
        }
        if self.dry_run:
            result.update({"sent": False, "dry_run": True})
            self.results.append(result)
            print("DRY RAW", len(payload), "bytes")
            return result
        try:
            with socket.create_connection((self.target_host, self.target_port), timeout=3) as connection:
                connection.sendall(payload)
                connection.settimeout(2)
                response = connection.recv(1024)
            result.update({"sent": True, "response_excerpt": response.decode("latin1", errors="replace")[:300]})
        except Exception as error:
            result.update({"sent": True, "error": type(error).__name__ + ": " + str(error)})
        self.results.append(result)
        print("RAW", len(payload), "bytes ->", result.get("error", "sent"))
        time.sleep(self.delay)
        return result

    def raw_tcp(self, port: int, payload: bytes) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": "raw_tcp", "port": port, "bytes": len(payload),
            "payload_hex": payload.hex(),
            "attack_command": f"send {len(payload)} raw TCP bytes to {self.target_host}:{port}",
        }
        if self.dry_run:
            result.update({"sent": False, "dry_run": True})
            self.results.append(result)
            return result
        try:
            with socket.create_connection((self.target_host, port), timeout=3) as connection:
                connection.sendall(payload)
            result["sent"] = True
        except Exception as error:
            # A reset after send is still traffic generation, but connect errors are not.
            result.update({"sent": False, "error": type(error).__name__ + ": " + str(error)})
        self.results.append(result)
        time.sleep(self.delay)
        return result

    def udp(self, port: int, payload: bytes, *, count: int = 1) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": "udp", "port": port, "bytes_each": len(payload), "count": count,
            "payload_hex": payload.hex(),
            "attack_command": f"send {count} UDP datagrams to {self.target_host}:{port}",
        }
        if self.dry_run:
            result.update({"sent": False, "dry_run": True})
            self.results.append(result)
            return result
        sent = 0
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                for _ in range(count):
                    connection.sendto(payload, (self.target_host, port))
                    sent += 1
            result.update({"sent": sent == count, "datagrams_sent": sent})
        except Exception as error:
            result.update({"sent": False, "datagrams_sent": sent,
                           "error": type(error).__name__ + ": " + str(error)})
        self.results.append(result)
        time.sleep(self.delay)
        return result
