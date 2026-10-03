"""Data-driven, lab-bounded actions for generated A2 custom-rule scenarios."""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import Any

from .client import LabClient


def _catalog_path() -> Path:
    candidates = (
        Path("/opt/soc/scenarios/a2/catalog.json"),
        Path(__file__).resolve().parents[2] / "scenarios" / "a2" / "catalog.json",
    )
    for path in candidates:
        if path.is_file():
            return path
    raise FileNotFoundError("A2 catalog.json not found")


def _spec(action_id: str) -> dict[str, Any]:
    sid = int(action_id.removeprefix("A2-"))
    with _catalog_path().open(encoding="utf-8") as handle:
        records = json.load(handle)
    for record in records:
        if int(record["sid"]) == sid:
            return record
    raise ValueError(f"unknown A2 action SID: {sid}")


def _auth_reset(client: LabClient) -> None:
    client.json_request("POST", "/lab/auth/reset", {})


def _auth_attempts(client: LabClient, channel: str, mode: str) -> None:
    _auth_reset(client)
    for index in range(7):
        if mode == "parent":
            username, password = f"candidate-{index}@soc.lab", f"guess-{index}"
        elif mode == "guess":
            username, password = "fixed-user@soc.lab", f"guess-{index}"
        else:
            username, password = f"spray-user-{index}@soc.lab", "Shared-Password-1!"
        client.json_request("POST", f"/lab/auth/{channel}", {
            "username": username, "password": password,
        })


def run_a2_action(action_id: str, client: LabClient) -> None:
    record = _spec(action_id)
    kind = record["kind"]
    params = record.get("params", {})

    if kind == "internal_discovery":
        client.json_request("POST", "/lab/discovery", {"profile": params["profile"]}, timeout=15)
    elif kind == "valid_auth":
        channel = params["channel"]
        headers = {
            "bearer": {"Authorization": "Bearer soc-lab-valid-token"},
            "session": {"Cookie": "session=soc-lab-valid-session"},
            "api-key": {"X-Api-Key": "soc-lab-valid-api-key"},
            "basic": {"Authorization": "Basic c29jbGFiOnZhbGlk"},
        }[channel]
        client.request("GET", f"/lab/auth/valid/{channel}", headers=headers)
    elif kind == "driveby_response":
        client.request("GET", "/lab/reflect?q=" + urllib.parse.quote(params["payload"], safe=""))
    elif kind == "active_port_scan":
        client.command(["nmap", "-sT", "-Pn", "-T3", "--max-retries", "1", "-p",
                        "21,22,23,25,80,443,8080,9200", client.target_host], timeout=30)
    elif kind == "http_probe":
        client.request(params["method"], params["path"], headers={"User-Agent": params["user_agent"]})
    elif kind == "raw_http_probe":
        payload = (params["method"] + " / HTTP/1.1\r\nHost: " + client.target_host
                   + "\r\nConnection: close\r\n\r\n").encode("ascii")
        client.raw_http(payload)
    elif kind == "ip_block_scan":
        targets = [f"172.29.0.{value}" for value in range(20, 25)]
        client.command(["nmap", "-sT", "-Pn", "-T3", "--max-retries", "1", "-p",
                        str(params["port"]), *targets], timeout=30)
    elif kind == "vuln_scan":
        headers = {"User-Agent": params["user_agent"]}
        body = params.get("body")
        if body is not None:
            headers["Content-Type"] = "application/json"
        client.request(params["method"], params["path"], headers=headers,
                       body=body.encode() if body is not None else None)
    elif kind == "wordlist_scan":
        for path in params["paths"]:
            client.request("GET", path, headers={"User-Agent": "resource-discovery-client/1.0"})
    elif kind == "brute_parent":
        _auth_attempts(client, params["channel"], "parent")
    elif kind == "password_guess":
        _auth_attempts(client, params["channel"], "guess")
    elif kind == "password_spray":
        _auth_attempts(client, params["channel"], "spray")
    elif kind == "webshell_access":
        body = params.get("body")
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if body else None
        client.request(params["method"], params["path"], headers=headers,
                       body=body.encode() if body else None)
    elif kind == "endpoint_dos":
        profile, count = params["profile"], int(params["count"])
        for index in range(count):
            if profile == "normal_get":
                client.request("GET", f"/lab/normal?work=render&item={index}")
            elif profile == "normal_post":
                client.json_request("POST", "/lab/normal", {"operation": "aggregate", "item": index})
            elif profile == "search":
                client.request("GET", f"/rest/products/search?q=resource-intensive-{index}")
            elif profile == "auth":
                client.json_request("POST", "/lab/auth/json", {"username": f"load-{index}", "password": f"invalid-{index}"})
            else:
                client.upload(f"batch-{index}.txt", "text/plain", "bounded upload processing test")
    elif kind == "web_c2":
        client.json_request("POST", "/lab/c2/start", {
            "count": 6, "interval_ms": 300, "profile": params["profile"],
        }, timeout=15)
    elif kind == "content_injection":
        client.request("GET", "/lab/content/preview?profile=" + params["profile"])
    elif kind == "network_dos":
        payload = ("bounded-udp-load-" + str(params["port"])).encode()
        client.udp(int(params["port"]), payload, count=int(params["count"]))
    elif kind == "non_app":
        payload = bytes.fromhex(params["payload_hex"])
        if params["protocol"] == "tcp":
            client.raw_tcp(int(params["port"]), payload)
        else:
            client.udp(int(params["port"]), payload)
    else:
        raise ValueError(f"unsupported A2 action kind: {kind}")
