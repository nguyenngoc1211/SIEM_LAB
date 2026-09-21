# SOC Attack Scenarios v2

## Scope and safety

This suite contains 19 atomic scenarios and four composite chains. It is restricted to the local Docker lab. The runner allowlists `soc_gateway`; SSRF, exfiltration, and C2 can reach only services on Docker networks; uploaded files are stored non-executable; command injection is a parser-backed simulation and never invokes a shell.

The ground-truth request `/__soc_attack_marker__` only delimits a run in `eve.json`. No Suricata or Wazuh rule matches the marker, scenario ID, run ID, or scenario name.

## Architecture and visibility

```text
soc_attacker_v2
    -> soc_gateway (Nginx, eth0 on soc_backend)
       -> Juice Shop or lab-backend
       -> isolated internal/exfil/C2/metadata sinks

soc_suricata shares the gateway network namespace
    -> passive AF_PACKET capture on eth0 (IDS, not IPS)
    -> runtime/suricata-logs/eve.json
    -> Wazuh Manager localfile ingestion
    -> SOC v2 child rules and temporal correlation
    -> MITRE metadata and CSV/JSON report
```

ET rules remain unchanged. Project rules are appended from `sensor/local.rules` into the generated combined ruleset. Automatic rule download is disabled by default in isolated mode.

## Atomic scenarios

| ID | Name | Attack class | MITRE | What happens | Expected telemetry | Expected detection | Why it exists |
|---|---|---|---|---|---|---|---|
| BASE-00 | Normal Traffic / Negative Control | baseline | - | Homepage, assets, search, health, and valid lab API requests | HTTP transactions without custom security signatures | No custom Suricata/Wazuh alert | Measures false positives |
| RECON-01 | Network Service Discovery | recon | T1046 | TCP connect, selected-port Nmap scan, light service detection, HTTP identification | SYN burst across selected ports and Nmap identification | SID 1001001 / Wazuh 110101 | Consolidates network discovery behavior |
| RECON-02 | Web Resource Enumeration | recon | T1595.002 | Normal pages followed by 20 sensitive-resource requests | One source, many sensitive paths in a short window | SID 1001002 / Wazuh 110102 | Tests thresholded enumeration rather than one-URL alerts |
| RECON-03 | Automated Scanner Fingerprint | recon | T1595.002 | sqlmap-, Nikto-, Nmap-, and scanner-like headers | Recognizable automated scanner headers | SID 1001003 / Wazuh 110103 | One clear scanner objective replaces many marker cases |
| WEB-04 | Path Traversal | web | T1190 | Normal path plus raw, encoded, and double-encoded traversal variants | Raw and normalized traversal indicators | SID 1001004 / Wazuh 110104 | Tests normalization-safe traversal detection |
| WEB-05 | Linux LFI | web | T1190 | Safe lab endpoint resolves an `/etc/passwd`-style path to a fixture | HTTP request plus backend file-access audit log | SID 1001005 / Wazuh 110105 | Produces real file/path handling without reading host data |
| WEB-06 | SQL Injection Progression | web | T1190 | Normal search, syntax, TRUE/FALSE, UNION, and delay probes | Ordered HTTP search probes with distinct SQLi forms | SIDs 1001006-1001008 / Wazuh 110106 | Evaluates progression, not four duplicate scenarios |
| WEB-07 | Encoded / Obfuscated SQL Injection | web | T1190 | URL/double encoding and comment obfuscation | Raw URI and normalized SQLi indicators | SID 1001009 / Wazuh 110106 | Tests normalization/evasion handling |
| WEB-08 | Cross-Site Scripting | web | T1190 | Harmless script, handler, encoded, and attribute markers are reflected | Request and safe reflected response | SID 1001010 / Wazuh 110108 | Consolidates XSS forms with benign controls |
| WEB-09 | Command Injection Safe Simulation | web | T1190 | Endpoint parses only allowlisted `echo` and `whoami` simulations | Suspicious separators plus audited simulation result | SID 1001011 / Wazuh 110109 | Verifies behavior without arbitrary command execution |
| WEB-10 | Prototype Pollution | web | T1190 | Node.js endpoint merges an isolated object containing prototype keys | Prototype-related JSON plus isolated inherited-value log | SID 1001012 / Wazuh 110110 | Matches the Node.js attack surface |
| AUTH-11 | JWT Tampering | auth | T1190 | Valid, modified, invalid-signature, and `none`-algorithm tokens | JWT validation outcomes and suspicious headers | SID 1001013 / Wazuh 110111 | Consolidates token manipulation objectives |
| AUTH-12 | Brute Force | auth | T1110.001 | One username receives many distinct passwords after benign failures | Same source/user, many passwords, short window | SID 1001014 / Wazuh 110112 | Distinguishes focused guessing from spraying |
| AUTH-13 | Password Spray | auth | T1110.003 | Many usernames receive one common password | Same source, many users, few passwords | SID 1001015 / Wazuh 110113 | Provides a distinct authentication pattern |
| SERVER-14 | Real SSRF to Isolated Sinks | server-side | T1190 | Backend performs HTTP requests to allowlisted internal and simulated-metadata sinks | Trigger request, backend egress request, sink log | SIDs 1001016-1001017 / Wazuh 110114 and 110119 | Replaces query-string-only SSRF markers |
| SERVER-15 | Suspicious File Upload | server-side | T1190 | Harmless double-extension and webshell-marker text files are stored mode 0600 in noexec tmpfs | Multipart request, filename/type mismatch, backend write log | SID 1001018 / Wazuh 110115 | Exercises a real upload path without executable content |
| EXFIL-16 | Fake Data Exfiltration | exfiltration | T1041, T1132.001 | Backend sends plain, encoded, and larger fake payloads to the isolated exfil sink | Real outbound POSTs and sink logs | SIDs 1001019-1001020 / Wazuh 110116 | Replaces callback strings with observable egress |
| C2-17 | Periodic HTTP C2 Beacon | C2 | T1071.001 | Backend sends six similar fake-host beacons at regular intervals | Same destination, similar size, periodic timing | SID 1001021 / Wazuh 110117 | Tests periodic application-layer behavior |
| HTTP-18 | HTTP Framing Anomaly | protocol | T1190 | Raw, non-destructive conflicting and duplicate framing headers are sent to Nginx | TCP/HTTP parser anomaly and framing signature | SIDs 1001022-1001024 / Wazuh 110118 | Retained because the client-Nginx-backend topology is observable |

## Composite chains

| Chain | Sequence | Correlation objective |
|---|---|---|
| CHAIN-A | RECON-01 -> RECON-02 -> WEB-06 | Reconnaissance followed by exploitation; SQLi progression escalation |
| CHAIN-B | RECON-02 -> AUTH-11 -> AUTH-12 | Enumeration followed by token manipulation and focused brute force |
| CHAIN-C | RECON-01 -> RECON-02 -> SERVER-14 | Reconnaissance followed by SSRF trigger and verified internal access |
| CHAIN-D | WEB-09 -> EXFIL-16 -> C2-17 | Web exploitation followed by fake-data exfiltration and beaconing |

Correlation rules use decoded network/application fields and time windows. They do not use chain IDs or ground-truth markers.

## Running scenarios

```powershell
# List catalog
docker exec soc_attacker_v2 attackctl list

# One scenario
docker exec soc_attacker_v2 attackctl run WEB-06

# An explicit batch, in the requested order
docker exec soc_attacker_v2 attackctl run-batch RECON-01 RECON-02 WEB-06 --pause 2

# A category or the complete atomic suite
docker exec soc_attacker_v2 attackctl run-category auth --pause 2
docker exec soc_attacker_v2 attackctl run-all --pause 2

# One chain
docker exec soc_attacker_v2 attackctl run-chain CHAIN-A
```

Every non-dry run appends a JSONL scenario record under `runtime/ground-truth/`. Reports use marker order as run boundaries so a Docker Desktop clock resynchronization cannot invert short time windows.

## Result meanings

| Status | Meaning |
|---|---|
| PASS | Execution, traffic, expected detection, Wazuh ingestion, and mapping succeeded; or a negative control remained quiet |
| FAIL | Traffic was visible but an expected Suricata alert was absent |
| PARTIAL | Suricata detected the behavior but a downstream Wazuh or mapping requirement was absent |
| NO_TELEMETRY | Scenario ran but relevant Suricata HTTP/flow/anomaly telemetry was absent |
| FALSE_POSITIVE | A negative control produced a project custom security alert |
| INFRA_ERROR | Runner or required infrastructure failed |

Runtime output is intentionally not committed as evidence. Regenerate it on the active lab with `attackctl report`.
