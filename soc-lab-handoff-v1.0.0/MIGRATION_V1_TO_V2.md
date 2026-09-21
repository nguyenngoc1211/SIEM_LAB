# Migration from scenarios v1 to v2

## Summary

| Metric | Count |
|---|---:|
| Before | 80 |
| After | 19 |
| Kept unchanged | 0 |
| Merged into a broader objective | 36 |
| Deleted | 29 |
| Replaced by real/safe behavior | 15 |
| Entirely new atomic objectives | 0 |

`MERGE` means the useful signal is retained inside a broader behavioral sequence. `REPLACE` means the marker/probe was removed and a real constrained lab behavior was implemented. `DELETE` means the old case was unsupported by the target, duplicated another objective, or lacked verifiable behavior.

## Complete disposition

| Old | Old name | Decision | V2 target | Technical reason |
|---:|---|---|---|---|
| 01 | baseline home page | MERGE | BASE-00 | One negative-control sequence is more useful than separate baseline rows |
| 02 | health and gateway endpoints | MERGE | BASE-00 | Valid health traffic belongs in the shared negative control |
| 03 | static asset crawl | MERGE | BASE-00 | Retained as benign asset telemetry |
| 04 | robots sitemap discovery | MERGE | BASE-00 | Normal discovery is a benign control, not an attack by itself |
| 05 | normal product search | MERGE | BASE-00 | Retained as the SQLi/XSS-adjacent benign control |
| 06 | ICMP and TCP connectivity | MERGE | RECON-01 | TCP connectivity retained inside full discovery; standalone ping removed |
| 07 | DNS lookup service names | DELETE | - | Single Docker DNS lookups have no useful detection objective |
| 08 | selected port scan | MERGE | RECON-01 | Port scan is one stage of network discovery |
| 09 | HTTP NSE enumeration | MERGE | RECON-01 | Service/HTTP identification is retained in the same sequence |
| 10 | internal TCP connect checks | MERGE | RECON-01 | Duplicated selected-port connectivity telemetry |
| 11 | HTTP OPTIONS enumeration | DELETE | - | A few OPTIONS requests are weak, common telemetry |
| 12 | uncommon HTTP methods | DELETE | - | No target behavior or stable independent detection objective |
| 13 | security header probe | DELETE | - | Header audit is not an attack scenario |
| 14 | Host header override | DELETE | - | No vulnerable virtual-host behavior was implemented |
| 15 | forwarded header spoofing | DELETE | - | Marker-like headers produced no verified access impact |
| 16 | sensitive file probe | MERGE | RECON-02 | Becomes one sensitive-path class in thresholded enumeration |
| 17 | source-control artifact probe | MERGE | RECON-02 | Same source/path-burst objective |
| 18 | backup and archive probe | MERGE | RECON-02 | Same source/path-burst objective |
| 19 | admin panel discovery | MERGE | RECON-02 | Same source/path-burst objective |
| 20 | debug metrics actuator discovery | MERGE | RECON-02 | Same source/path-burst objective; no Spring exploitation claim |
| 21 | API root discovery | MERGE | RECON-02 | API paths are included in the controlled burst |
| 22 | Swagger and OpenAPI discovery | MERGE | RECON-02 | Documentation paths are included in the controlled burst |
| 23 | GraphQL GET markers | DELETE | - | Target does not expose a GraphQL implementation |
| 24 | GraphQL introspection POST marker | DELETE | - | Marker-only request against unsupported technology |
| 25 | small directory fuzzing | MERGE | RECON-02 | Expanded into a meaningful 20-path burst |
| 26 | extension sweep | MERGE | RECON-02 | Standalone extension probes duplicated enumeration telemetry |
| 27 | path normalization anomalies | MERGE | WEB-04 | Normalization variants are stages of one traversal scenario |
| 28 | encoded path traversal | MERGE | WEB-04 | Encoded/double-encoded forms belong in the same progression |
| 29 | Linux LFI traversal | REPLACE | WEB-05 | New safe endpoint actually resolves a fixture-backed file path |
| 30 | Windows LFI traversal | DELETE | - | Linux/Node.js container target; Windows paths are inapplicable |
| 31 | PHP wrapper LFI markers | DELETE | - | Target is not PHP and exposes no PHP stream wrappers |
| 32 | classic SQL injection markers | MERGE | WEB-06 | Consolidated SQLi progression |
| 33 | boolean SQL injection markers | MERGE | WEB-06 | TRUE/FALSE stages retained together |
| 34 | UNION SQL injection markers | MERGE | WEB-06 | UNION stage retained together |
| 35 | time-delay SQL injection markers | MERGE | WEB-06 | Delay marker retained as a safe progression stage |
| 36 | encoded SQL injection markers | REPLACE | WEB-07 | Redesigned specifically around raw/normalized URI handling |
| 37 | NoSQL operator login marker | DELETE | - | Current application path is SQL-backed, not NoSQL-backed |
| 38 | NoSQL regex body marker | DELETE | - | Unsupported data-store technology and no real behavior |
| 39 | script XSS markers | MERGE | WEB-08 | Harmless script variant retained |
| 40 | event handler XSS markers | MERGE | WEB-08 | Handler variant retained |
| 41 | SVG and MathML XSS markers | MERGE | WEB-08 | Safe encoded/attribute variants retained in one objective |
| 42 | template injection markers | DELETE | - | No exposed server-side template engine processes the input |
| 43 | command injection separator markers | REPLACE | WEB-09 | Safe endpoint now parses and audits allowlisted simulations |
| 44 | command injection JSON body markers | REPLACE | WEB-09 | Nonexistent/500 endpoint replaced by verified behavior |
| 45 | SSRF localhost markers | REPLACE | SERVER-14 | Backend now performs a real request to an isolated sink |
| 46 | cloud metadata SSRF markers | REPLACE | SERVER-14 | Real cloud metadata is never touched; a Docker simulator is used |
| 47 | internal hostname SSRF markers | REPLACE | SERVER-14 | Backend egress and sink receipt are both verifiable |
| 48 | scanner User-Agent set | MERGE | RECON-03 | Retained as one multi-fingerprint scenario |
| 49 | suspicious scanner headers | MERGE | RECON-03 | Same automated-scanner detection objective |
| 50 | Shellshock header marker | DELETE | - | No Bash CGI attack surface |
| 51 | Log4Shell header marker | DELETE | - | Target is not a vulnerable Java/Log4j service |
| 52 | Spring4Shell marker | DELETE | - | Target is not Spring |
| 53 | Java serialization marker | DELETE | - | Target is not Java and performs no Java deserialization |
| 54 | PHP serialization marker | DELETE | - | Target is not PHP |
| 55 | XXE marker | DELETE | - | No XML parser endpoint with entity resolution |
| 56 | SOAP XML marker | DELETE | - | Target exposes no SOAP service |
| 57 | CRLF injection markers | DELETE | - | No verified header-splitting behavior or distinct objective |
| 58 | request smuggling marker headers | REPLACE | HTTP-18 | Raw, safe framing anomalies now traverse the actual Nginx topology |
| 59 | cache poisoning headers | DELETE | - | No cache layer or verified poisoning behavior |
| 60 | CORS preflight probes | DELETE | - | Preflight alone is normal traffic, not a security behavior |
| 61 | open redirect markers | DELETE | - | No endpoint performs the requested redirect |
| 62 | JWT none algorithm marker | MERGE | AUTH-11 | Becomes one step in token-tampering progression |
| 63 | invalid admin JWT marker | MERGE | AUTH-11 | Modified payload/signature variants are tested together |
| 64 | cookie tampering markers | DELETE | - | No verified session state change and no distinct telemetry objective |
| 65 | session fixation marker | DELETE | - | No real fixation-capable session flow |
| 66 | mass assignment markers | DELETE | - | No endpoint applies attacker-controlled privileged fields |
| 67 | prototype pollution marker | REPLACE | WEB-10 | Node.js endpoint now performs an isolated object merge and logs outcome |
| 68 | PHP upload marker | REPLACE | SERVER-15 | Replaced by a real non-executable upload endpoint; no PHP execution claim |
| 69 | double extension upload markers | REPLACE | SERVER-15 | File is actually stored in noexec tmpfs |
| 70 | suspicious upload name markers | REPLACE | SERVER-15 | Filename/type mismatch is verified by backend audit log |
| 71 | login failure burst capped | MERGE | AUTH-12 | Low-count failures are the benign prelude; focused burst has its own classifier |
| 72 | password spraying capped | MERGE | AUTH-13 | Redesigned as many users with one common password |
| 73 | password guessing capped | MERGE | AUTH-12 | Redesigned as one user with many distinct passwords |
| 74 | credential stuffing fake capped | DELETE | - | Fake credentials produced telemetry indistinguishable from generic failures |
| 75 | API rate-limit burst capped | DELETE | - | No independent rate-limit bypass behavior was verified |
| 76 | callback URL exfil markers | REPLACE | EXFIL-16 | Backend now sends fake data to the isolated exfil sink |
| 77 | base64 exfil marker | REPLACE | EXFIL-16 | Encoded fake payload is actually transmitted |
| 78 | fake C2 beacon markers | REPLACE | C2-17 | Periodic outbound POSTs now reach the isolated C2 sink |
| 79 | internal service connect checks | MERGE | RECON-01 | Duplicated connectivity/scan objective |
| 80 | normal baseline comparison traffic | MERGE | BASE-00 | Folded into the single negative control |

## Technology decisions

Deleted cases are not merely hidden from the catalog: unsupported PHP, Java, Spring, Bash CGI, SOAP, Windows, GraphQL, and NoSQL claims were removed. Real SSRF, upload, command simulation, exfiltration, C2, LFI, and prototype-merge services were added only where constrained behavior could be observed safely.
