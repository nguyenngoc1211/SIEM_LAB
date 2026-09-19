# SOC Attacker Advanced v3.0.0 - 80 scenarios

All scenarios are safe lab traffic simulations. Each scenario sends an HTTP marker header `X-SOC-Scenario: SOCV3-XX` so custom Suricata rules can generate deterministic alerts.

| ID | Category | Scenario |
|---:|---|---|
| 01 | baseline | baseline home page |
| 02 | baseline | health and gateway endpoints |
| 03 | baseline | static asset crawl |
| 04 | baseline | robots sitemap discovery |
| 05 | baseline | normal product search |
| 06 | recon | ICMP and TCP connectivity |
| 07 | recon | DNS lookup service names |
| 08 | recon | selected port scan |
| 09 | recon | HTTP NSE enumeration |
| 10 | recon | internal TCP connect checks |
| 11 | http | HTTP OPTIONS enumeration |
| 12 | http | uncommon HTTP methods |
| 13 | headers | security header probe |
| 14 | headers | Host header override |
| 15 | headers | forwarded header spoofing |
| 16 | discovery | sensitive file probe |
| 17 | discovery | source-control artifact probe |
| 18 | discovery | backup and archive probe |
| 19 | discovery | admin panel discovery |
| 20 | discovery | debug metrics actuator discovery |
| 21 | api | API root discovery |
| 22 | api | Swagger and OpenAPI discovery |
| 23 | api | GraphQL GET markers |
| 24 | api | GraphQL introspection POST marker |
| 25 | discovery | small directory fuzzing |
| 26 | discovery | extension sweep |
| 27 | web | path normalization anomalies |
| 28 | traversal | encoded path traversal |
| 29 | traversal | Linux LFI traversal |
| 30 | traversal | Windows LFI traversal |
| 31 | traversal | PHP wrapper LFI markers |
| 32 | sqli | classic SQL injection markers |
| 33 | sqli | boolean SQL injection markers |
| 34 | sqli | UNION SQL injection markers |
| 35 | sqli | time-delay SQL injection markers |
| 36 | sqli | encoded SQL injection markers |
| 37 | nosqli | NoSQL operator login marker |
| 38 | nosqli | NoSQL regex body marker |
| 39 | xss | script XSS markers |
| 40 | xss | event handler XSS markers |
| 41 | xss | SVG and MathML XSS markers |
| 42 | injection | template injection markers |
| 43 | cmdi | command injection separator markers |
| 44 | cmdi | command injection JSON body markers |
| 45 | ssrf | SSRF localhost markers |
| 46 | ssrf | cloud metadata SSRF markers |
| 47 | ssrf | internal hostname SSRF markers |
| 48 | ua | scanner User-Agent set |
| 49 | ua | suspicious scanner headers |
| 50 | exploit-marker | Shellshock header marker |
| 51 | exploit-marker | Log4Shell header marker |
| 52 | exploit-marker | Spring4Shell marker |
| 53 | exploit-marker | Java serialization marker |
| 54 | exploit-marker | PHP serialization marker |
| 55 | xml | XXE marker |
| 56 | xml | SOAP XML marker |
| 57 | headers | CRLF injection markers |
| 58 | headers | request smuggling marker headers |
| 59 | headers | cache poisoning headers |
| 60 | headers | CORS preflight probes |
| 61 | web | open redirect markers |
| 62 | auth | JWT none algorithm marker |
| 63 | auth | invalid admin JWT marker |
| 64 | auth | cookie tampering markers |
| 65 | auth | session fixation marker |
| 66 | api | mass assignment markers |
| 67 | api | prototype pollution marker |
| 68 | upload | PHP upload marker |
| 69 | upload | double extension upload markers |
| 70 | upload | suspicious upload name markers |
| 71 | auth | login failure burst capped |
| 72 | auth | password spraying capped |
| 73 | auth | password guessing capped |
| 74 | auth | credential stuffing fake capped |
| 75 | rate | API rate-limit burst capped |
| 76 | egress | callback URL exfil markers |
| 77 | egress | base64 exfil marker |
| 78 | egress | fake C2 beacon markers |
| 79 | recon | internal service connect checks |
| 80 | baseline | normal baseline comparison traffic |
