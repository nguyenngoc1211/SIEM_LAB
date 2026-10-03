# A2 full-run handoff and issue log

## Final verified run

- Date: 2026-09-26
- Command: `docker exec soc_attacker_v2 python3 /opt/soc/a2_runner.py --all`
- Runner exit code: `0`
- A2 definitions: `soc-attacker-advanced-v3.0.0/scenarios/a2/`
- A2 reports: `runtime/reports/a2/`
- A2 ground truth: `runtime/ground-truth/a2-scenario-runs.jsonl`
- Active custom rule file: `sensor/a2.rules`
- Active SID range: `1002001-1002075`

| Phase | Result |
|---|---:|
| Scenario reports created | 75/75 |
| Overall | 75/75 PASS |
| Suricata detection | 75/75 PASS |
| Wazuh ingestion | 75/75 PASS |
| Exact MITRE TechID mapping | 75/75 PASS |
| Techniques validated | 16 |
| Negative durations | 0 |
| Reports missing an expected TechID | 0 |

No blocking A2 failure remains after this run.

## Resolved issues

### Mapper discarded authoritative Suricata metadata

Status: resolved.

The mapper now preserves `data.alert.signature_id` as the producer rule ID,
retains Wazuh rule `86601` only as collector provenance, and gives valid
`mitre_tactic_id`/`mitre_technique_id` values declared by the sensor rule
precedence over retrieval. The deterministic mapping source is
`sensor_rule_metadata` with confidence `1.0`.

The mapper source is in the sibling project:
`../data/mitre-mapping/src/mitre_mapper/`. Its host-side suite passed 19 tests;
one FastAPI integration test was skipped because FastAPI is not installed in
the host Python environment. The rebuilt `mitre-mapper` container is healthy.

### A2 rule noise contaminated later marker windows

Status: resolved for A2-generated noise.

- T1595.001 address sweeps are restricted to aliases `172.29.0.20-24`.
- The generic T1595 scan excludes normal gateway port 80.
- T1046 rules are restricted to the pinned internal path
  `172.29.0.2 -> 172.29.0.4`.
- Gateway, backend, Juice Shop, and attacker use stable addresses on
  `soc_backend`.

Some reports still list legitimate semantic overlaps from A1 or ET Open rules,
for example SIDs `1001014`, `1001015`, `2006380`, `2010920`, and `2031502`.
These are additional detections, not evaluation failures; the expected A2 SID
and TechID remain exact.

### Negative report durations during clock corrections

Status: resolved.

The runner now measures elapsed time with a monotonic clock and derives the
query/report end time from that duration. All 75 final reports have a
non-negative `duration_seconds`. A regression test covers this behavior.

### Intermittent misses in T1110.001 and T1110.003

Status: resolved.

The sub-technique rules now match stable request-side evidence: a fixed account
for password guessing and a shared password for password spraying. This avoids
depending on response-body visibility across both proxy legs. All ten
sub-technique scenarios passed in the final full run.

### T1499 threshold split by wall-clock jumps

Status: resolved.

In the failed run, the runner generated 12 requests in about 0.75 monotonic
seconds, while EVE timestamps jumped by more than 15 seconds between requests
8 and 9. This split the original 10-events/10-seconds detection window. The
threshold remains 10 requests but uses a 60-second window, which tolerates the
observed container clock correction. All five T1499 scenarios passed in the
final full run.

## Verification completed

- Suricata configuration/ruleset validation: PASS.
- Attacker container unit tests: 12/12 PASS.
- Mapper host tests: 19 PASS, 1 dependency-based skip.
- Report audit: 75 PASS, 0 negative durations, 0 missing expected TechIDs.

## Operational note for a later call

Immediately after recreating Suricata, wait until its health is `healthy`
before starting A2. A probe sent while the container was still
`health: starting` did not yet appear in EVE; rerunning after health became
ready passed normally. This was a startup-readiness condition, not a scenario
failure.

Useful verification command:

```powershell
docker compose ps
docker exec soc_suricata suricata -T -c /etc/suricata/suricata.yaml
docker exec soc_attacker_v2 python3 -m unittest discover -s /opt/soc/tests -v
docker exec soc_attacker_v2 python3 /opt/soc/a2_runner.py --all
```
