# SOC Attack Scenarios v2

The former 80 marker-oriented cases were replaced by 19 catalog-backed behavioral scenarios and four composite chains.

The canonical scenario table, telemetry objectives, MITRE mappings, and rationale are documented in [`../../SCENARIOS_V2.md`](../../SCENARIOS_V2.md). The complete v1 disposition is in [`../../MIGRATION_V1_TO_V2.md`](../../MIGRATION_V1_TO_V2.md).

Examples:

```text
attackctl list
attackctl run WEB-06
attackctl run-batch RECON-01 RECON-02 WEB-06 --pause 2
attackctl run-category auth --pause 2
attackctl run-all --pause 2
attackctl chains
attackctl run-chain CHAIN-A
```

Ground-truth markers only delimit execution windows. Suricata and Wazuh detections must use observable behavior and never scenario IDs or names.
