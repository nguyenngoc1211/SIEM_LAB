# SOC Attack Scenarios v2

This image provides the 19-scenario v2 runner for the local Juice Shop/Nginx/Suricata/Wazuh lab. Despite the retained directory name for compatibility, the image and CLI version are `2.0.0`.

The runner rejects non-lab targets by default. It does not scan address ranges or public hosts. Server-side egress actions are performed by the constrained lab backend and can address only the internal aliases implemented by that backend.

## Commands

```powershell
# Catalog and chains
docker exec soc_attacker_v2 attackctl list
docker exec soc_attacker_v2 attackctl chains

# One scenario
docker exec soc_attacker_v2 attackctl run WEB-06

# An explicit ordered batch
docker exec soc_attacker_v2 attackctl run-batch WEB-06 WEB-07 AUTH-11 --pause 2

# A category or every atomic scenario
docker exec soc_attacker_v2 attackctl run-category auth --pause 2
docker exec soc_attacker_v2 attackctl run-all --pause 2

# One composite chain
docker exec soc_attacker_v2 attackctl run-chain CHAIN-A

# Preview without traffic
docker exec soc_attacker_v2 attackctl run-batch RECON-01 WEB-06 --dry-run

# Correlate ground truth, EVE, Wazuh, and MITRE metadata
docker exec soc_attacker_v2 attackctl report --output-dir /opt/soc/runtime/reports --mapper-url http://host.docker.internal:8000
```

Outputs are written to the host-mounted `runtime/ground-truth` and `runtime/reports` directories. See `../SCENARIOS_V2.md` for scenario semantics and `../MIGRATION_V1_TO_V2.md` for the complete 80-to-19 disposition.
