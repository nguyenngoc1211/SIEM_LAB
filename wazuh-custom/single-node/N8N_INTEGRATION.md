# Wazuh -> n8n integration

Wazuh forwards every generated alert (the current minimum stored alert level is
`3`) to the active n8n workflow **SOC Alert Mapping + Gemini Analysis**.

## Data path

`Wazuh alert` -> `custom-n8n.py` ->
`http://n8n:5678/webhook/soc-alert-analysis` -> ATT&CK mapper -> Gemini analysis

The `soc_shared` Docker network provides the internal DNS name `n8n`. Do not
replace it with `localhost`: inside the Wazuh container, `localhost` means the
Wazuh container itself.

## Start

From the repository root in PowerShell:

```powershell
docker compose -f data\docker-compose.yaml up -d
docker exec n8n-orchestrator n8n update:workflow --id=jkT3r1ENFjZBuGNO --active=true
docker compose -f wazuh-docker\single-node\docker-compose.yml -f wazuh-docker\single-node\docker-compose.suricata.yml up -d
```

The n8n workflow ID above belongs to the current local n8n database. If the
database is replaced, run `docker exec n8n-orchestrator n8n list:workflow`, find
**SOC Alert Mapping + Gemini Analysis**, and substitute its new ID.

## Change the n8n webhook URL

The integration reads `N8N_WEBHOOK_URL` first and uses the URL in
`wazuh_manager.conf` only as a fallback. This means the URL can be changed
without editing Wazuh XML.

1. In n8n, open the Webhook node of **SOC Alert Mapping + Gemini Analysis** and
   copy its **Production URL**. Do not copy the test URL containing
   `/webhook-test/`.
2. Copy the example environment file and edit its value:

```powershell
Copy-Item wazuh-docker\single-node\n8n-integration.env.example wazuh-docker\single-node\n8n-integration.env
notepad wazuh-docker\single-node\n8n-integration.env
```

3. Recreate only the manager with that environment file:

```powershell
docker compose --env-file wazuh-docker\single-node\n8n-integration.env `
  -f wazuh-docker\single-node\docker-compose.yml `
  -f wazuh-docker\single-node\docker-compose.suricata.yml `
  up -d --force-recreate wazuh.manager
```

4. Confirm the effective value and send a test alert:

```powershell
docker exec single-node-wazuh.manager-1 printenv N8N_WEBHOOK_URL
```

Use `http://n8n:5678/webhook/<path>` while n8n remains in the same
`soc_shared` network. If n8n runs directly on this Windows host, use
`http://host.docker.internal:5678/webhook/<path>`. If it moves to another
server, use its reachable HTTPS URL, for example
`https://n8n.example.org/webhook/<path>`, and ensure firewall/DNS/TLS access
from the Wazuh container.

## Verify

```powershell
docker exec single-node-wazuh.manager-1 sh -c "grep -n 'custom-n8n\|soc-alert-analysis' /var/ossec/etc/ossec.conf"
docker exec single-node-wazuh.manager-1 ls -l /var/ossec/integrations/custom-n8n /var/ossec/integrations/custom-n8n.py
docker logs --since 10m single-node-wazuh.manager-1
docker logs --since 10m n8n-orchestrator
```

For an end-to-end test through the exact Wazuh integration script:

```powershell
docker cp wazuh-docker\single-node\test-n8n-alert.json single-node-wazuh.manager-1:/tmp/test-n8n-alert.json
docker exec -e N8N_WEBHOOK_DEBUG=1 single-node-wazuh.manager-1 `
  /var/ossec/integrations/custom-n8n /tmp/test-n8n-alert.json unused `
  http://n8n:5678/webhook/soc-alert-analysis
```

Exit code `0` and a JSON response mean Wazuh reached n8n and the workflow ran
through its response node. The reserved documentation addresses in the sample
(`192.0.2.0/24`) are not real targets.

In n8n, open **Executions** to see each alert and the ATT&CK/Gemini result.
The production webhook is available only while the workflow is active.

## Important settings

- Wazuh `log_alert_level` is `3`, and the integration `level` is also `3`.
  Therefore every alert Wazuh currently writes is forwarded.
- The n8n container must have `GEMINI_API_KEY` and, when enabled by the mapper,
  `MAPPER_API_KEY` set to the matching value.
- `N8N_WEBHOOK_TIMEOUT` can be changed in the same environment file if the
  mapping/Gemini chain needs more than the default 120 seconds.
- Keep both stacks attached to the external `soc_shared` network.

## Troubleshooting

- HTTP 404 from n8n: activate the workflow and confirm the path is
  `/webhook/soc-alert-analysis` (not `/webhook-test/...`).
- DNS/connection error for `n8n`: inspect both containers and confirm they are
  attached to `soc_shared`.
- Wazuh reports an integration script error: confirm the two bind-mounted files
  exist and are executable/readable inside `/var/ossec/integrations`.
- Workflow runs but Gemini falls back: check `GEMINI_API_KEY`, n8n logs, and the
  `Analyze with Gemini` node output.
