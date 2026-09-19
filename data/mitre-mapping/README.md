# MITRE ATT&CK Mapping for IDS Alerts

Module độc lập xây CSDL retrieval từ `../attack_final.json`, map từng alert IDS/Suricata sang ATT&CK và cung cấp workflow n8n phân tích bằng Gemini:

`normalize → BM25 + ATTACK-BERT → fusion → cross-encoder → evidence guard → hierarchy/confusion → abstention`

Tài liệu cài đặt, vận hành và tích hợp n8n nằm tại [Hướng dẫn vận hành Mapping.md](Hướng%20dẫn%20vận%20hành%20Mapping.md).

Quick start từ thư mục `data`:

```powershell
docker network inspect soc_shared
python mitre-mapping\scripts\prepare_database.py --source attack_final.json
docker compose -f docker-compose.yaml up -d --build
python mitre-mapping\scripts\map_alert.py "test alert scan CH.txt" --expect T1595
```

API:

- `GET http://localhost:8000/health`
- `POST http://localhost:8000/map`
- `POST http://localhost:8000/webhook/map`

Evidence guard áp dụng policy hiện hành:

- `required_evidence` chỉ là cổng boolean và không cộng vào
  `raw_evidence_score`;
- technique cha/core không có required rule; sub-technique giữ gate dựa trên
  `event.type` hoặc `event.action`;
- candidate chỉ đi vào quyết định cuối khi có event signal từ một required
  hoặc positive rule khớp;
- rule name và tool name nằm ở positive/negative/exclusion, không nằm ở
  required.

Kết quả kiểm thử thật được lưu ở `reports/test-alert-scan-CH.result.json`.

Workflow n8n đầy đủ và summary nằm tại `integrations/n8n/`.
