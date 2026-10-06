# MITRE ATT&CK Mapping for IDS Alerts

Module độc lập xây CSDL retrieval từ bản làm giàu chuẩn tại
`artifacts/attack/attack_final.mapping.json`, map từng alert IDS/Suricata sang
ATT&CK và cung cấp workflow n8n phân tích bằng LLM (baseline B2 dùng DeepSeek):

`normalize → BM25 + ATTACK-BERT → fusion → cross-encoder → evidence guard → hierarchy/confusion → abstention`

Tài liệu cài đặt, vận hành và tích hợp n8n nằm tại [Hướng dẫn vận hành Mapping.md](Hướng%20dẫn%20vận%20hành%20Mapping.md).

Quick start từ thư mục `data`:

```powershell
docker network inspect soc_shared
python mitre-mapping\scripts\prepare_database.py
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
- parent nằm ngoài tập technique được hỗ trợ chỉ tạo warning; fallback chỉ xảy
  ra khi parent thực sự có trong index. Technique không khai báo parent sẽ
  không có fallback.

Kết quả kiểm thử thật được lưu ở
`reports/baseline-comparison/test-alert-scan-CH.result.json` (gốc repo).

## Baseline so sánh

- B1 `bm25_only`: xếp hạng thuần BM25.
- B2 `deepseek_only`: DeepSeek chọn technique trong closed-set 18 technique.
- Tham chiếu `hybrid_current`: mapper hiện tại, lấy từ report lưu trữ.

Chạy và xem báo cáo:

```powershell
$env:DEEPSEEK_API_KEY_NCKH = "<key>"
python scripts\run_baselines.py --strategies bm25_only,deepseek_only
```

Runner mặc định ghi vào bundle `reports/baseline-comparison/` ở gốc repo.
Kết quả 90 scenario ở `reports/baseline-comparison/REPORT.md` (report chính) và
`BAO_CAO_DEEPSEEK_B2_KET_QUA.md` trong cùng bundle.

Workflow n8n đầy đủ và summary nằm tại `integrations/n8n/`.
