# Hướng dẫn bàn giao CSDL và hệ thống ATT&CK Mapping

## 1. Kết quả đã triển khai

Mã hệ thống nằm trong thư mục `mitre-mapping/`, còn toàn bộ container được quản lý bởi một compose gốc `../docker-compose.yaml` với project duy nhất tên `data`. Bản dữ liệu làm giàu chuẩn nằm tại `artifacts/attack/attack_final.mapping.json`; collection `mitre_mitigations`, dữ liệu n8n, `./qdrant` và model trong `./tei` không bị xóa.

Các phần đã hoàn thành:

1. Validator kiểm tra schema/semantic, ID trùng, quan hệ cha-con, confusable reference, operator, evidence field, weight và metadata.
2. Mapping-ready snapshot có SHA-256, không sửa master database.
3. Technique documents và procedure documents tách riêng; tối đa 8 procedure đại diện được đưa vào dense text.
4. Qdrant collection `attack_techniques_v1` có named vector `dense` 768 chiều và named sparse vector `sparse` theo BM25.
5. Dense embedding dùng `basel/ATTACK-BERT` từ container hiện có, cache tại `./tei`.
6. BM25 và dense chạy độc lập Top 30, chuẩn hóa score, fusion 0.4/0.6 thành Top 20.
7. Cross-encoder `cross-encoder/ms-marco-MiniLM-L-6-v2` revision `c5ee24cb16019beea0893ab7796b1df96625c6b8` rerank Top 20 thành Top 5; model được cache tại `./tei/reranker`.
8. Evidence engine hỗ trợ `equals`, `contains_any`, `exists`, `in`, `greater_than_or_equal`, `matches_regex`.
9. Required, exclusion, positive, negative evidence; confusion guard; fallback sub-technique về parent khi parent có trong index; ba trạng thái `mapped`, `uncertain`, `insufficient_evidence`.
10. FastAPI cho CLI, gọi trực tiếp và Webhook/n8n.
11. Workflow n8n import-ready gồm chuẩn hóa, ATT&CK mapping, Gemini structured analysis, tạo payload analyst và fallback khi API lỗi.

### Bổ sung CSDL có chủ đích

Snapshot `artifacts/attack/attack_final.mapping.json` là nguồn làm giàu chuẩn.
File `configs/technique_overrides.json` vẫn được merge khi build để giữ khả
năng hiệu chỉnh riêng cho thực nghiệm, nhưng hiện để rỗng để không ghi đè dữ
liệu mới. Required evidence chỉ là cổng boolean và không cộng vào
`evidence_score`.

Database hiện hỗ trợ 18 technique. Parent, sub-technique hoặc confusable
reference nằm ngoài subset chỉ tạo warning. Khi parent không có trong index,
pipeline không tạo fallback; technique không khai báo parent cũng không có
fallback. Pipeline không tự sinh ATT&CK ID ngoài các point đã index.

## 2. Cấu trúc quan trọng

```text
mitre-mapping/
├── configs/
│   ├── settings.json
│   └── technique_overrides.json
├── artifacts/                 # Dữ liệu sinh bởi ứng dụng, không phải Docker project
│   ├── attack/
│   │   ├── attack_final.mapping.json
│   │   └── index_manifest.json
│   └── retrieval/
│       ├── technique_documents.jsonl
│       ├── procedure_documents.jsonl
│       └── bm25_index.json
├── integrations/n8n/mitre-mapping-webhook.workflow.json
├── reports/test-alert-scan-CH.result.json
├── schemas/
├── scripts/
├── src/mitre_mapper/
├── tests/
└── Dockerfile / Dockerfile.reranker
```

Ở thư mục cha: `./qdrant` là storage Qdrant, `./n8n` là runtime n8n, `./tei` chứa cache của cả embedding (`basel/ATTACK-BERT`) và `./tei/reranker`. Không còn compose thứ hai trong `mitre-mapping`.

`index_manifest.json` lưu version, SHA-256 của master/snapshot, ATT&CK version, model/revision, số technique/procedure và thời điểm build.

## 3. Cài đặt lần đầu

Các lệnh dưới đây chạy trong PowerShell tại thư mục `...\code\data`.

### Bước 1 — Docker và network

Mở Docker Desktop và xác minh:

```powershell
docker info
docker network inspect soc_shared
```

Nếu `soc_shared` chưa tồn tại:

```powershell
docker network create soc_shared
```

Nếu Docker Desktop mở nhưng engine chưa chạy và `docker-desktop` đang `Stopped`:

```powershell
wsl -d docker-desktop -u root --exec /bin/true
docker info
```

### Bước 2 — Build CSDL mapping-ready

```powershell
python mitre-mapping\scripts\prepare_database.py
python mitre-mapping\scripts\validate_attack_final.py
```

Validator phải trả `"errors": []`. Warning về reference ngoài supported subset là thông tin kiểm kê.

### Bước 3 — Chạy toàn bộ project `data`

```powershell
docker compose -f docker-compose.yaml up -d --build
docker compose -f docker-compose.yaml ps -a
```

Lệnh duy nhất này quản lý Qdrant, embedding, n8n, reranker, indexer và mapper dưới một mục `data` trong Docker Desktop. Không chạy compose khác trên cùng `./qdrant`.

Kết quả đúng:

- `reranker-api`: `healthy`;
- `indexer`: `Exited (0)` sau khi tạo/upsert index;
- `mapper-api`: `healthy`;
- `GET http://localhost:6333/collections/attack_techniques_v1`: `green`, 18 point.

Lần đầu build reranker tải PyTorch và model nên lâu; các lần sau dùng image/cache đã có.

### Bảo vệ API

Trong lab nội bộ có thể để `MAPPER_API_KEY` rỗng. Trước khi expose ra mạng, tạo `mitre-mapping/.env` từ `.env.example`, thay secret mạnh rồi restart:

```powershell
$env:MAPPER_API_KEY = "replace-with-a-strong-secret"
docker compose -f docker-compose.yaml up -d
```

Client phải gửi header `X-API-Key` đúng giá trị. Không commit `.env` chứa secret.

## 4. Kiểm thử

### Unit và integration fallback

Không cần cài package Python ngoài:

```powershell
Set-Location mitre-mapping
python -m unittest discover -s tests -v
Set-Location ..
```

### Production pipeline với alert yêu cầu

```powershell
python mitre-mapping\scripts\map_alert.py "test alert scan CH.txt" `
  --expect T1595 `
  --output mitre-mapping\reports\test-alert-scan-CH.result.json
```

Kết quả đã xác minh lại với database 18 technique ngày 2026-09-19:

```json
{
  "mapping_status": "mapped",
  "primary_mapping": {
    "technique_id": "T1595",
    "name": "Active Scanning",
    "confidence": 0.884473
  },
  "degraded_modes": []
}
```

Confidence hiện là candidate score theo tài liệu đề xuất, chưa phải xác suất đã calibration.

### Gọi API trực tiếp

```powershell
$body = Get-Content -LiteralPath "test alert scan CH.txt" -Raw -Encoding UTF8
Invoke-RestMethod -Method Post `
  -Uri "http://localhost:8000/webhook/map" `
  -ContentType "application/json" `
  -Headers @{ "X-API-Key" = "your-key-if-enabled" } `
  -Body $body
```

API nhận cả alert chuẩn hóa trực tiếp và payload n8n dạng `{ "body": { ...alert... } }`. Raw Wazuh/Suricata phổ biến cũng được normalizer chuyển đổi thận trọng; field không có sẽ để trống/unknown, không tự suy diễn outcome.

## 5. Dùng kết quả cho analyst

Các field chính:

- `mapping_status`: quyết định cuối.
- `primary_mapping`: technique/name/confidence nếu có mapping.
- `supporting_evidence`: field thực tế làm tăng độ tin cậy.
- `contradictory_evidence`: evidence âm, exclusion hoặc confusion penalty.
- `alternative_candidates`: phương án khác và lý do loại.
- `candidate_trace`: BM25, dense, fusion, rerank, evidence và final score để audit.
- `pipeline`: version/hash/collection/model, latency và degraded mode.

Quy tắc xử lý:

- `mapped`: có thể đưa vào enrichment của case nhưng analyst vẫn duyệt theo playbook.
- `uncertain`: xem Top 2 và evidence, không tự động đóng case.
- `insufficient_evidence`: giữ alert gốc, bổ sung telemetry; không ép ATT&CK ID.

Không gửi `alert_id`, timestamp chính xác hoặc flow ID vào embedding. Các field này vẫn có thể nằm trong `normalized_alert` để truy vết.

## 6. Đưa lên n8n bằng Webhook

### Import workflow

1. Mở `http://localhost:5678`.
2. Chọn **Import from File**.
3. Chọn `mitre-mapping/integrations/n8n/mitre-mapping-webhook.workflow.json`.
4. Mở node **Map to ATT&CK** và kiểm tra URL `http://mapper-api:8000/webhook/map`.
5. Cấu hình `GEMINI_API_KEY` theo `integrations/n8n/WORKFLOW_SUMMARY.md`.
6. Nếu mapper đã bật API key, đặt cùng `MAPPER_API_KEY` cho container n8n.
7. Save và Activate workflow.

Container n8n và mapper cùng `soc_shared`, vì vậy n8n dùng hostname `mapper-api`; không dùng `localhost:8000` từ bên trong n8n.

### Test trong editor

Nhấn **Listen for test event**, sau đó:

```powershell
$body = Get-Content -LiteralPath "test alert scan CH.txt" -Raw -Encoding UTF8
Invoke-RestMethod -Method Post `
  -Uri "http://localhost:5678/webhook-test/soc-alert-analysis" `
  -ContentType "application/json" `
  -Body $body
```

### URL production

Sau khi Activate:

```text
POST http://localhost:5678/webhook/soc-alert-analysis
Content-Type: application/json
```

Workflow gồm tám node: nhận Webhook → chuẩn hóa → mapping → dựng request Gemini → Gemini → parse/validate → dựng cảnh báo analyst → trả JSON. Chi tiết hợp đồng dữ liệu và xử lý lỗi nằm tại `integrations/n8n/WORKFLOW_SUMMARY.md`.

## 7. Cập nhật CSDL và rebuild index

Sau khi sửa `artifacts/attack/attack_final.mapping.json` hoặc override:

```powershell
python mitre-mapping\scripts\prepare_database.py
python mitre-mapping\scripts\validate_attack_final.py
docker compose -f docker-compose.yaml build indexer mapper-api
docker compose -f docker-compose.yaml run --rm indexer `
  python scripts/build_qdrant_index.py --wait 300 --recreate
docker compose -f docker-compose.yaml up -d mapper-api
```

`--recreate` cần dùng khi thay toàn bộ tập technique để point thuộc database cũ
không còn trong Qdrant. Tùy chọn này chỉ xóa/tạo lại collection cấu hình
`attack_techniques_v1`, không đụng collection `mitre_mitigations`.

## 8. Vận hành và xử lý lỗi

```powershell
docker compose -f docker-compose.yaml ps -a
docker compose -f docker-compose.yaml logs --tail 100 mapper-api reranker-api indexer
Invoke-RestMethod http://localhost:8000/health
Invoke-RestMethod http://localhost:6333/collections/attack_techniques_v1
```

- Port 6333/8080 bị chiếm: kiểm tra không còn project compose cũ ngoài `data`.
- `indexer Exited (1)`: kiểm tra log Qdrant và embedding trong cùng project `data`.
- n8n không gọi được mapper: kiểm tra cả hai container có network `soc_shared` và dùng hostname `mapper-api`.
- reranker tải model lại: kiểm tra bind mount `./tei/reranker:/models` và quyền ghi.
- API trả 503: xem `docker compose ... logs mapper-api`; production đã tắt local fallback để lỗi hạ tầng không bị che giấu.

## 9. Vocabulary evidence cần thống nhất ở upstream

Evidence guard yêu cầu ít nhất một `event.*` rule thuộc `required_evidence`
hoặc `positive_evidence` khớp. Với alert đã chuẩn hóa, upstream cần dùng đúng
vocabulary của database mới, đặc biệt:

- `event.type`: `network_scan`, `network_communication`, `authentication`,
  `web_request` hoặc `service_access` theo loại alert;
- `event.action`: `scan`, `probe`, `discover`, `connect`, `login`,
  `authenticate`, `exploit` hoặc `flood`;
- `event.outcome`: `success` hoặc `failure`;
- `network.direction`: database hiện có cả vocabulary semantic
  (`inbound`, `outbound`, `lateral`) và Suricata (`to_server`, `to_client`);
- `target.type`: một số rule dùng `host` hoặc `application`, trong khi nhánh
  raw Wazuh của normalizer hiện mặc định là `service`;
- `http.status_code`: evidence dùng số nguyên `401`/`403`; upstream không nên
  gửi chuỗi `"401"`/`"403"`;
- khi không biết `network.application_protocol`, normalizer raw để trống chứ
  không sinh literal `unknown`.

Rule `T1498-POS-002` trước đây dùng field không tồn tại
`network.transport_protocol`; bản build này đã sửa sang field chuẩn
`network.transport`.

## 10. Giới hạn nghiên cứu hiện tại

- Mapping từng alert độc lập, không correlation theo chuỗi thời gian.
- Supported subset là 18 technique, không phải toàn bộ Enterprise ATT&CK.
- Dataset ground truth lớn, calibration, baseline metrics và confusion matrix chưa nằm trong phạm vi kiểm thử alert đơn hiện tại.
- Model MS MARCO là baseline reranker tiếng Anh; cần validation set SOC thực tế trước khi tối ưu threshold hoặc thay model.
- Mọi mapping tự động cần lưu candidate trace và được analyst duyệt khi dùng cho quyết định có tác động cao.
