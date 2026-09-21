Hiện mình chưa tìm thấy `attack_final_updated.json` trong thư mục `data` hoặc `mitre-mapping`. Bạn cần lưu/copy file vào đó trước.

Không cần đổi tên file nguồn. Script sẽ tự tạo lại artifact chuẩn `artifacts/attack/attack_final.mapping.json`.

## Chạy từ thư mục `data`

Giả sử cấu trúc:

```text
data/
├── attack_final_updated.json
├── docker-compose.yaml
└── mitre-mapping/
```

### 1. Build lại toàn bộ artifact

```powershell
python mitre-mapping\scripts\prepare_database.py `
  --source .\attack_final_updated.json
```

Lệnh này sẽ ghi lại:

```text
artifacts/attack/attack_final.mapping.json
artifacts/attack/index_manifest.json
artifacts/retrieval/technique_documents.jsonl
artifacts/retrieval/procedure_documents.jsonl
artifacts/retrieval/bm25_index.json
```

`configs/technique_overrides.json` hiện là `{}`, nên không có override cũ ghi đè dữ liệu mới.

### 2. Validate database đã build

```powershell
python mitre-mapping\scripts\validate_attack_final.py
```

Yêu cầu:

```json
{
  "errors": []
}
```

Parent nằm ngoài supported subset có thể xuất hiện trong `warnings`; đó không phải lỗi build.

### 3. Chạy test

```powershell
Set-Location mitre-mapping
python -m unittest discover -s tests -v
node tests\test_n8n_workflow.js
Set-Location ..
```

### 4. Build image mới

Artifact được copy vào Docker image, vì vậy phải build lại:

```powershell
docker compose -f docker-compose.yaml build indexer mapper-api
```

### 5. Recreate Qdrant collection

```powershell
docker compose -f docker-compose.yaml run --rm indexer `
  python scripts/build_qdrant_index.py --wait 300 --recreate
```

Nên dùng `--recreate` vì database mới có thể thêm hoặc loại bỏ technique. Tùy chọn này chỉ recreate collection `attack_techniques_v1`, không ảnh hưởng collection khác.

### 6. Recreate mapper API

```powershell
docker compose -f docker-compose.yaml up -d `
  --no-deps --force-recreate mapper-api
```

### 7. Kiểm tra kết quả

```powershell
Invoke-RestMethod http://localhost:8000/health
```

```powershell
Invoke-RestMethod `
  http://localhost:6333/collections/attack_techniques_v1
```

Kiểm tra số point Qdrant phải bằng `technique_count` trong:

```powershell
Get-Content mitre-mapping\artifacts\attack\index_manifest.json
```

### 8. Test một alert

```powershell
$body = Get-Content -LiteralPath ".\test alert scan CH.txt" `
  -Raw -Encoding UTF8

$result = Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:8000/webhook/map" `
  -ContentType "application/json" `
  -Body $body

$result | ConvertTo-Json -Depth 20
```

Kiểm tra:

```text
mapping_status
primary_mapping
candidate_trace
pipeline.attack_final_sha256
pipeline.degraded_modes
```

`pipeline.degraded_modes` nên là mảng rỗng.

Nếu bạn lưu file ngay trong thư mục `mitre-mapping`, chỉ cần đổi bước đầu thành:

```powershell
python scripts\prepare_database.py `
  --source .\attack_final_updated.json
```