# Summary — SOC Alert Mapping + Gemini Analysis

## Mục tiêu

Workflow nhận một alert IDS/Suricata qua Webhook, chuẩn hóa ngữ cảnh, gọi pipeline ATT&CK mapping nội bộ, dùng Gemini phân tích bằng chứng, sau đó trả một payload cảnh báo thống nhất cho analyst.

```text
Webhook
  → Normalize Alert
  → Map to ATT&CK
  → Prepare Gemini Request
  → Analyze with Gemini
  → Parse Gemini Analysis
  → Build Analyst Alert
  → Return Analyst Alert
```

File import: `mitre-mapping-webhook.workflow.json`.

Workflow có ID ổn định `socAlertGeminiV1` để tương thích với lệnh import của n8n 2.x.

## Các node

| Node | Chức năng |
|---|---|
| `Receive IDS Alert` | Nhận POST tại path `soc-alert-analysis`, trả kết quả bằng Respond to Webhook. |
| `Normalize Alert` | Nhận `body` object/string, Wazuh `_source`, normalized alert hoặc generic alert; tạo `mapper_input` và `alert_context` ổn định. |
| `Map to ATT&CK` | Gửi alert tới `http://mapper-api:8000/webhook/map`; dùng kết quả mapping deterministic hiện tại. |
| `Prepare Gemini Request` | Rút gọn alert và mapping thành prompt; tạo response schema bắt buộc. |
| `Analyze with Gemini` | Gọi `gemini-2.5-flash:generateContent` bằng header `x-goog-api-key`. |
| `Parse Gemini Analysis` | Kiểm tra `error`, `promptFeedback`, `candidates`, `finishReason`, parts và JSON; tạo fallback an toàn nếu Gemini lỗi/bị block. |
| `Build Analyst Alert` | Tạo incident ID ổn định, payload analyst, message tiếng Việt, mapping trace, LLM metadata và processing errors. |
| `Return Analyst Alert` | Trả JSON hoàn chỉnh cho caller của Webhook. |

## Các thay đổi so với workflow mẫu

- Thay endpoint mapping cũ `/analyze` bằng API thật `/webhook/map` và schema output mới (`mapping_status`, `primary_mapping`, evidence, alternatives, pipeline).
- Prompt Gemini được viết hoàn toàn bằng tiếng Anh. Prompt yêu cầu các giá trị mô tả dành cho analyst viết bằng tiếng Việt; JSON key và enum giữ tiếng Anh.
- Không đặt API key trực tiếp trong URL/workflow. Key lấy từ biến môi trường `GEMINI_API_KEY` và gửi bằng `x-goog-api-key`.
- Dùng structured output với `responseMimeType: application/json` và response schema có kiểu/enum rõ ràng.
- Không truy cập trực tiếp `candidates[0].content.parts[0]`; mọi cấp dữ liệu đều được kiểm tra trước.
- Xử lý được `body` dạng JSON string, object, array, `_source`, alert đã chuẩn hóa và field bị thiếu.
- Hai HTTP node dùng `continueRegularOutput`; lỗi mapper/Gemini được đưa vào `processing.errors` thay vì làm workflow mất phản hồi.
- Gemini không được phép tạo hoặc thay ATT&CK ID. Technique ID chỉ đến từ mapper deterministic.
- `soar_action` chỉ là khuyến nghị. Workflow đặt `action_executed: false`, không tự block IP hoặc isolate host.
- Sửa lỗi đặt tên `recommended_mitigration` thành `recommended_actions` và chuẩn hóa toàn bộ key sang snake_case.

## Hợp đồng dữ liệu giữa các node

`Normalize Alert` trả:

```json
{
  "mapper_input": {},
  "alert_context": {
    "signature": "...",
    "source_ip": "...",
    "destination_ip": "...",
    "http": {}
  },
  "normalization": {
    "ok": true,
    "warnings": []
  }
}
```

`Build Analyst Alert` trả:

```json
{
  "incident_id": "inc-YYYYMMDD-hash",
  "alert": {},
  "network": {},
  "attack_mapping": {},
  "ai_analysis": {},
  "llm_meta": {},
  "decision": {
    "need_admin_verification": true,
    "recommended_soar_action": "admin_approval",
    "action_executed": false
  },
  "processing": {
    "errors": []
  },
  "analyst_message": "..."
}
```

## Cấu hình Gemini

Không commit API key. Từ thư mục `data`, tạo file local dựa trên mẫu:

```powershell
Copy-Item mitre-mapping\.env.example mitre-mapping\.env
```

Sửa dòng:

```text
GEMINI_API_KEY=your-real-google-ai-studio-key
```

Sau đó recreate n8n bằng cùng env file:

```powershell
docker compose --env-file mitre-mapping\.env -f docker-compose.yaml up -d n8n
```

Nếu mapper bật API key, đặt `MAPPER_API_KEY` trong cùng file và recreate cả `n8n` lẫn `mapper-api`.

## Import và sử dụng

1. Mở `http://localhost:5678`.
2. Import `mitre-mapping/integrations/n8n/mitre-mapping-webhook.workflow.json`.
3. Kiểm tra node `Analyze with Gemini` hiển thị expression `$env.GEMINI_API_KEY`.
4. Save và Activate.
5. Test URL: `http://localhost:5678/webhook-test/soc-alert-analysis`.
6. Production URL: `http://localhost:5678/webhook/soc-alert-analysis`.

Ví dụ PowerShell sau khi nhấn **Listen for test event**:

```powershell
$body = Get-Content -LiteralPath "test alert scan CH.txt" -Raw -Encoding UTF8
Invoke-RestMethod -Method Post `
  -Uri "http://localhost:5678/webhook-test/soc-alert-analysis" `
  -ContentType "application/json" `
  -Body $body
```

## Kiểm thử kỹ thuật

`tests/test_n8n_workflow.js` thực hiện:

- compile cú pháp của cả bốn Code node;
- chạy normalizer với payload Wazuh bọc trong `body`;
- kiểm tra Gemini prompt có mapping T1595 và structured-output config;
- kiểm tra phần prompt được dựng từ fixture ASCII không chứa ký tự tiếng Việt;
- parse response Gemini hợp lệ;
- dựng payload analyst;
- kiểm tra fallback khi Gemini không trả candidate và bị safety block.

Chạy lại:

```powershell
node mitre-mapping\scripts\build_n8n_workflow.js
node mitre-mapping\tests\test_n8n_workflow.js
```

File JSON cũng đã được import thành công bằng CLI của container n8n 2.29.9 với một `N8N_USER_FOLDER` tạm. Phép thử này không ghi vào database n8n thật. Kết nối nội bộ từ n8n tới `mapper-api` và Qdrant đã được xác nhận healthy.

Kiểm thử runtime bằng `test alert scan CH.txt` trả `mapping_status=mapped`, technique `T1595 — Active Scanning`, confidence `0.980645`.

Không có Gemini key thật trong source nên kiểm thử tự động không gọi Google API. Mapping API và nhánh JavaScript được kiểm thử độc lập; sau khi cấu hình key, nên gửi một alert lab qua Webhook test trước khi Activate production.
