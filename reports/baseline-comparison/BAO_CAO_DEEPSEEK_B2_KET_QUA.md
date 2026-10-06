# Báo cáo kết quả baseline B2 (DeepSeek-only) – 90 scenario

Ngày thực hiện: 2026-10-06

## 1. Tóm tắt

- Baseline **B2 đã được chuyển từ Gemini sang DeepSeek**. Toàn bộ tên arm, prompt,
  config và CLI của B2 nay dùng hậu tố `deepseek_only`.
- API key lấy từ biến môi trường `DEEPSEEK_API_KEY_NCKH` (không ghi key ra file
  hay ra log).
- Đã chạy đủ **90/90 scenario** của dataset đóng băng, không có scenario nào lỗi
  hay bị bỏ sót.
- Không gặp lỗi `429`/`503` nên cơ chế giãn tần suất chỉ giữ ở mức nền; tham số
  động vẫn được bật để tự giãn khi provider trả về rate limit.

Kết quả chính trên 90 scenario:

| Strategy | N | Exact top-1 | Top-3 hit | Partial credit | Wrong primary | Coverage | Abstain | Trung vị latency |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `bm25_only` (B1) | 90 | 34.4% | 67.8% | 37.2% | 60.0% | 100% | 0.0% | 1.24 ms |
| **`deepseek_only` (B2)** | 90 | **58.9%** | **94.4%** | **63.3%** | 27.8% | 95.6% | 4.4% | 6.532 s |
| `hybrid_current` (tham chiếu lưu trữ) | 90 | 47.8% | 81.1% | 53.3% | 18.9% | 77.8% | 22.2% | 2.228 s |

Wilson 95% CI cho `deepseek_only`: exact top-1 `[48.6%, 68.5%]`,
top-3 `[87.7%, 97.6%]`.

McNemar theo `primary_hit`:

- `bm25_only` vs `deepseek_only`: 8 case chỉ BM25 đúng, 30 case chỉ DeepSeek đúng,
  p = 0.00047.
- `deepseek_only` vs `hybrid_current`: 21 case chỉ DeepSeek đúng, 11 case chỉ hybrid
  đúng, p = 0.110 (khác biệt chưa có ý nghĩa thống kê ở mức 90 scenario).

## 2. Cấu hình B2

| Khóa | Giá trị |
|---|---|
| Provider | DeepSeek (API tương thích OpenAI, `/chat/completions`) |
| Model | `deepseek-flash` |
| Mode | `closed_set` trên 18 technique được hỗ trợ |
| Temperature | 0.0 |
| Repeats | 1 |
| Max output tokens | 8192 |
| API key env | `DEEPSEEK_API_KEY_NCKH` |
| Request timeout | 300 s |
| Max retries | 2 |
| Base interval giữa 2 request | 1.5 s |
| Backoff cap | 60 s |

Prompt: `prompts/deepseek_only_v1.md` (`prompt_version = deepseek-only-1.0.0`).
DeepSeek không có `responseSchema` như Gemini nên output được ép bằng
`response_format = {"type": "json_object"}` và schema được mô tả ngay trong prompt;
strategy vẫn kiểm tra ID hợp lệ, ID ngoài subset và trạng thái abstain như B2 cũ.

## 3. Cơ chế giãn tần suất theo trạng thái trả về

Chiến lược pacing nằm trong `DeepSeekOnlyStrategy`:

- Khoảng cách nền giữa hai request là 1.5 s.
- Khi gặp `429`, `500`, `502`, `503`, `504`: khoảng cách bị **nhân đôi** (tối đa
  8 lần nền) và có backoff lũy thừa, tôn trọng `retry_after`/`retryDelay` nếu
  provider trả về.
- Sau 3 lần gọi thành công liên tiếp, khoảng cách tự **co lại 70%** về mức nền.
- Nếu gặp `401/402/403` hoặc `insufficient_balance` thì dừng ngay bằng
  `QuotaExhausted` thay vì đốt quota.

Trong lần chạy này không có response `429/503` nào, nên khoảng cách thực tế giữ ở
1.5 s và tổng thời gian chạy 90 scenario khoảng 12–13 phút.

## 4. Kết quả theo trạng thái và độ trễ

| Chỉ số | Giá trị |
|---|---:|
| `mapped` | 65 |
| `uncertain` | 21 |
| `insufficient_evidence` | 4 |
| `error` / `skipped` / `invalid_output` | 0 |

Độ trễ `deepseek_only` (ms): min 4134, median 6532, mean 8043, p95 18093, max 21327.

Trong 90 scenario có 93 dòng checkpoint: 3 lần trả về `invalid_output` đã được
chạy lại và cho kết quả hợp lệ, không còn dòng lỗi nào ở trạng thái cuối.

## 5. Kết quả theo nhóm

| Strategy | Group | N | Exact top-1 | Top-3 hit | Partial credit |
|---|---|---:|---:|---:|---:|
| `deepseek_only` | A1 | 15 | 33.3% | 86.7% | 33.3% |
| `deepseek_only` | A2 | 75 | 64.0% | 96.0% | 69.3% |

DeepSeek mạnh hơn rõ rệt ở nhóm A2 (64.0% top-1) và yếu ở nhóm A1 web (33.3%),
giống xu hướng chung của các baseline khi nhóm A1 có nhiều nhãn gây tranh luận.

## 6. Phân tích lỗi điển hình

Các nhóm map sai nhiều nhất:

- `T1210` (5/5 sai, đều chọn `T1190`): đây là nhóm nhãn ET Open gây tranh luận đã
  ghi nhận trong thí nghiệm Gemini trước đó; `T1210` luôn nằm trong top-3.
- Họ `T1595` bị lẫn với `T1046` và lẫn nội bộ trong họ: `T1595` 1/5,
  `T1595.001` 0/5, `T1595.002` 2/5, `T1595.003` 3/5. Top-3 vẫn phủ gần hết.
- `T1110.001` 0/5 nhưng primary là cha `T1110` nên vẫn được partial credit 0.5.
- `T1189` 1/5, phần lớn bị map sang `T1659` (Content Injection).
- Abstain 4 case: `A2-T1071.001-04`, `A2-T1095-01`, `A2-T1095-05`,
  `A2-T1659-04`.

Top-3 đạt 94.4% cho thấy phần lớn lỗi top-1 nằm ở bước chọn kỹ thuật trúng nhất,
không phải ở bước gợi ý ứng viên.

## 7. Tệp kết quả

| Đường dẫn | Nội dung |
|---|---|
| `REPORT.md` | Report chính của bundle (kèm ngày cập nhật) |
| `comparison.md` | Bảng tóm tắt để đưa vào báo cáo |
| `comparison.csv` | Chi tiết từng scenario × strategy |
| `comparison.json` | Dữ liệu đầy đủ, breakdown theo nhóm/họ |
| `raw_results/deepseek_only.jsonl` | Output thô 90 scenario (tier 2, git ignore) |
| `checkpoints/deepseek_only.jsonl` | Checkpoint resume (tier 2, git ignore) |
| `run_metadata.json` | Config, hash dataset, đường dẫn report |

Các đường dẫn trên tính từ gốc bundle `reports/baseline-comparison/`.

## 8. Lệnh tái lập

Đứng tại `NCKH_Code/code/data/mitre-mapping`, đảm bảo biến môi trường
`DEEPSEEK_API_KEY_NCKH` đã được set, rồi chạy:

```powershell
python scripts\run_baselines.py --strategies bm25_only,deepseek_only
```

Mặc định runner ghi vào `reports/baseline-comparison/` ở gốc repo; chỉ cần thêm
`--output-dir` nếu muốn tách một bundle khác.

Chạy theo từng đoạn để resume (scenario lỗi/chưa chạy được ưu tiên trước):

```powershell
python scripts\run_baselines.py --strategies bm25_only,deepseek_only `
  --limit 20
```

`--limit` áp trên danh sách đã ưu tiên, nên chạy lặp lại với cùng `--limit` sẽ
luôn xử lý nhóm còn thiếu trước. Dùng `--no-prioritize-pending` để tắt ưu tiên này.

## 9. Hạn chế và việc tiếp theo

- DeepSeek phản hồi chậm hơn hybrid (trung vị 6.5 s so với 2.2 s) nhưng bù lại
  top-1 và top-3 cao hơn.
- `hybrid_current` là dữ liệu lưu trữ, chưa chạy lại trên input đã sanitize, nên
  chỉ là mốc tham chiếu.
- Khác biệt DeepSeek vs hybrid chưa có ý nghĩa thống kê ở mức 90 scenario; nên đọc
  kèm Wilson CI và McNemar.
- Có thể chạy thêm arm `deepseek-v4-pro` để so sánh chất lượng/chi phí, hoặc
  `--repeats 3` để đo self-consistency.
