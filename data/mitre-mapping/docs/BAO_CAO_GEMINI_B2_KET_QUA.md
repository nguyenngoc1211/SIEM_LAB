# Báo cáo kết quả chạy baseline B2 (Gemini-only) – tạm dừng

Ngày thực hiện: 2026-10-05

## 1. Trạng thái

- Đã dừng toàn bộ tiến trình chạy Gemini theo yêu cầu.
- Không còn tiến trình Python nào đang chạy.
- Toàn bộ kết quả thành công và lý do lỗi đã được lưu vào snapshot tự chứa.

Snapshot chính: `reports/baselines/snapshots/gemini_attempts_20261005/`

## 2. Kết quả đạt được theo từng arm

| Arm | Model | Số scenario đã thử | Thành công | Lỗi | Lý do lỗi |
|---|---|---:|---:|---:|---|
| `gemini_only` | `gemini-2.5-flash` | 40 | 23 | 17 | HTTP 404 (key NGOC không hỗ trợ 2.5 Flash) |
| `gemini_only_38flash` | `gemini-3.8-flash` | 7 | 1 | 6 | HTTP 429 (4), HTTP 503 (2) |
| `gemini_only_38flash_nothink` | `gemini-3.8-flash`, thinkingBudget=0 | 1 | 0 | 1 | HTTP 429 (hết quota ngày, chưa xác thực được chế độ no-thinking) |
| `gemini_only_pro31` | `gemini-3.1-pro-preview` | 1 | 0 | 1 | HTTP 429 (free tier limit = 0, model chỉ dùng được khi bật billing) |

Tổng số kết quả Gemini thành công: **24 dòng**, trong đó 23 dòng `mapped` của `gemini-2.5-flash` và 1 dòng `uncertain` của `gemini-3.8-flash`.

Ngoài Gemini, hai baseline còn lại đã hoàn thành đủ 90 scenario:

| Strategy | Số scenario | Primary hit (toàn bộ 90) |
|---|---:|---:|
| `bm25_only` | 90 | 34.4% |
| `hybrid_current` (tham chiếu lưu trữ) | 90 | 47.8% |

## 3. Đánh giá ghép cặp trên 23 alert của Gemini 2.5 Flash

Vì chỉ 23 alert có kết quả Gemini thành công, phép so sánh được giới hạn trên đúng 23 scenario đó để đảm bảo công bằng.

| Strategy | N | Primary hit | Top-3 hit | Wrong primary | Coverage | Trung vị latency |
|---|---:|---:|---:|---:|---:|---:|
| `gemini_only` (2.5 Flash) | 23 | 78.3% | 91.3% | 21.7% | 100% | 16.0 s |
| `hybrid_current` | 23 | 39.1% | 69.6% | 21.7% | 60.9% | 1.95 s |
| `bm25_only` | 23 | 26.1% | 60.9% | 73.9% | 100% | 1.2 ms |

McNemar `gemini_only` vs `hybrid_current`: 10 case chỉ Gemini đúng, 1 case chỉ hybrid đúng, p = 0.0117.

## 4. Chi tiết 23 scenario

| Scenario | Expected | Gemini | Kết quả | Hybrid | BM25 |
|---|---|---|---|---|---|
| A1-T1046-01 | T1046 | T1046 | đúng | T1190 | T1095 |
| A1-T1046-02 | T1046 | T1046 | đúng | T1190 | T1095 |
| A1-T1078-01 | T1078 | T1595.002 | sai | T1190 | T1095 |
| A1-T1189-01 | T1189 | T1189 | đúng | bỏ trống | T1095 |
| A1-T1189-02 | T1189 | T1189 | đúng | T1190 | T1190 |
| A1-T1190-01 | T1190 | T1190 | đúng | T1190 | T1190 |
| A1-T1190-02 | T1190 | T1595.002 | sai | T1190 | T1190 |
| A1-T1190-03 | T1190 | T1190 | đúng | T1190 | T1190 |
| A1-T1190-04 | T1190 | T1190 | đúng | T1190 | T1190 |
| A1-T1190-05 | T1190 | T1190 | đúng | T1190 | T1190 |
| A1-T1210-01 | T1210 | T1190 | sai (nhãn gây tranh luận) | bỏ trống | T1190 |
| A1-T1210-02 | T1210 | T1190 | sai (nhãn gây tranh luận) | bỏ trống | T1190 |
| A1-T1210-03 | T1210 | T1210 | đúng | bỏ trống | T1190 |
| A1-T1210-04 | T1210 | T1210 | đúng | bỏ trống | T1190 |
| A1-T1210-05 | T1210 | T1190 | sai (nhãn gây tranh luận) | T1190 | T1190 |
| A2-T1046-01 | T1046 | T1046 | đúng | T1046 | T1595.001 |
| A2-T1046-02 | T1046 | T1046 | đúng | T1046 | T1595.001 |
| A2-T1046-03 | T1046 | T1046 | đúng | T1046 | T1499 |
| A2-T1071.001-01 | T1071.001 | T1071.001 | đúng | bỏ trống | T1095 |
| A2-T1071.001-02 | T1071.001 | T1071.001 | đúng | bỏ trống | T1095 |
| A2-T1071.001-03 | T1071.001 | T1071.001 | đúng | bỏ trống | T1095 |
| A2-T1071.001-05 | T1071.001 | T1071.001 | đúng | bỏ trống | T1095 |
| A2-T1078-03 | T1078 | T1078 | đúng | T1078 | T1078 |

Kết quả: 18/23 đúng (78.3%).

Điểm mạnh của Gemini 2.5 Flash trên tập này:

- C2 `T1071.001`: đúng 4/4 trong khi hybrid bỏ trống cả 4.
- `T1046` nhóm A1: đúng 2/2 trong khi hybrid chọn `T1190`.
- `T1189`: đúng 2/2 trong khi hybrid bỏ trống 1 và chọn nhầm 1.

Điểm yếu:

- 3 case `T1210` map sang `T1190`; đây là nhóm nhãn ET Open gây tranh luận, `T1190` có thể đúng ngữ nghĩa ATT&CK hơn.
- Không bao giờ abstain: map đủ 23/23, kể cả các case sai, nên không có cơ chế "chuyển cho analyst".
- Latency trung vị 16.0 s, gấp khoảng 8 lần hybrid.

## 5. Kết quả Gemini 3.8 Flash

- Chạy được với key `GEMINI_API_KEY_NGOC`, output đúng schema.
- Rất chậm: 123 s cho một alert, dùng khoảng 3.000 token "thinking".
- Không ổn định: 2 lần gặp HTTP 503 "model is currently experiencing high demand" và thất bại sau nhiều lần retry.
- Kết quả duy nhất: `A1-T1046-01` → `T1595.002`, trạng thái `uncertain` (expected `T1046`, tức là sai). Cùng alert này 2.5 Flash trả đúng `T1046`.
- Chế độ không thinking chưa được xác thực vì quota ngày đã cạn trước khi có response hợp lệ.

## 6. Ma trận model và quota ghi nhận được

| Model | Key `GEMINI_API_KEY` (project cũ) | Key `GEMINI_API_KEY_NGOC` (project mới) |
|---|---|---|
| `gemini-2.5-flash` | Chạy được, free tier 20 request/ngày | HTTP 404 – không còn cho user mới |
| `gemini-2.5-pro` | Không kiểm tra | HTTP 404 – không còn cho user mới |
| `gemini-2.0-flash` | Không kiểm tra | HTTP 404 – đã khai tử |
| `gemini-2.5-flash-lite` | Không kiểm tra | HTTP 404 – không còn cho user mới |
| `gemini-3.1-pro-preview` | Không kiểm tra | HTTP 429 – free tier limit = 0, cần bật billing |
| `gemini-3.8-flash` | Chưa xác thực | Chạy được, free tier 20 request/ngày, chậm và hay gặp 503 |

Thời điểm cạn quota ghi nhận: `gemini-3.8-flash` yêu cầu thử lại sau khoảng 9h52m; `gemini-2.5-flash` trước đó yêu cầu khoảng 10h45m.

## 7. Bài học vận hành quan trọng

Free tier của cả hai key đều giới hạn **20 request/ngày cho mỗi model**. Cơ chế retry 5 lần cho mỗi scenario đã nhanh chóng đốt hết quota: chỉ một vài alert gặp 503 là đủ tiêu hết 20 request.

Đã sửa lại cho các lần chạy sau:

- `max_retries` giảm từ 5 xuống 1, tức mỗi scenario chỉ thử tối đa 2 lần trong một lượt chạy.
- Thêm cơ chế dừng sớm `QuotaExhausted`: khi gặp 429 kèm `retryDelay` lớn (>= 600 giây), strategy dừng ngay cả lượt chạy thay vì tiếp tục thử các scenario còn lại.
- Checkpoint vẫn giữ nguyên nguyên tắc: scenario thành công không chạy lại, chỉ scenario lỗi được retry ở lượt sau.

## 8. Tệp lưu trữ

| Đường dẫn | Nội dung |
|---|---|
| `reports/baselines/snapshots/gemini_attempts_20261005/summary.json` | Tổng hợp toàn bộ arm Gemini |
| `reports/baselines/snapshots/gemini_attempts_20261005/*.successful.jsonl` | Kết quả thành công từng arm |
| `reports/baselines/snapshots/gemini_attempts_20261005/*.errors.jsonl` | Lý do lỗi từng scenario |
| `reports/baselines/snapshots/gemini_attempts_20261005/*.latest.jsonl` | Trạng thái mới nhất mỗi scenario |
| `reports/baselines/snapshots/gemini_attempts_20261005/partial_2.5_flash_*` | Báo cáo đánh giá ghép cặp 23 alert |
| `reports/baselines/snapshots/gemini_only_2.5_flash_partial/` | Snapshot gốc của 23 kết quả 2.5 Flash |
| `reports/baselines/checkpoints/` | Checkpoint để resume khi có quota |

Lệnh tái lập snapshot:

```powershell
python scripts/archive_gemini_runs.py
python scripts/snapshot_partial_baselines.py --arm gemini_only --snapshot-dir reports/baselines/snapshots/gemini_only_2.5_flash_partial
```

## 9. Việc tiếp theo

1. Chờ quota reset (khoảng 10 giờ) rồi resume `gemini_only` bằng key cũ với `gemini-2.5-flash`; chỉ cần chạy thêm 67 alert.
2. Nếu muốn dùng Gemini Pro hoặc chạy đủ nhanh trong ngày, cần bật billing hoặc dùng key từ project trả phí.
3. Nếu vẫn muốn 3.8 Flash, nên chạy vào thời điểm model bớt tải và bắt đầu bằng chế độ không thinking để kiểm tra lại latency trước khi chạy toàn bộ.
4. Các con số 78.3% chỉ là kết quả tạm trên 23 alert lệch về nhóm A1, không dùng làm kết luận cuối cho B2.
