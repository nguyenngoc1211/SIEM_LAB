# Báo cáo xây dựng 2 baseline mapper (B1 BM25-only, B2 Gemini-only)

Ngày thực hiện: 2026-10-05

## 1. Tóm tắt

Đã hoàn thành:

- Baseline **B1 – BM25-only**, chạy thuần Python trên chỉ mục BM25 có sẵn, không cần Qdrant, TEI hay reranker.
- Baseline **B2 – Gemini-only**, gọi Gemini bằng prompt có version, schema output cố định, closed-set trên 18 technique được hỗ trợ, có kiểm tra ID hợp lệ và có thể abstain.
- Bộ **dataset đóng băng** 90 alert A1/A2 kèm ground truth, đã loại bỏ mọi trường MITRE trước khi đưa vào baseline.
- **Harness so sánh** sinh báo cáo `comparison.json`, `comparison.csv`, `comparison.md` và lưu raw result từng strategy.
- **Test offline** cho sanitizer, BM25, kiểm tra output Gemini và bộ chấm điểm.

Kết quả chạy thử trên 90 scenario:

| Strategy | N | Exact top-1 | Top-3 hit | Partial credit | Wrong primary | Coverage | Trung vị latency |
|---|---:|---:|---:|---:|---:|---:|---:|
| `bm25_only` (top-1, theo kế hoạch) | 90 | 34.4% | 67.8% | 37.2% | 60.0% | 100% | 1.08 ms |
| `bm25_only_threshold` (biến thể phụ) | 90 | 34.4% | 67.8% | 37.2% | 60.0% | 100% | 1.08 ms |
| `gemini_only` | 90 | chưa chạy | chưa chạy | chưa chạy | chưa chạy | 0% (skipped) | n/a |
| `hybrid_current` (tham chiếu lưu trữ) | 90 | 47.8% | 81.1% | 53.3% | 18.9% | 77.8% | 2227.97 ms |

`gemini_only` chưa được chạy thật vì workspace không có `GEMINI_API_KEY`. Toàn bộ 90 run được ghi nhận là `skipped`, không phải kết quả chất lượng. Sau khi cấu hình key, chạy lại lệnh ở mục 10 để có bảng đầy đủ ba hệ thống.

## 2. Phạm vi thay đổi

Toàn bộ thay đổi nằm trong các thư mục mới của module baseline. Không sửa file production nào.

| File/thư mục mới | Vai trò |
|---|---|
| `src/mitre_mapper/baselines/sanitize.py` | Loại bỏ trường MITRE khỏi alert đầu vào |
| `src/mitre_mapper/baselines/base.py` | Contract kết quả chung và loader catalog |
| `src/mitre_mapper/baselines/bm25_only.py` | Baseline B1 |
| `src/mitre_mapper/baselines/gemini_only.py` | Baseline B2 |
| `src/mitre_mapper/baselines/dataset.py` | Dựng dataset đóng băng từ report A1/A2 |
| `src/mitre_mapper/baselines/evaluate.py` | Tính metric, Wilson CI, McNemar |
| `src/mitre_mapper/baselines/compare.py` | Sinh báo cáo so sánh |
| `src/mitre_mapper/baselines/runner.py` | Điều phối chạy và chấm điểm |
| `scripts/build_benchmark_dataset.py` | CLI dựng dataset |
| `scripts/run_baselines.py` | CLI chạy baseline và so sánh |
| `configs/baselines.json` | Cấu hình baseline |
| `prompts/gemini_only_v1.md` | Prompt B2 có version |
| `schemas/baseline_result.schema.json` | Schema kết quả chung |
| `tests/test_baselines.py` | Test offline |
| `benchmark/` | Dataset đóng băng đã sinh |
| `reports/baselines/` | Báo cáo so sánh đã sinh |

Không sửa: `pipeline.py`, `api.py`, `clients.py`, `database.py`, `normalization.py`, `evidence.py`, `settings.py`, workflow n8n, `docker-compose.yaml`.

Các artifact được đọc (chỉ đọc):

- `artifacts/attack/attack_final.mapping.json`
- `artifacts/attack/index_manifest.json`
- `artifacts/retrieval/technique_documents.jsonl`
- `artifacts/retrieval/bm25_index.json`
- `../soc-lab-handoff-v1.0.0/runtime/reports/a1|a2/*.json`

## 3. Baseline B1 – BM25-only lấy dữ liệu từ đâu

Phân biệt hai nguồn:

- **Knowledge base**: 18 technique document trong `artifacts/retrieval/technique_documents.jsonl`, và trọng số BM25 đã dựng sẵn trong `artifacts/retrieval/bm25_index.json`.
- **Query**: alert đã chuẩn hóa, lấy `derived.retrieval_text`; nếu thiếu thì dựng lại bằng `build_retrieval_text()`.

Cách tính:

1. Token hóa `retrieval_text`.
2. `build_query_vector()` gán mỗi token đã biết trọng số `1.0`.
3. Nhân vô hướng với `document_vectors[technique_id]` (đã chứa IDF và TF saturation).
4. Xếp hạng giảm dần theo điểm thô.

`BM25OnlyStrategy` có hai biến thể:

- `variant = "top1"`: lấy technique đứng đầu, đúng định nghĩa baseline trong kế hoạch P3.
- `variant = "threshold"`: dùng `min_score` và `margin_ratio` giữa top-1/top-2 để có thể trả `uncertain` hoặc `insufficient_evidence`. Ngưỡng hiện là mặc định thực nghiệm, chưa calibrate trên dev split.

`confidence` của B1 là điểm chuẩn hóa min-max theo từng query, cùng cách hybrid đang làm, nên top-1 luôn bằng 1.0. Không nên so sánh confidence giữa các alert khác nhau.

## 4. Baseline B2 – Gemini-only hoạt động thế nào

- Mặc định `mode = "closed_set"`: Gemini chỉ được chọn trong 18 technique thuộc supported subset.
- Biến thể `mode = "open_set"`: Gemini tự do trả ID; ID ngoài subset bị ghi nhận và loại, không tự remap về parent.
- `prompts/gemini_only_v1.md` giữ prompt cố định; `prompt_version = gemini-only-1.0.0`.
- Output dùng `responseMimeType: application/json` và `responseSchema` cố định gồm: `mapping_status`, `primary_technique_id`, `primary_technique_name`, `confidence`, `ranked_candidates`, `evidence`, `rationale`, `uncertainty`.
- Có thể abstain bằng `mapping_status = insufficient_evidence`.
- ID không hợp lệ hoặc ngoài subset làm kết quả thành `invalid_output` và được đếm riêng, không bị tính thành đúng.
- `repeats > 1` chạy lặp và sinh thêm `gemini_only_consensus` (majority vote) kèm độ đồng thuận.
- Không có `GEMINI_API_KEY` thì strategy trả `skipped` thay vì gọi mạng, nên pipeline chạy được offline.

## 5. Loại bỏ MITRE khỏi alert đầu vào

Theo yêu cầu, sanitizer xóa:

- mọi field có tên chứa `mitre`, ví dụ `mitre_technique_id`, `mitre_tactic_id`, `mitre`, `wazuh_mitre`;
- các field `tactic`, `tactic_id`, `technique_id`, `technique_ids`, `attack_pattern` ở mọi cấp;
- list item/tag dạng `T1046`, `TA0007`, `attack.t1046`;
- dòng free text có nhãn MITRE/ATT&CK, ví dụ `Declared MITRE techniques: T1046`;
- token `Txxxx` và `TAxxxx` còn sót trong chuỗi.

Kết quả trên dataset hiện tại:

| Chỉ số | Giá trị |
|---|---:|
| Alert đầu vào | 90 |
| Field bị xóa | 90 |
| Field bị xóa có giá trị thật (khác null) | 0 |
| Chuỗi bị scrub inline | 0 |
| Alert còn dấu vết MITRE sau sanitize | 0 |

Field duy nhất bị xóa trong snapshot này là `derived.external_hints.wazuh_mitre`, và cả 90 giá trị đều là `null`. Nói cách khác, dataset hiện tại vốn chưa leak, nhưng sanitizer giờ bắt buộc và ghi log, đồng thời vẫn xử lý đúng cho các alert tương lai có metadata thật.

Mọi lần xóa được ghi trong `benchmark/alerts.jsonl` ở khóa `sanitization`, và `benchmark/manifest.json` tổng hợp `removed_fields`, `scrubbed_values`, `alerts_with_leakage_after_sanitize`.

## 6. Dataset đóng băng

Nguồn: 90 report trong `soc-lab-handoff-v1.0.0/runtime/reports/a1|a2`.

| File | Nội dung |
|---|---|
| `benchmark/alerts.jsonl` | 90 `normalized_alert` đã sanitize, giữ nguyên mọi field hành vi khác |
| `benchmark/ground_truth.jsonl` | `technique_ids`, `tactic_ids`, `expected_mapping_status` |
| `benchmark/archived_hybrid_results.jsonl` | Kết quả mapper hiện tại lấy từ report, làm mốc tham chiếu |
| `benchmark/manifest.json` | Hash SHA-256, số lượng, version sanitizer, version index |

Thông tin index: `index_version=1.0.0`, ATT&CK `19.1`, 18 technique, `attack_final_sha256=16cda6d4e3b0dca9340e6b84f403b335624cc7093665f145540c2809ea33a03e`.

Hash dataset hiện tại: `alerts.jsonl=68ebdf83997bd8033c02808688e3fdf752d4214edf483452788f6350e5bf481e`.

## 7. Chỉ số đánh giá

- `exact_top1`: primary trùng đúng technique mong đợi khi ground truth chỉ có một technique.
- `primary_hit`: primary nằm trong tập technique mong đợi.
- `top3_hit`: ít nhất một technique mong đợi nằm trong 3 candidate đầu.
- `all_expected_top3`: toàn bộ tập mong đợi nằm trong 3 candidate đầu.
- `partial_credit`: 1.0 nếu primary trúng; 0.5 nếu primary là cha hoặc con của technique mong đợi; còn lại 0.
- `wrong_primary`: có primary, không trúng và không có quan hệ cha/con.
- `coverage`: có primary (`mapped` hoặc `uncertain`).
- `abstain`: `insufficient_evidence`, `skipped`, `error` hoặc `invalid_output`.

Mỗi tỷ lệ đều kèm Wilson 95% CI. Báo cáo cũng có McNemar exact test theo từng cặp strategy trên `primary_hit`.

## 8. Kết quả chạy thử

Chi tiết đầy đủ ở `reports/baselines/comparison.md`, `comparison.csv`, `comparison.json`.

Nhận xét chính:

- BM25-only top-1 đạt 34.4% exact, thấp hơn mốc hybrid lưu trữ 47.8%, nhưng top-3 đạt 67.8% so với 81.1%. Retrieval thuần từ khóa mất khoảng 13 điểm top-3.
- BM25-only không bao giờ abstain, nên wrong primary lên tới 60%. Đây là hệ quả trực tiếp của định nghĩa baseline "lấy top-1 làm dự đoán".
- Biến thể `bm25_only_threshold` cho cùng accuracy vì `uncertain` vẫn giữ primary, giống semantics của hybrid. Khác biệt chỉ nằm ở nhãn trạng thái.
- `hybrid_current` đạt top-3 81.1% nhưng abstain 22.2%; đây là đánh đổi coverage/accuracy mà baseline không có.
- McNemar `bm25_only` vs `hybrid_current`: 2 case chỉ BM25 đúng, 14 case chỉ hybrid đúng, p = 0.0042.

Lưu ý: `hybrid_current` đọc từ report lưu trữ chạy trước sanitize, là mốc tham chiếu chứ không phải lần chạy lại trên dataset đã sanitize. Với snapshot này, sanitizer chỉ xóa field null nên mức ảnh hưởng thực tế bằng 0.

## 9. Cấu hình

File `configs/baselines.json`:

| Khóa | Ý nghĩa |
|---|---|
| `bm25_only.variant` | `top1` (mặc định, theo kế hoạch) hoặc `threshold` |
| `bm25_only.extra_variants` | Danh sách biến thể chạy thêm, mặc định `["threshold"]` |
| `bm25_only.min_score` | Ngưỡng điểm thô tối thiểu cho biến thể threshold |
| `bm25_only.margin_ratio` | Khoảng cách tương đối top-1/top-2 để tránh `uncertain` |
| `bm25_only.top_k` | Số candidate đưa vào `alternative_candidates` |
| `gemini_only.model` | Model Gemini, mặc định `gemini-2.5-flash` |
| `gemini_only.mode` | `closed_set` hoặc `open_set` |
| `gemini_only.temperature` | Mặc định `0.0` để tái lập |
| `gemini_only.repeats` | Số lần chạy lặp mỗi alert |
| `gemini_only.max_output_tokens` | Giới hạn output |
| `gemini_only.request_timeout` | Timeout mỗi request |
| `gemini_only.max_retries` | Số lần retry khi lỗi 429/5xx |
| `evaluation.top_n` | Số candidate cho metric top-N, mặc định 3 |
| `evaluation.partial_credit_parent` | Điểm cho quan hệ cha/con, mặc định 0.5 |

Biến môi trường:

| Biến | Vai trò |
|---|---|
| `GEMINI_API_KEY` | Bắt buộc để chạy B2 thật |
| `GEMINI_MODEL` | Ghi đè model trong config |

`scripts/run_baselines.py` tự đọc `mitre-mapping/.env` nếu file tồn tại và biến chưa được set trong môi trường. Không in key ra log.

## 10. Cách chạy

Đứng tại `NCKH_Code/code/data/mitre-mapping`:

```powershell
# 1. Dựng lại dataset đóng băng (chạy lại khi report A1/A2 thay đổi)
python scripts/build_benchmark_dataset.py

# 2. Chạy BM25 thật + Gemini dry-run (không cần API key)
python scripts/run_baselines.py --dry-run

# 3. Chỉ chạy BM25, không đụng Gemini
python scripts/run_baselines.py --strategies bm25_only

# 4. Smoke test nhanh 5 alert
python scripts/run_baselines.py --limit 5 --dry-run

# 5. Chạy Gemini thật, lặp 3 lần để đo self-consistency
Copy-Item .env.example .env
# Sửa .env: GEMINI_API_KEY=<key-that>
python scripts/run_baselines.py --repeats 3
```

Gemini thật cần quyền truy cập mạng tới `generativelanguage.googleapis.com`. Trong môi trường sandbox hiện tại, bước này sẽ cần bạn chạy ngoài sandbox hoặc cấp quyền mạng.

Output:

- `reports/baselines/comparison.md` – bảng tóm tắt để đưa vào báo cáo.
- `reports/baselines/comparison.csv` – chi tiết từng scenario × strategy.
- `reports/baselines/comparison.json` – dữ liệu đầy đủ, có breakdown theo nhóm và theo technique.
- `reports/baselines/raw_results/<strategy>.jsonl` – output thô từng strategy.
- `reports/baselines/run_metadata.json` – cấu hình, hash dataset, đường dẫn report.

## 11. Kiểm thử

```powershell
python -m unittest discover -s tests -p 'test_baselines.py' -v
```

Kết quả hiện tại: 8 test đạt, 0 thất bại. Test bao phủ sanitizer, BM25 xếp hạng và tính tất định, kiểm tra ID Gemini, dry-run không gọi mạng, partial credit cha/con và parser scenario.

## 12. Hạn chế và việc tiếp theo

- Gemini chưa chạy thật trong lần này do thiếu API key; cần chạy lại để có bảng ba hệ thống đầy đủ.
- Ngưỡng `threshold` của B1 chưa calibrate trên dev split; không nên tune trực tiếp trên 90 scenario đánh giá.
- `hybrid_current` là dữ liệu lưu trữ, chưa chạy lại trên input đã sanitize.
- Sanitizer scrub token ATT&CK trong mọi chuỗi; với snapshot này không có token nào bị scrub, nhưng nếu alert tương lai có rule name chứa `Txxxx`, chuỗi đó sẽ bị thay đổi và được ghi log.
- 90 scenario vẫn cho khoảng tin cậy khá rộng; nên đọc kèm Wilson CI và McNemar thay vì chỉ nhìn phần trăm.
- Việc expose B1/B2 qua mapper API hoặc thêm node switch trong n8n sẽ cần sửa `api.py`/workflow, nằm ngoài phạm vi lần này; cần hỏi trước khi thực hiện.
