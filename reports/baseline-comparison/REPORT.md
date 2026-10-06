# So sánh mapper chính với các baseline (B1 BM25-only, B2 DeepSeek-only)

Cập nhật: `2026-10-06`

## 1. Phạm vi

So sánh ba hệ thống trên **cùng một dataset đóng băng 90 alert A1/A2** đã loại
bỏ mọi trường MITRE trước khi đưa vào model:

- `hybrid_current` - mapper chính (BM25 + ATTACK-BERT + fusion + cross-encoder +
  evidence guard + hierarchy/confusion + abstention), lấy từ report lưu trữ.
- `bm25_only` (B1) - baseline retrieval thuần từ khóa, lấy technique đứng đầu.
- `deepseek_only` (B2) - baseline LLM, DeepSeek chọn technique trong closed-set
  18 technique.

## 2. Kết quả 90 scenario

| Strategy | N | Exact top-1 | Top-3 hit | Partial credit | Wrong primary | Coverage | Abstain | Trung vị latency |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `bm25_only` (B1) | 90 | 34.4% | 67.8% | 37.2% | 60.0% | 100% | 0.0% | 1.24 ms |
| `bm25_only_threshold` | 90 | 34.4% | 67.8% | 37.2% | 60.0% | 100% | 0.0% | 1.33 ms |
| `deepseek_only` (B2) | 90 | 58.9% | 94.4% | 63.3% | 27.8% | 95.6% | 4.4% | 6532.49 ms |
| `hybrid_current` (mapper chính) | 90 | 47.8% | 81.1% | 53.3% | 18.9% | 77.8% | 22.2% | 2227.97 ms |

Wilson 95% CI cho `deepseek_only`: exact top-1 `[48.6%, 68.5%]`, top-3
`[87.7%, 97.6%]`.

McNemar theo `primary_hit`:

| So sánh | Chỉ first đúng | Chỉ second đúng | p-value |
|---|---:|---:|---:|
| `bm25_only` vs `deepseek_only` | 8 | 30 | 0.000472 |
| `bm25_only` vs `hybrid_current` | 2 | 14 | 0.004181 |
| `deepseek_only` vs `hybrid_current` | 21 | 11 | 0.110184 |

## 3. Nhận xét chính

- `deepseek_only` dẫn đầu về exact top-1 (58.9%) và top-3 (94.4%), nhưng trung vị
  latency cao hơn khoảng 3 lần so với mapper chính.
- `hybrid_current` có `wrong_primary` thấp nhất (18.9%) nhờ abstain 22.2%, tức là
  đánh đổi coverage để giảm kết luận sai.
- `bm25_only` phủ 100% nhưng sai 60% - luôn trả lời mà không có cơ chế chuyển cho
  analyst.
- Khác biệt `deepseek_only` vs `hybrid_current` chưa có ý nghĩa thống kê ở mức 90
  scenario (p = 0.110); nên đọc kèm Wilson CI và McNemar thay vì chỉ nhìn phần
  trăm.
- Nhóm lỗi tập trung ở các họ bị lẫn như `T1210` (nhãn ET Open gây tranh luận) và
  họ `T1595`; chi tiết ở `BAO_CAO_DEEPSEEK_B2_KET_QUA.md` mục 6.

## 4. Provenance

| Trường | Giá trị |
|---|---|
| Dataset | `benchmark` version `1.0.0`, 90 alert |
| Alerts SHA-256 | `68ebdf83997bd8033c02808688e3fdf752d4214edf483452788f6350e5bf481e` |
| Ground truth SHA-256 | `4e8c3ec3f6d54ba644a29f8b86404446fcf9b0a51d1018727d1fd4eadf3210a8` |
| ATT&CK index | `index_version=1.0.0`, ATT&CK `19.1`, 18 technique |
| ATT&CK final SHA-256 | `16cda6d4e3b0dca9340e6b84f403b335624cc7093665f145540c2809ea33a03e` |
| B2 model | `deepseek-flash`, closed-set, temperature 0.0 |
| B2 API key env | `DEEPSEEK_API_KEY_NCKH` |
| Thời điểm chạy | `2026-10-06T14:14:04Z` |

## 5. Tệp trong bundle

| Tệp / thư mục | Tầng | Nội dung |
|---|---|---|
| `REPORT.md` | 1 | Report chính (tệp này) |
| `comparison.md` | 1 | Bảng so sánh đầy đủ do máy sinh |
| `comparison.csv` | 1 | Chi tiết từng scenario x strategy |
| `comparison.json` | 1 | Dữ liệu đầy đủ, breakdown theo nhóm/họ, McNemar |
| `run_metadata.json` | 1 | Config, hash dataset, đường dẫn artifact |
| `BAO_CAO_BASELINE_MAPPER.md` | 1 | Báo cáo xây dựng B1/B2 và cách chạy |
| `BAO_CAO_DEEPSEEK_B2_KET_QUA.md` | 1 | Kết quả B2 DeepSeek chi tiết, phân tích lỗi |
| `test-alert-scan-CH.result.json`, `verification-summary.json` | 1 | Kết quả kiểm thử mapper |
| `raw_results/`, `checkpoints/` | 2 | Output thô + checkpoint (git ignore) |

## 6. Chạy lại

Đứng tại gốc repo `code/`:

```powershell
$env:DEEPSEEK_API_KEY_NCKH = "<key>"
python data\mitre-mapping\scripts\run_baselines.py --strategies bm25_only,deepseek_only
```

Runner mặc định ghi vào chính bundle này; scenario thiếu hoặc lỗi được chạy
trước, checkpoint cho phép resume. Dùng `--limit N` để chạy theo đoạn.

## 7. Ghi chú

- `hybrid_current` đọc từ report lưu trữ, chạy trước bước sanitize, nên là mốc
  tham chiếu chứ không phải lần chạy lại trên dataset đã làm sạch.
- Số liệu top-1/top-3/partial credit/wrong/coverage lấy từ `comparison.json`.
- B2 hiện hành là DeepSeek; artifact của thí nghiệm Gemini cũ đã được dọn khỏi
  bundle này.
