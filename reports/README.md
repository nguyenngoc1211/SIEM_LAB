# Reports - kho báo cáo của dự án

Thư mục này là **điểm vào duy nhất** cho các báo cáo/đánh giá của NCKH. Mỗi báo
cáo là một bundle độc lập. Tên thư mục **không** chứa ngày; ngày cập nhật nằm ở
dòng đầu file report chính `.md` của từng bundle.

## Danh mục

| Bundle | Loại | Report chính | Nội dung |
|---|---|---|---|
| `scenario-results-a1-a2/` | `run` | `REPORT.md` | Kết quả chạy 90 scenario A1/A2 trên mô hình chính (end-to-end Suricata/Wazuh -> n8n -> mapper) |
| `baseline-comparison/` | `cmp` | `REPORT.md` | So sánh mapper chính (hybrid) với baseline B1 BM25-only và B2 DeepSeek-only trên cùng 90 scenario |

`registry.json` là bản máy đọc của bảng trên, dùng khi cần lọc/tìm theo script.

## Hai tầng của một bundle

| Tầng | Nội dung | Git |
|---|---|---|
| Tier 1 - curated | `REPORT.md`, bảng tổng hợp, `comparison.md/.csv/.json`, `run_metadata.json`, `MANIFEST.json` | **commit** |
| Tier 2 - raw | `raw/`, `raw_results/`, `checkpoints/`, `snapshots/`, `archive/` | **ignore** |

Tier 2 do máy sinh và có thể tạo lại từ tier 1 cộng với lệnh ghi trong report,
nên giữ trên máy để resume/tra cứu nhưng không commit. Quy tắc nằm ở mục
`Reports policy` trong `.gitignore` tại gốc `code/`.

## Quy ước

- ID bundle: `<scope>-<type>` (ví dụ `scenario-results-a1-a2`,
  `baseline-comparison`); không ghi ngày trong tên thư mục.
- Ngày cập nhật ghi trong file report chính `.md` của bundle.
- Mọi đường dẫn raw trong report phải ghi rõ gốc, ví dụ
  `soc-lab-handoff-v1.0.0/runtime/reports/...` (đường dẫn tương đối tính từ gốc
  `code/`).
- Bundle mới: tạo thư mục, thêm `REPORT.md` + `MANIFEST.json`, rồi cập nhật
  `README.md` và `registry.json` này.

## Nguồn phát sinh report (writer)

| Writer | Ghi vào |
|---|---|
| `soc-lab-handoff-v1.0.0/scripts/build_scenario_results_report.py` | `reports/scenario-results-a1-a2/REPORT.md` |
| `data/mitre-mapping/scripts/run_baselines.py` (`--output-dir`, mặc định) | `reports/baseline-comparison/` |

Artifact thô của phần A1/A2 vẫn nằm ở `soc-lab-handoff-v1.0.0/runtime/reports/`
vì `./runtime` là bind mount của Docker; không di chuyển để tránh vỡ compose.

## Chạy lại

```powershell
# A1/A2 scenario results (đọc runtime/reports, ghi đè REPORT.md)
cd soc-lab-handoff-v1.0.0
python scripts\build_scenario_results_report.py

# Baseline comparison (90 scenario, cần DEEPSEEK_API_KEY_NCKH)
$env:DEEPSEEK_API_KEY_NCKH = "<key>"
python data\mitre-mapping\scripts\run_baselines.py --strategies bm25_only,deepseek_only
```
