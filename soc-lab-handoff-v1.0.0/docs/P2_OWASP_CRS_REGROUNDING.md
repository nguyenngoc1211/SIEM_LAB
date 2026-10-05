# Báo cáo thay đổi — P2: Neo bộ rule A2 vào OWASP CRS

- **Ngày thực hiện:** 2026-10-05
- **Nhánh:** `main`
- **Commit:** `1c0b528` — `feat(soc-lab): ground A2 Suricata rules on OWASP CRS via metadata`
- **Phạm vi ảnh hưởng:** `soc-lab-handoff-v1.0.0/` — 37 file thay đổi (+284 / −95)

> Tài liệu này dành cho thành viên nhóm: mô tả **đã sửa cái gì, vì sao, và cách tự kiểm chứng lại**.

---

## 1. Tóm tắt một dòng

Trong 75 rule của bộ A2 (`sensor/a2.rules`), **16 rule đã có sẵn** được neo vào **OWASP Core Rule Set (CRS)** thông qua tag `metadata` (giữ nguyên `msg:` hành vi); **59 rule còn lại** vẫn giữ nguồn gốc `custom`. Kết quả: **16 OWASP CRS-derived + 59 Custom**.

---

## 2. Bối cảnh & mục tiêu

- Bộ rule A2 trước đây **toàn bộ** mang nhãn "custom", làm giảm độ tin cậy khi trình bày ra bên ngoài.
- Mục tiêu P2: tăng tính chính danh bằng cách **neo các rule đang tồn tại** vào OWASP CRS — nguồn tham chiếu công khai, phổ biến trong cộng đồng Suricata/ModSecurity.
- **Ràng buộc quan trọng (không thương lượng):**
  - Chỉ tái-neo **rule đã có**; **KHÔNG thêm kịch bản mới** (đề xuất thêm T1190 trước đó đã bị bác).
  - Giữ nguyên **`msg:` hành vi** của từng rule; tham chiếu CRS ghi vào **`metadata:`** — *không phải* đổi tên msg (đổi tên msg chỉ là "name-aligned", không phải rule dẫn xuất CRS thật).
  - Mỗi rule tái-neo ghi rõ **CRS rule ID + phiên bản**.
  - Bảo toàn đặc trưng phát hiện lõi khi chuyển CRS→Suricata (strings / PCRE / payload type); không port toàn bộ CRS.

---

## 3. Danh sách file thay đổi

| File | +/− | Nội dung |
|---|---|---|
| `sensor/a2.rules` | +17 / −16 | Regenerate: 16 SID được thêm clause `metadata:owasp_crs_rule ...` |
| `soc-attacker-advanced-v3.0.0/src/tools/generate_a2.py` | +82 / −42 | Sinh metadata CRS + `rule_source`/`source_type`/`reference` |
| `soc-attacker-advanced-v3.0.0/src/soc_scenarios/rule_catalog.py` | +8 / −2 | Phân loại provenance theo tag metadata (bỏ heuristic SID-range) |
| `soc-attacker-advanced-v3.0.0/tests/test_scenario_framework.py` | +78 / −0 | Test provenance theo metadata + regression SID dải cũ |
| `scripts/build_scenario_results_report.py` | +67 / −3 | Thêm cột `Rule source` + bảng thống kê CRS-vs-Custom |
| `scenarios/a2/**` (16 thư mục × 2 file) | ±1 mỗi file | `rule.rules` thêm metadata; `scenario.yaml` đổi `rule_source: custom → owasp_crs` |

**Tổng: 37 file, +284 / −95.**

---

## 4. Chi tiết theo file

### 4.1 `generate_a2.py` (trọng tâm)
- Thêm hằng số `CRS_VERSION = "4.29.0"` và `CRS_LEGACY_VERSION = "3.3.7"`.
- `crs_metadata(rule_id, version, strength)` → render clause:
  `metadata:owasp_crs_rule <id>, owasp_crs_ver <ver>, owasp_crs_strength <literal|semantic>`
- `crs_kwargs(reference)` → dịch tuple CRS thành kwargs cho `add()`.
- `add(...)` nhận thêm `classtype`, `metadata`, `rule_source`, `source_type`, `reference`; chèn `metadata_clause` vào rule sinh ra.
- Gắn nhãn CRS cho **đúng 16 rule**; đồng thời ghi `rule_source`/`source_type`/`reference` vào `catalog.json` của từng scenario.
- **`msg:` của mọi rule KHÔNG đổi.**

### 4.2 `rule_catalog.py`
- `_source_for(...)` nhận thêm `metadata`; nếu có tag `owasp_crs_rule` → trả `("owasp_crs", "a2.rules")`.
- **Gỡ heuristic SID-range chết** (`1002100–1002149`) → provenance giờ **do tag metadata quyết định**, không do dải SID.
- `parse_rule(...)` truyền `metadata` xuống `_source_for`.

### 4.3 `test_scenario_framework.py`
- `test_owasp_crs_metadata_is_classified_as_owasp_crs` — SID 1002028 + tag `930130` ⇒ `owasp_crs`.
- `test_a2_sid_without_crs_metadata_keeps_custom_provenance` — SID không tag ⇒ `custom`; kèm **regression**: SID `1002100` (dải cũ) **vẫn phải `custom`**.
- `test_owasp_crs_scenario_matches_crs_catalog_source` — scenario `A2-T1595.003-03` khớp `rule_source: owasp_crs`.

### 4.4 `build_scenario_results_report.py`
- `yaml_scalar()`: regex mới hỗ trợ **key thụt lề** (`^[ \t]*key:`), cần để đọc `rule_source` nằm dưới `suricata:`.
- Thêm `RULE_SOURCE_LABELS` + `rule_source_label()` (`et_open`/`et` → "ET Open", `owasp_crs` → "OWASP CRS-derived", `custom` → "Custom").
- `table_rows()`: thêm **cột `Rule source`**.
- Thêm `rule_source_summary()` → **bảng thống kê CRS-derived vs Custom** kèm tỉ lệ %; chèn mục mới **"## Nguồn gốc rule theo nhóm kịch bản"**.

### 4.5 `sensor/a2.rules` + 16 thư mục scenario
- Regenerate: chỉ đúng **16 SID** được thêm clause metadata; `msg:` và các điều kiện phát hiện không đổi.
- `scenario.yaml`: `rule_source` đổi `custom → owasp_crs`.

---

## 5. Bảng ánh xạ 16 rule đã neo CRS

| SID | Scenario | CRS rule | CRS ver | Strength | Cơ sở CRS |
|---|---|---|---|---|---|
| 1002012 | T1595-02 | **913100** | 4.29.0 | semantic | UA scanner (lab UA riêng) |
| 1002013 | T1595-03 | 913100 | 4.29.0 | semantic | UA scanner |
| 1002014 | T1595-04 | 913100 | 4.29.0 | semantic | UA scanner |
| 1002015 | T1595-05 | **911100** | 4.29.0 | literal | Method not allowed (TRACE) |
| 1002021 | T1595.002-01 | 913100 | 4.29.0 | literal | UA "Nuclei" |
| 1002027 | T1595.003-02 | **920440** | 4.29.0 | literal | Extension restricted (backup) |
| 1002028 | T1595.003-03 | **930130** | 4.29.0 | literal | Restricted File Access (.git/.env) |
| 1002046 | T1505.003-01 | **932160** | 4.29.0 | literal | Unix Shell Code Found |
| 1002047 | T1505.003-02 | 932160 | 4.29.0 | literal | Unix Shell Code Found |
| 1002049 | T1505.003-04 | 932160 | 4.29.0 | literal | Unix Shell Code Found |
| 1002050 | T1505.003-05 | 932160 | 4.29.0 | literal | Unix Shell Code Found |
| 1002051 | T1499-01 | **912170** | **3.3.7** | semantic | DoS burst counter (legacy) |
| 1002052 | T1499-02 | 912170 | 3.3.7 | semantic | DoS burst counter (legacy) |
| 1002053 | T1499-03 | 912170 | 3.3.7 | semantic | DoS burst counter (legacy) |
| 1002054 | T1499-04 | 912170 | 3.3.7 | semantic | DoS burst counter (legacy) |
| 1002055 | T1499-05 | 912170 | 3.3.7 | semantic | DoS burst counter (legacy) |

**Quy ước `strength`:**
- `literal` — điều kiện CRS khớp nguyên văn (field + giá trị).
- `semantic` — cùng trường/họ phát hiện nhưng giá trị đặc thù lab.

**Lưu ý về `912170`:** rule này **không còn tồn tại trong CRS 4.x** (file `REQUEST-912-DOS-PROTECTION.conf` đã bị gỡ từ 4.0.0). Đã xác minh nó chỉ có trong **CRS 3.3.7** (`SecRule IP:DOS_BURST_COUNTER`, phase:5). Nhóm T1499 **giữ lại** và ghi rõ phiên bản `3.3.7` để minh bạch nguồn gốc lịch sử.

---

## 6. Tiêu chí đánh giá & các nhóm bị loại

Trước khi gắn nhãn, 57 ứng viên đã được soi qua 2 tiêu chí:

- **C1 — Độ tương đồng với rule custom cũ:** điều kiện CRS phải thực sự tương ứng với điều kiện phát hiện hiện tại.
- **C2 — Tương thích với scenario + MITRE:** nhãn/ngữ nghĩa CRS phải khớp hành vi kịch bản và Technique.

**Kết quả: 16 chấp nhận (28,1%) — 41 loại (71,9%).** Các nhóm bị loại:

| Nhóm | Lý do | Số rule |
|---|---|---|
| N1 | Gán 913100 cho rule **không có điều kiện UA** | 15 |
| N2 | Gán nhãn DoS **912170 cho brute-force T1110\*** (sai ngữ nghĩa) | 15 |
| N3 | Gán **912170** (tầng HTTP) cho UDP flood **T1498** | 5 |
| N4 | Gán **943120** cho T1078 1002005 (hành vi benign-success) | 1 |
| N5 | Gán XSS inbound cho rule phía **response** (1002009/1002062/1002063) | 3 |
| N6 | Gán **932160** cho rule **ASPX** 1002048 | 1 |
| N7 | Gán **911100** cho OPTIONS/WebDAV 1002023 | 1 |

> Nguyên tắc: khi không chắc, **giữ `msg:` hành vi + ghi CRS vào metadata/reference** thay vì ép nhãn CRS sai.

---

## 7. Kiểm chứng đã chạy

| Kiểm tra | Lệnh | Kết quả |
|---|---|---|
| Unit test framework | `cd soc-attacker-advanced-v3.0.0 && PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py'` | **17/17 PASS** |
| Phân loại nguồn A2 | `parse_rule` trên `sensor/a2.rules` | `{custom: 59, owasp_crs: 16}` — tổng **75** |
| Cú pháp report builder | `python3 -m py_compile scripts/build_scenario_results_report.py` | **OK** |
| Diff `a2.rules` | `git diff` | đúng 16 SID tái-neo, `msg:` không đổi |

Khi có dữ liệu runtime, report builder cho: **A1 = 15 ET Open**, **A2 = 16 OWASP CRS-derived + 59 Custom** ⇒ tổng **31/90 = 34,4%** rule có nguồn gốc bên ngoài.

---

## 8. Cách tự kiểm chứng / tái tạo

```bash
# 1. Chạy unit test của framework scenario
cd soc-lab-handoff-v1.0.0/soc-attacker-advanced-v3.0.0
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py'

# 2. Kiểm tra phân loại nguồn rule A2
cd ..
grep -c "owasp_crs_rule" sensor/a2.rules   # => 16

# 3. (Tuỳ chọn) tái sinh report tổng hợp — cần runtime/reports/a1|a2
python3 scripts/build_scenario_results_report.py
```

---

## 9. Tồn đọng

- Chưa regenerate `docs/A1_A2_SCENARIO_RESULTS.md` (cần một lần chạy tạo `runtime/reports/a1|a2`).
- Vài câu chữ docs vẫn gọi "A2 là custom rule" ở **mức nhóm** — vẫn đúng ở cấp nhóm, giữ nguyên.
- Thư mục `temp/` (tài liệu đánh giá nội bộ + file rule tham chiếu) **chưa được commit**.
