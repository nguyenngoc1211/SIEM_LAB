# Kết quả lịch sử A1 (ET Open)

Ngày kiểm chứng: 2026-09-25.

Expected Technique ID của mỗi scenario được lấy trực tiếp từ metadata của ET
Open rule đang active. Mapper được gọi bằng raw Wazuh alert; không dùng MITRE
metadata có sẵn trong ET/Wazuh để quyết định mapping PASS.

| Scenario | SID | Expected | Mapper | Trạng thái mapper | Suricata | Wazuh | Kết quả |
| --- | ---: | --- | --- | --- | --- | --- | --- |
| A1-T1046-01 | 2068312 | T1046 | - | insufficient_evidence | PASS | PASS | FAIL |
| A1-T1046-02 | 2068313 | T1046 | - | insufficient_evidence | PASS | PASS | FAIL |
| A1-T1078-01 | 2056147 | T1078 | - | insufficient_evidence | PASS | PASS | FAIL |
| A1-T1189-01 | 2069667 | T1189 | - | insufficient_evidence | PASS | PASS | FAIL |
| A1-T1189-02 | 2069668 | T1189 | - | insufficient_evidence | PASS | PASS | FAIL |
| A1-T1190-01 | 2008538 | T1190 | T1595.002 | mapped | PASS | PASS | FAIL |
| A1-T1190-02 | 2010087 | T1190 | T1595.002 | mapped | PASS | PASS | FAIL |
| A1-T1190-03 | 2034647 | T1190 | - | insufficient_evidence | PASS | PASS | FAIL |
| A1-T1190-04 | 2001202 | T1190 | T1190 | mapped | PASS | PASS | PASS |
| A1-T1190-05 | 2011843 | T1190 | T1190 | mapped | PASS | PASS | PASS |
| A1-T1210-01 | 2030335 | T1210 | T1190 | mapped | PASS | PASS | FAIL |
| A1-T1210-02 | 2030502 | T1210 | T1190 | mapped | PASS | PASS | FAIL |
| A1-T1210-03 | 2033272 | T1210 | T1190 | mapped | PASS | PASS | FAIL |
| A1-T1210-04 | 2044530 | T1210 | T1190 | mapped | PASS | PASS | FAIL |
| A1-T1210-05 | 2034808 | T1210 | - | insufficient_evidence | PASS | PASS | FAIL |

Tổng hợp:

- Environment/traffic: 15/15 PASS.
- Suricata detection: 15/15 PASS.
- Wazuh ingestion: 15/15 PASS.
- Mapper đúng expected TechID ET: 2/15 PASS.
- Mapper khác TechID ET: 6/15.
- Mapper trả `insufficient_evidence`: 7/15.

Chạy lại một scenario:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a1_runner.py --scenario A1-T1190-01
```

Artifact tương ứng nằm tại `runtime/reports/a1/A1-T1190-01.json`.
