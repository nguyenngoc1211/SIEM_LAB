# Cách chạy SOC Lab ngày 21/09

Mở PowerShell và chuyển đến thư mục lab:

```powershell
cd "C:\Users\DELL\Documents\Zalo Received Files\NCKH\NCKH_Code\code\soc-lab-handoff-v1.0.0"
```

## 1. Khởi động lab

Nếu source vừa được thay đổi, build lại image:

```powershell
docker compose build
docker compose up -d --wait --wait-timeout 180
```

Nếu image đã có sẵn và không muốn Docker pull từ Internet:

```powershell
docker compose up -d --no-build --pull never --wait --wait-timeout 180
```

Kiểm tra trạng thái:

```powershell
docker compose ps
```

Các container quan trọng phải ở trạng thái `Up`. Các service `soc_gateway`,
`soc_lab_backend` và `soc_suricata` nên có trạng thái `healthy`.

## 2. Chạy bộ 19 scenario v2

Liệt kê scenario:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/attackctl.py list
```

Chạy một scenario:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/attackctl.py run WEB-06
```

Một số ví dụ:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/attackctl.py run RECON-03
docker exec soc_attacker_v2 python3 /opt/soc/attackctl.py run AUTH-12
docker exec soc_attacker_v2 python3 /opt/soc/attackctl.py run SERVER-14
```

Chạy một nhóm scenario theo danh sách ID:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/attackctl.py run-batch RECON-01 RECON-02 WEB-06 AUTH-12 --pause 2
```

Chạy theo category:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/attackctl.py run-category auth --pause 2
```

Chạy toàn bộ 19 scenario:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/attackctl.py run-all --pause 2
```

## 3. Chạy attack chain

Liệt kê các chain:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/attackctl.py chains
```

Chạy một chain:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/attackctl.py run-chain CHAIN-A
```

Ví dụ khác:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/attackctl.py run-chain CHAIN-C
```

## 4. Sinh report cho 19 scenario v2

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/attackctl.py report --output-dir /opt/soc/runtime/reports
```

Report được ghi ra host:

```text
runtime\reports\scenario-results.csv
runtime\reports\scenario-results.json
```

## 5. Build ET Rule Catalog

Rule Catalog chỉ đọc active rules từ volume Suricata. ET rules không bị sửa.

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/tools/build_rule_catalog.py
```

Output sẽ có dạng:

```text
Active rules: 52873
MITRE mapped rules: 27764
Unique SIDs: 52873
Techniques: 50
```

Catalog được ghi tại:

```text
soc-attacker-advanced-v3.0.0\data\rule_catalog.json
```

## 6. Chạy ET scenario theo SID

Chạy một A1 ET Open scenario theo ID:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a1_runner.py --scenario A1-T1190-01
```

Chạy theo scenario ID:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a1_runner.py --scenario A1-T1210-01
```

Chạy theo MITRE technique:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a1_runner.py --technique T1190
```

Chạy toàn bộ ET YAML scenario:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a1_runner.py --all
```

Report ET nằm tại:

```text
runtime\reports\a1\A1-T1190-01.json
```

Expected TechID của A1 được lấy trực tiếp từ metadata của ET rule đang active.
Một lần chạy chỉ PASS toàn bộ khi mapper trả đúng TechID đó:

```text
Environment: PASS
Traffic: PASS
Detection: PASS
SIEM ingestion: PASS
MITRE mapping: PASS
Final: PASS
```

Report JSON giữ đầy đủ `attack_commands`, `suricata_rules_triggered`,
`raw_suricata_alerts`, `raw_wazuh_alerts`, `normalized_alerts` và
`mapper_output`. Detection/Wazuh có thể PASS trong khi mapping FAIL; đây là kết
quả kiểm thử mapper hợp lệ, không phải lỗi sinh traffic.

## 7. Chạy scenario A2

A2 là nhóm scenario kiểm thử các custom rule, tách biệt với A1. Phiên bản runner
mới chọn một Wazuh alert gần nhất rồi gửi alert đó qua workflow n8n để
normalization và mapping.

### 7.1. Kiểm tra và kích hoạt runner mới

Kiểm tra runner trong container đã có hai tham số mới hay chưa:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a2_runner.py --help | Select-String "mapping-webhook-url|alert-quiet-seconds"
```

Nếu output có cả `--mapping-webhook-url` và `--alert-quiet-seconds` thì không
cần build lại. Nếu không có, container vẫn đang chạy code cũ đã đóng trong
image. Build và recreate riêng attacker một lần:

```powershell
docker compose build attacker
docker compose up -d --no-deps --force-recreate attacker
```

Thao tác này không recreate Suricata, Wazuh, n8n hoặc mapper. Kiểm tra lại hai
tham số bằng lệnh `--help` ở trên trước khi chạy scenario.

Xem các tùy chọn của runner:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a2_runner.py --help
```

Liệt kê toàn bộ ID scenario A2 hiện có:

```powershell
docker exec soc_attacker_v2 python3 -c "from pathlib import Path; print('\n'.join(p.parent.name for p in sorted(Path('/opt/soc/scenarios/a2').glob('**/scenario.yaml'))))"
```

### 7.2. Chạy một kịch bản

Chạy theo scenario ID:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a2_runner.py --scenario A2-T1046-01
```

Ví dụ với scenario có MITRE sub-technique:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a2_runner.py --scenario A2-T1110.001-01
```

Cũng có thể truyền trực tiếp đường dẫn tới file YAML:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a2_runner.py /opt/soc/scenarios/a2/T1046/A2-T1046-01/scenario.yaml
```

### 7.3. Chạy nhiều kịch bản theo danh sách ID

Runner nhận một ID mỗi lần. Dùng vòng lặp PowerShell để chạy một danh sách ID
cụ thể; vòng lặp vẫn tiếp tục nếu một scenario trả về kết quả FAIL:

```powershell
$a2ScenarioIds = @(
    "A2-T1046-01",
    "A2-T1078-01",
    "A2-T1110.001-01"
)

foreach ($scenarioId in $a2ScenarioIds) {
    docker exec soc_attacker_v2 python3 /opt/soc/a2_runner.py --scenario $scenarioId
}
```

### 7.4. Chạy tất cả kịch bản của một technique

Lệnh sau chạy tất cả scenario A2 có expected technique `T1046`:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a2_runner.py --technique T1046
```

Với sub-technique, dùng đầy đủ mã technique:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a2_runner.py --technique T1110.001
```

### 7.5. Chạy toàn bộ A2

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a2_runner.py --all
```

Mỗi scenario tạo một report JSON riêng trên host tại:

```text
runtime\reports\a2\<SCENARIO_ID>.json
```

Ví dụ:

```text
runtime\reports\a2\A2-T1046-01.json
```

Lịch sử ground truth của các lần chạy A2 được nối thêm vào:

```text
runtime\ground-truth\a2-scenario-runs.jsonl
```

Sau khi chạy nhiều scenario hoặc `--all`, runner in tổng số PASS/FAIL cùng số
lượng scenario vượt qua từng bước Detection, Ingestion và Mapping. Lệnh trả về
exit code `1` nếu có ít nhất một scenario FAIL; đây có thể là kết quả kiểm thử
mapping, không nhất thiết là lỗi của container hoặc quá trình sinh traffic.

Mapping của scenario được gửi qua webhook n8n production cũ:

```text
http://host.docker.internal:5678/webhook/soc-alert-analysis
```

Workflow tại URL này phải nhận raw Wazuh alert bằng `POST`, chạy normalizer
v1.1 và mapper, rồi trả mapping trực tiếp hoặc trong field `mapping_snapshot`.
Runner không gửi expected TechID trong request mapping.

Runner chờ các Wazuh alert phù hợp ngừng xuất hiện trong 2 giây, sau đó chỉ chọn
một alert có sensor timestamp gần thời điểm kết thúc traffic nhất để gửi vào
workflow. Có thể thay đổi khoảng chờ hoặc URL khi cần:

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a2_runner.py --scenario A2-T1071.001-05 --alert-quiet-seconds 3
```

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/a2_runner.py --scenario A2-T1071.001-05 --mapping-webhook-url http://host.docker.internal:5678/webhook/soc-alert-analysis
```

Report giữ toàn bộ candidate alert để audit, đồng thời ghi alert được chọn trong
`selected_wazuh_alert`, tiêu chí chọn trong `alert_correlation`, và response
mapping của n8n trong `mapper_output`.

Xem alert đã được chọn và lý do chọn:

```powershell
$report = Get-Content "runtime\reports\a2\A2-T1071.001-05.json" -Raw | ConvertFrom-Json
$report.alert_correlation | ConvertTo-Json -Depth 10
$report.selected_wazuh_alert | ConvertTo-Json -Depth 30
```

Xem toàn bộ kết quả mapping n8n, gồm evidence, alternatives và
`candidate_trace` nếu workflow trả field đó:

```powershell
$report.mapper_output[0] | ConvertTo-Json -Depth 50
```

Nếu `candidate_trace` không xuất hiện, kiểm tra node `Respond to Webhook` của
n8n. Node này phải trả nguyên output của `Map to ATT&CK`; nếu chỉ trả
`mapping_snapshot` rút gọn thì runner không thể phục hồi `candidate_trace` đã
bị workflow loại bỏ.

## 8. Kiểm tra MITRE coverage

```powershell
docker exec soc_attacker_v2 python3 /opt/soc/tools/coverage.py
```

Output JSON:

```text
runtime\reports\mitre_coverage.json
```

## 9. Xem Suricata alert

Theo dõi `fast.log`:

```powershell
docker exec soc_suricata tail -f /var/log/suricata/fast.log
```

Theo dõi toàn bộ EVE JSON:

```powershell
docker exec soc_suricata tail -f /var/log/suricata/eve.json
```

Tìm ET SID `2008538`:

```powershell
docker exec soc_suricata grep '"signature_id":2008538' /var/log/suricata/eve.json
```

## 10. Xem Wazuh alert và MITRE mapping

Theo dõi Wazuh alert:

```powershell
docker exec single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.json
```

Tìm alert theo SID:

```powershell
docker exec single-node-wazuh.manager-1 grep '"signature_id":"2008538"' /var/ossec/logs/alerts/alerts.json
```

Với SID `2008538`, kết quả đúng cần có:

```text
MITRE tactic: TA0001
MITRE technique: T1190
```

## 11. Chạy unit test

```powershell
cd soc-attacker-advanced-v3.0.0
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
cd ..
```

Kết quả hiện tại:

```text
Ran 10 tests
OK
```

## 12. Dừng lab

Dừng container nhưng giữ volume và dữ liệu:

```powershell
docker compose down
```

Không sử dụng lệnh sau nếu muốn giữ Suricata rules và Wazuh logs:

```powershell
docker compose down -v
```

## Ghi chú

- Chỉ chạy scenario trong Docker/local lab.
- Attacker được cố định tại `172.29.0.10` và được loại khỏi Suricata
  `HOME_NET` để các ET rule inbound hoạt động đúng.
- Runner chờ EVE preflight trước khi sinh traffic, tránh chạy khi Suricata còn
  đang validate rules.
- Additional SID được lưu để đánh giá cross-detection nhưng không tự động làm
  scenario thất bại.
- Mapping MITRE được so sánh trên đúng expected SID, không suy đoán từ tên
  signature.
