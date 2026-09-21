# SOC Detection Lab Handoff

Bộ mã nguồn triển khai luồng giám sát:

```text
Client -> Nginx gateway -> OWASP Juice Shop
             ^
             | shared network namespace
          Suricata
             |
          EVE JSON
             |
        Wazuh Manager -> Indexer -> Dashboard
```

## Phạm vi sử dụng

Đây là môi trường **lab/staging cho đào tạo và kiểm thử SOC**. OWASP Juice Shop là ứng dụng cố ý chứa lỗ hổng; không được công khai môi trường này ra Internet hoặc đưa dữ liệu thật vào hệ thống.

Tài liệu chính:

- `docs/BAO_CAO_TRIEN_KHAI.md`: báo cáo kỹ thuật và kết quả nghiệm thu.
- `docs/HUONG_DAN_BAN_GIAO.md`: quy trình triển khai cho trưởng nhóm.
- `docs/PRODUCTION_READINESS.md`: điều kiện bắt buộc trước khi chạy trong hạ tầng production/prod-like.
- `docs/RUNBOOK.md`: vận hành, kiểm tra, xử lý lỗi và rollback.
- `docs/FILE_MANIFEST.md`: chức năng của từng file.

## Khởi động nhanh trong mạng lab cô lập

```bash
cp .env.example .env
# Sửa LAB_BIND_IP thành IP private cụ thể nếu cần truy cập từ máy khác.
make preflight
make up
```

Tích hợp với Wazuh official single-node:

```bash
sudo ./wazuh/install-wazuh-4.8.sh /absolute/path/to/wazuh-docker/single-node
cd /absolute/path/to/wazuh-docker/single-node
sudo ./wazuh-suricata-up.sh
```

Kiểm tra toàn bộ:

```bash
cd /path/to/soc-lab-handoff-v1.0.0
make test
sleep 10
make check
```

Dashboard: mở `Threat Hunting` hoặc `Security events`, dùng bộ lọc:

```text
rule.groups:suricata
```

## SOC Attack Scenarios v2

The evaluation suite now contains 19 behavioral scenarios and four composite chains:

```powershell
docker exec soc_attacker_v2 attackctl run WEB-06
docker exec soc_attacker_v2 attackctl run-batch RECON-01 RECON-02 WEB-06 --pause 2
docker exec soc_attacker_v2 attackctl run-all --pause 2
docker exec soc_attacker_v2 attackctl run-chain CHAIN-A
docker exec soc_attacker_v2 attackctl report --output-dir /opt/soc/runtime/reports --mapper-url http://host.docker.internal:8000
```

See `SCENARIOS_V2.md` and `MIGRATION_V1_TO_V2.md`. V2 custom SIDs use `1001001-1001099`; ET rules are not modified.

Custom SID của SOC Attack Scenarios v2: `1001001` đến `1001099`. Đây là file custom riêng; ET Rules không bị sửa đè.
