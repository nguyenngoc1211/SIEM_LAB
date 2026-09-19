# File manifest

| File/thư mục | Chức năng |
|---|---|
| `docker-compose.yml` | Juice Shop, Nginx gateway và Suricata sidecar |
| `.env.example` | Cấu hình lab với bind mặc định an toàn |
| `.env.production.example` | Mẫu pin image digest và IP private |
| `Makefile` | Lệnh vận hành chuẩn hóa |
| `gateway/nginx.conf` | Reverse proxy và health endpoint |
| `sensor/Dockerfile` | Image Suricata tùy biến |
| `sensor/entrypoint.sh` | Xây/validate ruleset, capture và update rules |
| `sensor/local.rules` | Custom SID 1000001–1000007 |
| `scripts/preflight.sh` | Kiểm tra trước triển khai |
| `scripts/test-alerts.sh` | Sinh traffic kiểm thử có kiểm soát |
| `scripts/system-check.sh` | Kiểm tra end-to-end và tự tìm Wazuh container |
| `scripts/status.sh` | Trạng thái và alert gần nhất |
| `scripts/show-custom-alerts.sh` | Lọc custom SID |
| `scripts/validate.sh` | Kiểm tra Compose/shell syntax |
| `scripts/generate-manifest.sh` | Tạo `MANIFEST.sha256` |
| `wazuh/install-wazuh-4.8.sh` | Cài localfile + Compose override cho Wazuh |
| `wazuh/ossec-localfile.xml` | Block XML tham khảo |
| `ops/logrotate-suricata.conf.template` | Mẫu rotation EVE/fast/stats log |
| `docs/BAO_CAO_TRIEN_KHAI.md` | Báo cáo nghiệm thu |
| `docs/HUONG_DAN_BAN_GIAO.md` | Hướng dẫn triển khai |
| `docs/PRODUCTION_READINESS.md` | Go/No-Go và hardening checklist |
| `docs/RUNBOOK.md` | Vận hành, sự cố, backup/rollback |
| `MANIFEST.sha256` | Checksum toàn bộ file bàn giao |
