# Hướng dẫn bàn giao và triển khai

## 1. Nội dung bàn giao

```text
soc-lab-handoff-v1.0.0/
├── docker-compose.yml
├── .env.example
├── .env.production.example
├── Makefile
├── README.md
├── gateway/
├── sensor/
├── scripts/
├── wazuh/
├── ops/
└── docs/
```

## 2. Chuẩn bị máy chủ

- Docker Engine và Docker Compose plugin.
- Wazuh official Docker single-node đã hoạt động.
- Một mạng lab cô lập.
- Không dùng dữ liệu thật.
- Cổng được firewall kiểm soát.

## 3. Kiểm tra checksum

```bash
sha256sum -c MANIFEST.sha256
```

## 4. Cấu hình

```bash
cp .env.example .env
nano .env
```

Khuyến nghị:

```dotenv
LAB_BIND_IP=<IP_PRIVATE_CUA_SERVER>
LAB_PORT=8081
RULE_UPDATE_INTERVAL=86400
```

Không đặt `LAB_BIND_IP=0.0.0.0` nếu chưa có firewall/allowlist.

## 5. Preflight và khởi động

```bash
make preflight
make up
```

Kiểm tra:

```bash
docker compose ps
curl -I http://127.0.0.1:8081
```

Nếu bind vào IP private, thay `127.0.0.1` bằng IP đó.

## 6. Tích hợp Wazuh

```bash
sudo ./wazuh/install-wazuh-4.8.sh \
  /absolute/path/to/wazuh-docker/single-node
```

Script sẽ:

- backup `wazuh_manager.conf`;
- thêm `<localfile>` cho EVE JSON;
- tạo `docker-compose.suricata.yml`;
- tạo script up/down có override.

Khởi động/recreate Wazuh Manager:

```bash
cd /absolute/path/to/wazuh-docker/single-node
sudo ./wazuh-suricata-up.sh
```

## 7. Kiểm thử nghiệm thu

```bash
cd /absolute/path/to/soc-lab-handoff-v1.0.0
make test
sleep 10
make check
```

`make check` phải kết thúc với `FAIL=0`. `WARN` về truncated packet có thể được chấp nhận tạm thời nếu custom alerts vẫn xuất hiện.

## 8. Kiểm tra Dashboard

Vào **Threat Hunting** hoặc **Security events**:

```text
rule.groups:suricata
```

Trang **Endpoints** không liệt kê các container này vì pipeline không cài Wazuh Agent trong từng container.

## 9. Theo dõi Docker host tùy chọn

Muốn thấy host Docker như một endpoint và thu sự kiện create/start/stop/delete container:

- cài Wazuh Agent trên chính host Docker;
- bật `docker-listener`;
- không cài agent riêng cho mỗi container trừ khi có yêu cầu đặc biệt.

## 10. Dừng và rollback

Dừng lab:

```bash
cd /path/to/project
make down
```

Dừng Wazuh bằng override:

```bash
cd /path/to/wazuh-docker/single-node
sudo ./wazuh-suricata-down.sh
```

Khôi phục cấu hình Manager từ file backup được script in ra lúc cài, sau đó chạy lại Wazuh bằng Compose gốc.

Không dùng `docker compose down -v` với Wazuh trừ khi chủ đích xóa dữ liệu.
