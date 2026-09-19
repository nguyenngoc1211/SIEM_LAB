# Runbook vận hành

## Lệnh thường dùng

```bash
make preflight
make up
make status
make test
make check
make logs
make down
```

## Health check nhanh

```bash
curl -s -o /dev/null -w 'HTTP %{http_code}\n' http://127.0.0.1:8081

docker compose ps

docker top soc_suricata -eo pid,comm,args

ls -lh runtime/suricata-logs/eve.json
```

## Xem custom alerts

```bash
./scripts/show-custom-alerts.sh
```

## Wazuh container name

Không hard-code tên vì Docker Compose có thể dùng dấu `-` hoặc `_`:

```bash
MANAGER=$(docker ps --format '{{.Names}} {{.Image}}' \
  | awk '$2 ~ /^wazuh\/wazuh-manager:/ {print $1; exit}')
echo "$MANAGER"
```

## Wazuh không nhìn thấy EVE JSON

```bash
docker exec "$MANAGER" ls -lh /var/log/suricata/eve.json

docker inspect "$MANAGER" \
  --format '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}'
```

Khởi động Wazuh với override:

```bash
cd /path/to/wazuh-docker/single-node
sudo ./wazuh-suricata-up.sh
```

## Suricata restart loop

```bash
docker logs --tail 200 soc_suricata

docker inspect soc_suricata \
  --format 'Status={{.State.Status}} Restarts={{.RestartCount}}'
```

Các lỗi đã biết trong bản cũ:

- PCRE chứa dấu `;` chưa escape.
- Duplicate SID do nối local rules nhiều lần.

Bản hiện tại tạo `soc-combined.rules` và validate trước khi chạy/reload.

## Port bị chiếm

```bash
ss -ltnp | grep ':8081'
docker ps --format 'table {{.Names}}\t{{.Ports}}' | grep 8081
```

Không xóa nhầm Wazuh. Chỉ dừng stack/container cũ đang publish cùng cổng.

## Endpoints hiển thị disconnected agent cũ

Đây là agent từ container cũ, không liên quan pipeline EVE hiện tại. Xem danh sách:

```bash
docker exec "$MANAGER" /var/ossec/bin/agent_control -l
```

Xóa thủ công nếu đã xác nhận agent không còn sử dụng:

```bash
docker exec -it "$MANAGER" /var/ossec/bin/manage_agents
```

## Backup

Trước thay đổi:

```bash
tar -czf soc-lab-config-$(date +%F-%H%M).tar.gz \
  --exclude='runtime/suricata-logs/*' \
  .
```

Wazuh installer tự tạo backup timestamp của `wazuh_manager.conf`.

## Rollback

1. `make down` tại project.
2. Chạy `wazuh-suricata-down.sh`.
3. Khôi phục `wazuh_manager.conf.backup.<timestamp>`.
4. Xóa hoặc bỏ qua `docker-compose.suricata.yml`.
5. Chạy Wazuh bằng Compose gốc.
6. Không xóa volume Wazuh.
