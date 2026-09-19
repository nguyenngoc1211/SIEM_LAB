# SOC Attacker Advanced v3.0.0

Container tạo traffic mô phỏng cho SOC lab Juice Shop + Nginx + Suricata + Wazuh.

Bản này có đúng **80 kịch bản**. Nó bị khóa mặc định vào target lab `http://soc_gateway` và network Docker `soc_backend`.

## Chạy container

```powershell
cd .\soc-attacker-advanced-v3.0.0
docker compose up -d --build
```

Kiểm tra:

```powershell
docker ps --filter "name=soc_attacker_v3"
```

## Lệnh dùng chính

Liệt kê kịch bản:

```powershell
docker compose exec -T attacker-v3 attackctl list
```

Liệt kê nhóm:

```powershell
docker compose exec -T attacker-v3 attackctl categories
```

Chạy toàn bộ 80 kịch bản:

```powershell
docker compose exec -T attacker-v3 attackctl run-all
```

Chạy từ kịch bản 01 đến 20:

```powershell
docker compose exec -T attacker-v3 attackctl run-all --from-id 01 --to-id 20
```

Chạy riêng một kịch bản:

```powershell
docker compose exec -T attacker-v3 attackctl run 35
```

Chạy theo nhóm:

```powershell
docker compose exec -T attacker-v3 attackctl run-category sqli
docker compose exec -T attacker-v3 attackctl run-category xss
docker compose exec -T attacker-v3 attackctl run-category auth
```

Dry-run để xem nó sẽ gửi gì mà chưa bắn traffic:

```powershell
docker compose exec -T attacker-v3 attackctl run-all --dry-run
```


## An toàn

- Không scan Internet mặc định.
- Không chứa malware.
- Không chạy exploit thật.
- Không brute-force lớn; mọi burst đều bị giới hạn bằng `MAX_BURST`.
- Chỉ dùng để tạo dấu hiệu traffic cho IDS/SIEM trong lab.

