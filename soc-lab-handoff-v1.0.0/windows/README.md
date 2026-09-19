# Tự động khởi động SOC Lab trên Windows

Bộ script này tự động thực hiện chuỗi sau sau khi tài khoản Windows đăng nhập:

```text
Docker Desktop
  -> SOC Compose: Nginx + Juice Shop + Suricata + attacker
  -> Wazuh Compose: manager + indexer + dashboard
  -> mount eve.json vào Wazuh manager
  -> gán restart policy unless-stopped
```

## 1. Điều kiện trước khi cài

- Windows 10/11.
- Docker Desktop đang dùng Linux containers.
- Lệnh `docker`, `docker compose` chạy được trong PowerShell.
- Project này và repository `wazuh-docker\single-node` đã có trên máy.
- Các image đã được pull ít nhất một lần. Tác vụ tự khởi động dùng `--pull never` để không phụ thuộc mạng hoặc credential helper khi đăng nhập.

Cấu trúc khuyến nghị:

```text
C:\...\code\
├── soc-lab-handoff-v1.2.0\
└── wazuh-docker\
    └── single-node\
```

## 2. Cài đặt một lần

Mở PowerShell bằng đúng tài khoản sẽ chạy Docker Desktop:

```powershell
cd 'C:\...\code\soc-lab-handoff-v1.2.0'
Set-ExecutionPolicy -Scope Process Bypass
.\windows\Install-All.ps1 -StartNow
```

Script tự dò Wazuh tại thư mục ngang hàng `wazuh-docker\single-node`.
Khi đặt Wazuh ở vị trí khác:

```powershell
.\windows\Install-All.ps1 `
  -WazuhProjectPath 'D:\Lab\wazuh-docker\single-node' `
  -StartNow
```

Quá trình cài đặt sẽ:

1. Tạo `windows\Config.psd1` chứa đường dẫn local.
2. Sao lưu rồi bổ sung `<localfile>` đọc `/var/log/suricata/eve.json` vào Wazuh manager config.
3. Dùng `windows\wazuh\docker-compose.suricata.yml` để mount thư mục log Suricata vào manager.
4. Đăng ký Scheduled Task `SOC Lab AutoStart` chạy khi đăng nhập.
5. Khởi động toàn bộ stack ngay khi có `-StartNow`; lần chạy cài đặt được phép pull image còn thiếu.
6. Gán `restart: unless-stopped` cho các container SOC và Wazuh hiện có.

## 3. Kiểm tra

```powershell
.\windows\Test-SOC-System.ps1
```

Xem trạng thái tác vụ:

```powershell
Get-ScheduledTask -TaskName 'SOC Lab AutoStart'
Get-ScheduledTaskInfo -TaskName 'SOC Lab AutoStart'
```

Xem log tự khởi động:

```powershell
Get-Content .\runtime\autostart-logs\soc-autostart.log -Tail 100
```

Thử chạy tác vụ mà không cần khởi động lại Windows:

```powershell
Start-ScheduledTask -TaskName 'SOC Lab AutoStart'
Start-Sleep 30
.\windows\Test-SOC-System.ps1
```

## 4. Lệnh vận hành

Khởi động thủ công:

```powershell
.\windows\Start-SOC-System.ps1
```

Dừng container nhưng không xóa container/volume:

```powershell
.\windows\Stop-SOC-System.ps1
```

Dừng cả Docker Desktop:

```powershell
.\windows\Stop-SOC-System.ps1 -StopDockerDesktop
```

Gán lại restart policy:

```powershell
.\windows\Set-RestartPolicies.ps1
```

## 5. Truy cập dịch vụ

Juice Shop qua Nginx:

```text
http://127.0.0.1:8080
```

Wazuh Dashboard trên máy Windows:

```text
https://127.0.0.1
```

Truy cập từ máy khác qua SSH tunnel:

```bash
ssh -L 8443:127.0.0.1:443 dell@WINDOWS_IP
```

Sau đó mở:

```text
https://localhost:8443
```

Bộ lọc Wazuh:

```text
rule.groups:suricata
```

## 6. Gỡ tự khởi động

```powershell
.\windows\Uninstall-AutoStart.ps1
```

Xóa luôn file cấu hình đường dẫn được sinh ra:

```powershell
.\windows\Uninstall-AutoStart.ps1 -RemoveGeneratedConfig
```

Lệnh này không xóa container, image, volume, log hoặc repository Wazuh.

## 7. Xử lý lỗi thường gặp

### Docker Engine chưa sẵn sàng

```powershell
docker desktop status
docker info
```

Tăng thời gian chờ khi cài lại:

```powershell
.\windows\Install-All.ps1 -DockerWaitSeconds 420
```

### Image chưa tồn tại local

Tự khởi động cố ý không pull image. Chạy thủ công một lần khi có mạng:

```powershell
cd 'C:\...\soc-lab-handoff-v1.2.0'
docker compose pull
docker compose build

cd 'C:\...\wazuh-docker\single-node'
docker compose pull
```

Sau đó chạy lại:

```powershell
.\windows\Start-SOC-System.ps1
```

### Wazuh không đọc eve.json

```powershell
docker exec single-node-wazuh.manager-1 sh -c 'ls -lh /var/log/suricata/eve.json'
docker exec single-node-wazuh.manager-1 sh -c "grep -n suricata /var/ossec/etc/ossec.conf"
```

Kiểm tra file nguồn trên Windows:

```powershell
Get-Item .\runtime\suricata-logs\eve.json
```

### Scheduled Task chạy lỗi

```powershell
Get-ScheduledTaskInfo -TaskName 'SOC Lab AutoStart'
Get-Content .\runtime\autostart-logs\soc-autostart.log -Tail 200
```

Không tách `if {}` và `else {}` thành hai lần paste riêng trong PowerShell.

## 8. Lưu ý vận hành

- Dùng `docker compose stop`, không dùng `down -v`, khi chỉ muốn dừng tạm thời.
- Docker Desktop là ứng dụng theo phiên người dùng; tác vụ này chạy sau khi tài khoản đăng nhập, không phải trước màn hình đăng nhập.
- Không công khai Juice Shop hoặc Wazuh Dashboard trực tiếp ra Internet.
- Chỉ chạy attacker và các bài kiểm thử trên lab do bạn sở hữu hoặc được phép kiểm thử.
