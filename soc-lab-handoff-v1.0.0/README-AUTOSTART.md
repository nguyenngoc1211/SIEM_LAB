# SOC Lab Windows AutoStart Pack

Gói này bổ sung tự khởi động cho project SOC hiện có. Không chứa lại Docker Compose chính, image hoặc dữ liệu Wazuh.

## Cách cài vào project hiện tại

Giải nén **toàn bộ nội dung** của gói vào thư mục gốc SOC, cùng cấp với `docker-compose.yml`:

```text
soc-lab-handoff-v1.0.0\
├── docker-compose.yml
├── runtime\
├── sensor\
├── gateway\
└── windows\              <- thư mục từ gói này
```

Sau đó mở PowerShell:

```powershell
cd 'C:\Users\DELL\Documents\Zalo Received Files\NCKH\NCKH_Code\code\soc-lab-handoff-v1.0.0'
Set-ExecutionPolicy -Scope Process Bypass
.\windows\Install-All.ps1 -StartNow
.\windows\Test-SOC-System.ps1
```

Script tự dò Wazuh tại:

```text
C:\Users\DELL\Documents\Zalo Received Files\NCKH\NCKH_Code\code\wazuh-docker\single-node
```

Khi Wazuh nằm ở vị trí khác:

```powershell
.\windows\Install-All.ps1 `
  -WazuhProjectPath 'D:\Lab\wazuh-docker\single-node' `
  -StartNow
```

Tài liệu đầy đủ nằm tại `windows\README.md`.
