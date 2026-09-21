# Production readiness và quyết định Go/No-Go

## Quyết định hiện tại

| Mục tiêu | Quyết định |
|---|---|
| Cyber range / đào tạo | GO |
| Lab SOC nội bộ | GO |
| Staging bảo mật cô lập | GO có điều kiện |
| Internet-facing production | **NO-GO** |
| Ứng dụng chứa dữ liệu thật | **NO-GO** |

Lý do chính: Juice Shop là ứng dụng cố ý chứa lỗ hổng.

## Checklist bắt buộc trước môi trường prod-like

- [ ] Đặt trong VLAN/subnet cô lập.
- [ ] Không có dữ liệu thật, credential thật hoặc token thật.
- [ ] Chỉ bind IP private cụ thể hoặc localhost.
- [ ] Firewall/ACL chỉ cho phép nhóm kiểm thử.
- [ ] Truy cập từ xa qua VPN/bastion.
- [ ] Pin image bằng digest.
- [ ] Quét image và SBOM được lưu cùng change record.
- [ ] Cấu hình log rotation.
- [ ] Cảnh báo dung lượng đĩa.
- [ ] Backup cấu hình Wazuh trước triển khai.
- [ ] Test rollback.
- [ ] Dashboard dùng TLS và credential đã thay mặc định.
- [ ] Xác nhận custom SOC v2 SID `1001001–1001099` đi tới Wazuh; không chỉnh sửa ET Rules.
- [ ] Review/tune SID nhiễu `2200122`, `2200003`.
- [ ] Phê duyệt kế hoạch nâng Wazuh 4.8.0.
- [ ] Phê duyệt kế hoạch chuyển Suricata 7 sang 8.

## Pin image

Các tag `latest`, `alpine` và `7.0` có thể trỏ đến image khác theo thời gian. Trên máy đã pull image được phê duyệt, lấy digest bằng:

```bash
docker image inspect bkimminich/juice-shop:latest \
  --format '{{index .RepoDigests 0}}'

docker image inspect nginx:alpine \
  --format '{{index .RepoDigests 0}}'

docker image inspect jasonish/suricata:7.0 \
  --format '{{index .RepoDigests 0}}'
```

Ghi digest vào `.env`, lưu vào change ticket và kiểm tra lại trước mỗi deploy.

## Exposure

Cấu hình bàn giao mặc định:

```dotenv
LAB_BIND_IP=127.0.0.1
```

Đây là safe default có chủ đích. Trường hợp cần truy cập từ mạng lab, dùng IP private cụ thể. Không đổi sang `0.0.0.0` chỉ để “chạy cho nhanh”.

## Log retention

File EVE JSON tăng liên tục. Dùng template:

```text
ops/logrotate-suricata.conf.template
```

Thay đường dẫn tuyệt đối, kiểm thử bằng:

```bash
sudo logrotate -d /etc/logrotate.d/soc-suricata
```

## Phiên bản

Bộ này đã test với:

- Wazuh 4.8.0.
- Suricata 7.0.17.

Tại ngày 10/07/2026:

- Wazuh release notes đã có 4.14.6.
- Suricata stable có 8.0.6 và 7.0.17.
- Nhánh Suricata 7.0.x ở cuối cửa sổ hỗ trợ tháng 07/2026.

Không coi việc “đang chạy” là đủ tiêu chuẩn production. Nâng cấp phải là change riêng, có backup, compatibility review và regression test.
