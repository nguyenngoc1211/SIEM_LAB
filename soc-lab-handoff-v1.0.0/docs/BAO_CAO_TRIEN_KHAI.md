# Báo cáo triển khai SOC Detection Lab

**Ngày báo cáo:** 10/07/2026  
**Trạng thái:** Đã kiểm thử end-to-end trong môi trường lab  
**Phạm vi:** Nginx, OWASP Juice Shop, Suricata 7.0.17, Wazuh single-node 4.8.0

## 1. Tóm tắt điều hành

Hệ thống đã hoàn thành luồng thu thập và phân tích cảnh báo:

```text
HTTP client
   -> Nginx reverse proxy
   -> OWASP Juice Shop

Nginx network namespace
   -> Suricata packet inspection
   -> runtime/suricata-logs/eve.json
   -> read-only bind mount vào Wazuh Manager
   -> Wazuh analysis/indexing
   -> Wazuh Dashboard
```

Kết quả nghiệm thu cuối cùng do người triển khai cung cấp:

| Hạng mục | Kết quả |
|---|---:|
| `soc_gateway`, `soc_juice_shop`, `soc_suricata` | PASS |
| Wazuh manager, indexer, dashboard | PASS |
| HTTP qua Nginx | `200` |
| Suricata engine | Đang xử lý traffic |
| Suricata restart count | `0` |
| EVE JSON | Khoảng `556 KB` tại thời điểm kiểm tra |
| Tổng Suricata alerts | `53` |
| Wazuh đọc được EVE JSON | PASS |
| Cấu hình Wazuh | PASS |
| Wazuh Suricata alerts | `43` |

**Kết luận kỹ thuật:** pipeline phát hiện và đưa sự kiện từ Suricata lên Wazuh đã hoạt động. Đây là kết quả đạt yêu cầu cho lab/staging.

## 2. Cảnh báo về phạm vi production

OWASP Juice Shop là ứng dụng **cố ý không an toàn**, được thiết kế cho đào tạo và thử nghiệm bảo mật. Không được dùng hệ thống này như ứng dụng nghiệp vụ, không chứa dữ liệu thật và không công khai trực tiếp ra Internet.

Do đó:

- Có thể triển khai trong VLAN lab, sandbox, staging an ninh hoặc cyber range.
- Không phê duyệt triển khai public production theo cấu hình mặc định.
- Nếu cần truy cập từ xa, phải qua VPN, bastion hoặc allowlist IP và chỉ bind vào IP private cụ thể.

## 3. Kiến trúc và vai trò

### 3.1 `juice-shop`

Ứng dụng mục tiêu. Chỉ expose cổng `3000` trong Docker network, không publish ra host.

### 3.2 `gateway`

Nginx reverse proxy duy nhất publish cổng host. Health check dùng `/__gateway_health__`.

### 3.3 `suricata`

Chia sẻ network namespace với `gateway` qua:

```yaml
network_mode: "service:gateway"
```

Suricata đọc traffic trên `eth0`, ghi EVE JSON ra bind mount và tự cập nhật ET Open rules. Rules tải về được kiểm tra cú pháp trước khi reload.

### 3.4 Wazuh

Wazuh Manager đọc trực tiếp file:

```text
/var/log/suricata/eve.json
```

Đây là tích hợp log phía Manager, không phải Wazuh Agent trong từng container. Vì vậy các container SOC không xuất hiện như endpoint riêng trong trang **Endpoints**. Cảnh báo phải xem tại **Threat Hunting** hoặc **Security events**.

## 4. Rules và alert

Project giữ SID local trong dải:

| SID | Mục đích |
|---:|---|
| 1000001 | Probe kiểm tra pipeline |
| 1000002 | SQL injection pattern |
| 1000003 | XSS pattern |
| 1000004 | Path traversal pattern |
| 1000005 | sqlmap User-Agent |
| 1000006 | Nhiều lần đăng nhập thất bại |
| 1000007 | Command injection pattern |

Hai cảnh báo nhiễu đã quan sát:

- `2200122` — AF-PACKET truncated packet.
- `2200003` — IPv4 truncated packet.

Các alert này thường liên quan capture trên virtual interface/offload. Không nên tắt ngay; cần baseline, xác nhận ảnh hưởng rồi mới suppress hoặc tune.

## 5. Các lỗi đã xử lý

### 5.1 Cổng `8080` bị chiếm, mặc định đã đổi sang `8081`

Nguyên nhân: stack cũ vẫn chạy. Đã xóa/dừng container cũ trước khi chạy stack mới.

### 5.2 Suricata restart loop

Nguyên nhân ban đầu: entrypoint chờ cập nhật rules và fail trước khi khởi động engine. Đã đổi sang khởi động từ ruleset đã validate, cập nhật ET Open dưới nền.

### 5.3 Sai PCRE và trùng SID

- Dấu `;` trong PCRE command-injection làm parser hiểu sai option.
- Local rules từng bị nối lặp vào file ET Open, gây duplicate SID.

Bản bàn giao dùng `\x3b` và xây file `soc-combined.rules` riêng, sau đó validate trước khi kích hoạt.

### 5.4 Wazuh không thấy EVE JSON

Nguyên nhân: chưa mount thư mục log vào Wazuh Manager. Script tích hợp tạo Compose override và bind mount read-only.

### 5.5 Tên container Wazuh thay đổi

Compose mới đặt tên dạng `single-node-wazuh.manager-1`, không phải dạng cũ có dấu gạch dưới. Script kiểm tra mới tự tìm container theo image, không hard-code tên.

## 6. Quy trình nghiệm thu

```bash
cp .env.example .env
make preflight
make up

sudo ./wazuh/install-wazuh-4.8.sh /path/to/wazuh-docker/single-node
cd /path/to/wazuh-docker/single-node
sudo ./wazuh-suricata-up.sh

cd /path/to/project
make test
sleep 10
make check
```

Điều kiện PASS:

- HTTP `200` qua gateway.
- Suricata engine đang chạy, restart count bằng 0.
- `eve.json` tăng dung lượng.
- Có Suricata alert.
- Wazuh Manager nhìn thấy EVE JSON.
- `wazuh-analysisd -t` thành công.
- Có alert Suricata trong `/var/ossec/logs/alerts/alerts.json`.

## 7. Dashboard

Không dùng trang **Endpoints** để kiểm tra pipeline này. Truy cập **Threat Hunting** hoặc **Security events** và lọc:

```text
rule.groups:suricata
```

Có thể lọc custom rule:

```text
data.alert.signature_id:1000001
```

## 8. Rủi ro và việc cần làm trước prod-like

1. Pin toàn bộ image bằng digest; không dùng `latest` hoặc tag trôi.
2. Không bind `0.0.0.0`; dùng IP private cụ thể hoặc `127.0.0.1` sau reverse proxy/VPN.
3. Thiết lập firewall/allowlist.
4. Bật log rotation và theo dõi dung lượng đĩa.
5. Sao lưu cấu hình Wazuh và kiểm thử rollback.
6. Tách kế hoạch nâng cấp Wazuh khỏi thay đổi tích hợp này.
7. Lập kế hoạch chuyển Suricata 7 sang Suricata 8.
8. Cài Wazuh Agent trên Docker host và bật Docker listener nếu cần theo dõi lifecycle container; việc đó độc lập với luồng EVE JSON hiện tại.

## 9. Phiên bản và vòng đời

Môi trường đã kiểm thử dùng Wazuh `4.8.0` và Suricata `7.0.17`. Tại ngày lập báo cáo, tài liệu chính thức liệt kê Wazuh `4.14.6` là bản mới hơn; mọi central component Wazuh cần cùng patch level khi nâng cấp. Suricata `8.0.6` là nhánh stable mới, còn nhánh `7.0.x` đang ở cuối cửa sổ hỗ trợ tháng 07/2026.

Không nâng cấp trực tiếp trong cùng lần bàn giao. Đề xuất:

- Giữ bộ đã kiểm thử trong lab để bảo toàn kết quả.
- Tạo change riêng để nâng Wazuh và Suricata, chạy lại toàn bộ test acceptance.

## 10. Tài liệu chính thức tham khảo

- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/
- Wazuh–Suricata integration: https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html
- Wazuh Docker monitoring: https://documentation.wazuh.com/current/user-manual/capabilities/container-security/monitoring-docker.html
- Wazuh release notes: https://documentation.wazuh.com/current/release-notes/index.html
- Wazuh upgrade guide: https://documentation.wazuh.com/current/upgrade-guide/index.html
- Suricata downloads: https://suricata.io/download/
- Suricata EOL policy: https://suricata.io/our-story/eol-policy/
- Suricata rule management: https://docs.suricata.io/en/latest/rule-management/suricata-update.html
- Suricata rule reload: https://docs.suricata.io/en/latest/rule-management/rule-reload.html
