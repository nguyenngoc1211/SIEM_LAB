# Các rule trong ET Open có technique trong module mapping

## 1. Các technique không có rule ET Open

Khớp chính xác bằng ID, không suy diễn từ tên rule:

| Technique | Số rule ET active | Kết quả |
| --- | --- | --- |
| T1595 | 0 | Không tìm thấy |
| T1595.001 | 0 | Không tìm thấy |
| T1595.002 | 0 | Không tìm thấy |
| T1595.003 | 0 | Không tìm thấy |
| T1110 | 0 | Không tìm thấy |
| T1110.001 | 0 | Không tìm thấy |
| T1110.003 | 0 | Không tìm thấy |
| T1505.003 | 0 | Không tìm thấy |
| T1499 | 0 | Không tìm thấy |
| T1071.001 | 0 | Không tìm thấy |
| T1659 | 0 | Không tìm thấy |

## 2. Các technique có rule ET Open

Mức độ:

- Dễ: dùng ngay HTTP/UDP tới gateway hiện có, không cần thêm service.
- Trung bình: cần helper tạm thời như listener hoặc client/server trong container, hoặc payload nhị phân.
- Khó: cần thay đổi topology/service đáng kể hoặc tái tạo state nhiều bước.

### T1190 — 6.221 active rules

Chọn 5 rule dễ tái hiện nhất:

| SID | Rule | Mức | Lý do |
| --- | --- | --- | --- |
| 2008538 | ET SCAN Sqlmap SQL Injection Scan | Dễ | Chỉ cần HTTP request với User-Agent bắt đầu bằng `sqlmap`. Scenario hiện có đã kiểm thử thành công. |
| 2010087 | ET SCAN Suspicious User-Agent Containing SQL Inject/ion | Dễ | User-Agent chỉ cần chứa `SQL`, sau đó là `Inject`; response không quan trọng. |
| 2034647 | ET EXPLOIT Apache log4j RCE Attempt (http ldap) | Dễ | Gửi `${jndi:ldap://...}` trong request tới gateway; không cần máy đích thực sự có Log4j. |
| 2001202 | ET WEB_SPECIFIC_APPS PHPNuke general SQL injection attempt | Dễ | URI `/modules.php?` chứa `name=`, rồi `UNION` và `SELECT`; HTTP 404 vẫn có thể alert. |
| 2011843 | ET WEB_SPECIFIC_APPS BaconMap Local File Inclusion Attempt | Dễ | GET tới đường dẫn BaconMap, tham số `filepath=` chứa traversal đã URL-encode. |

SID 2008538 và 2034647 đã xuất hiện trong EVE hiện tại, đều mang `T1190/TA0001`. Scenario 2008538 có kết quả đầy đủ `PASS` cho environment, traffic, detection, SIEM và MITRE trong [SCN-T1190-ET-SQLMAP.json (line 1)](C:/Users/DELL/Documents/Zalo Received Files/NCKH/NCKH_Code/code/soc-lab-handoff-v1.0.0/runtime/reports/a1/SCN-T1190-ET-SQLMAP.json:1).

### T1189 — 2.053 active rules

| SID | Rule | Mức | Lý do |
| --- | --- | --- | --- |
| 2069667 | ET MALWARE Fake Updates Victim Click Confirmation Javascript Observed | Dễ | Có thể để `/lab/reflect` trả về ba chuỗi JavaScript mà rule yêu cầu; chiều gateway → attacker phù hợp. |
| 2069668 | ET MALWARE Observed Fake Updates Page Inbound | Dễ | Phản chiếu ba cụm từ “working on updates…”, “installing features…” và “critical security update”. |
| 2063270 | ET EXPLOIT Generic MultiStage Javascript Redirect Activity M1 | Trung bình | Cần attacker đóng vai HTTP server và một client thuộc `HOME_NET` tải response chứa chuỗi JavaScript đúng thứ tự. |
| 2063263 | ET EXPLOIT_KIT Generic MultiStage Javascript Redirect Activity M2 | Trung bình | Tương tự M1, nhưng body phải có chuỗi tạo thẻ `<a>` và `a.click()` đúng khoảng cách. |
| 2069998 | ET EXPLOIT_KIT Balada Javascript Inject Observed | Trung bình | Cần response từ phía external chứa bốn literal escaped chính xác; có thể làm bằng HTTP server giả lập. |

Các rule này chỉ yêu cầu nội dung response, không chứng minh trình duyệt thật sự bị compromise.

### T1046 — 4 active rules

| SID | Rule | Mức | Lý do |
| --- | --- | --- | --- |
| 2068312 | ET INFO Insecure Proxy Discovery via AWS Metadata M1 | Dễ | Request URI bắt đầu `/proxy/` và kết thúc `/latest/meta-data/iam/security-credentials/`. |
| 2068313 | ET INFO Insecure Proxy Discovery via AWS Metadata M2 | Dễ | Tương tự, với `/latest/dynamic/instance-identity/document`. |
| 2064028 | ET MALWARE IP Check With Minimal Headers and Custom User-Agent | Trung bình | Cần client trong `HOME_NET`, Host thuộc danh sách như `ipinfo.io`, User-Agent chính xác và bộ header tối thiểu. |
| 2070126 | ET WEB_SPECIFIC_APPS Exchange EWS InstallApp SSRF Attempt | Trung bình | Cần listener HTTP tạm trên gateway port 444 và POST body chứa `InstallApp`, `ManifestUrl` cùng URL/UNC. |

Đáng chú ý: hai rule proxy/metadata được gắn T1046 nhưng observable thực tế gần SSRF/proxy discovery hơn network service scan truyền thống.

### T1078 — 2 active rules

| SID | Rule | Mức | Lý do |
| --- | --- | --- | --- |
| 2056147 | ET WEB_SPECIFIC_APPS Cisco Smart Licensing API Hardcoded Admin Credentials | Dễ | Gửi request tới `/cslu/` với giá trị Basic Authorization cố định; ứng dụng không cần là Cisco thật. |
| 2055590 | ET WEB_SPECIFIC_APPS Fortra FileCatalyst HSQLDB Default Credentials | Trung bình | Cần TCP listener port 4406 và gửi đúng chuỗi nhị phân chứa `SA` và `GOSENSGO613` trên connection established. |

### T1210 — 134 active rules

| SID | Rule | Mức | Lý do |
| --- | --- | --- | --- |
| 2030335 | ET EXPLOIT D-Link Command Injection CVE-2020-13782 | Dễ | GET URI chứa `_ajax_explorer.sgi?action=`, `&path=`, `&where=`, `&en=;`. |
| 2030502 | ET EXPLOIT Comtrend VR-3033 Command Injection | Dễ | GET tới `ping.cgi?pingIpAddress=` có dấu `;`. |
| 2033272 | ET EXPLOIT Unknown Command Injection / Mirai Activity | Dễ | POST với URI bắt đầu `/op_type=` và chứa dấu `;`. |
| 2044530 | ET EXPLOIT Razer Sila Router Command Injection — wget | Dễ | POST `/ubus/` với body chứa cấu trúc `"exec",{"command":"wget...`. |
| 2034808 | ET HUNTING Log4j RCE lower TCP bypass | Dễ | Đặt chuỗi dạng `${lower:j}ndi...` trong một TCP/HTTP request established tới gateway. |

Cần thận trọng về ngữ nghĩa: các request từ attacker ngoài vào public gateway vẫn có thể kích hoạt rule mang T1210, dù ATT&CK định nghĩa T1210 chủ yếu cho lateral movement.

### T1498 — 1 active rule

| SID | Rule | Mức | Lý do |
| --- | --- | --- | --- |
| 2059017 | ET EXPLOIT Microsoft LDAP Referral Response Inbound CVE-2024-49113 | Trung bình | Cần UDP datagram có source port 389 và BER/LDAP byte sequence chính xác. UDP không cần listener đích, nhưng phải dựng payload nhị phân cẩn thận. |

Rule này phát hiện một exploit/DoS payload, không chứng minh đã tạo ra network bandwidth exhaustion thực tế.

### T1095 — 12 active rules

Chọn 5 rule ít phụ thuộc nhất:

| SID | Rule | Mức | Lý do |
| --- | --- | --- | --- |
| 2062886 | ET MALWARE GorillaBot CnC Server Probe | Trung bình | Client `HOME_NET` gửi đúng một byte `0x01` tới external server port 38242 trên TCP established. |
| 2063513 | ET MALWARE SillyRAT Keylogger:On | Trung bình | External helper server trả chuỗi Base64 `a2V5bG9nZ2VyOm9u\n` cho HOME client. |
| 2063514 | ET MALWARE SillyRAT Server PING | Trung bình | External server trả payload kết thúc bằng `)J@NcRfU`; rule này đồng thời thiết lập flowbit SillyRAT. |
| 2063515 | ET MALWARE SillyRAT Keylogger:Dump | Trung bình | Tương tự SID 2063513, với chuỗi Base64 `a2V5bG9nZ2VyOmR1bXA=\n`. |
| 2066801 | ET MALWARE ZeroTrace CnC Server Settings Inbound | Trung bình | Response TCP phải chứa ZIP magic và các tên `ip.txt`, `inj.txt`, `uac.txt`, `downloadexecute.txt`, `port.txt` theo đúng thứ tự. |

Các rule này không chạy được chỉ bằng request HTTP thông thường. Cần một external raw-TCP server trong attacker container và HOME-side client chạy qua interface được Suricata theo dõi.
