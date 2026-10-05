# Đánh giá kết quả đổi tên A2 custom rule theo OWASP CRS

## 0. Phạm vi và nguồn đối chiếu

- File gốc: `sensor/a2.rules` (75 rule, SID `1002001`–`1002075`).
- File đổi tên: `a2_owasp_crs_4_29.rules` (57 rule đổi `msg:`).
- Báo cáo chuyển tên: `a2_owasp_crs_4_29_report.md`.
- Ngữ nghĩa kịch bản: `docs/A1_A2_SCENARIO_RESULTS.md` (mục `Chi tiết A2`).

Kiểm chứng độc lập bằng diff trên cả 75 dòng `alert`:
**đúng là chỉ trường `msg:` thay đổi**, các phần còn lại (SID, protocol, direction, flow, content, pcre, detection_filter, classtype, rev) giữ nguyên.
Vì vậy toàn bộ vấn đề chất lượng nằm ở **tên alert**, không nằm ở detection logic.

## 1. Tiêu chí đánh giá

Một lần đổi tên được coi là **Chấp nhận được** khi thoả mãn đồng thời hai tiêu chí:

- **C1 — Tương đồng với custom rule cũ:** tên mới phải phản ánh đúng *đối tượng quan sát* và *cơ chế phát hiện* của rule gốc (cùng trường HTTP/TCP/UDP, cùng hướng flow, cùng bản chất hành vi). Đây là điều kiện để alert không mô tả sai cái nó vừa bắt.
- **C2 — Tương thích scenario + MITRE technique dự kiến:** tên mới không được gán sai hành vi (ví dụ benign-success thành attack), và không mâu thuẫn với technique được gán cho scenario đó.

**Không thể chấp nhận** nếu vi phạm ít nhất một tiêu chí, đặc biệt khi tên mới tạo ra một *tuyên bố sai* mà bằng chứng trong rule không chống đỡ được.

Lưu ý: kể cả nhóm "Chấp nhận được" vẫn chỉ là **CRS name-aligned / CRS-referenced**, không phải "đã chuyển thành rule của OWASP CRS".

## 2. Kết quả tổng quan

| Hạng mục | Số lượng |
|---|---:|
| Rule đổi `msg:` | 57 |
| Chấp nhận được | 16 (28,1%) |
| Không thể chấp nhận | 41 (71,9%) |

Phân bố theo nhóm phân loại gốc của báo cáo:

| Nhóm gốc | Tổng | Chấp nhận | Không chấp nhận |
|---|---:|---:|---:|
| A | 13 | 13 | 0 |
| B | 44 | 3 | 41 |

## 3. Nhóm Chấp nhận được (16 rule)

| SID | Scenario | Tech | CRS | Tên cũ → Tên mới | Căn cứ chấp nhận |
|---|---|---|---|---|---|
| 1002012 | A2-T1595-02 | T1595 | 913100 | LAB HTTP Capability Assessment → Found User-Agent associated with security scanner | Rule khớp trực tiếp `http.user_agent`; cùng cơ chế scanner-detection, cùng họ T1595. (biên) |
| 1002013 | A2-T1595-03 | T1595 | 913100 | LAB Service Banner Identification → Found User-Agent ... scanner | Cùng lý do: điều kiện cốt lõi là User-Agent. (biên) |
| 1002014 | A2-T1595-04 | T1595 | 913100 | LAB Infrastructure Metadata Probe → Found User-Agent ... scanner | Có điều kiện `http.user_agent` trong rule; họ T1595. (biên) |
| 1002015 | A2-T1595-05 | T1595 | 911100 | LAB Legacy Method Reconnaissance → Method is not allowed by policy | Rule khớp `http.method: TRACE`; TRACE không nằm trong allowed_methods mặc định của CRS. |
| 1002021 | A2-T1595.002-01 | T1595.002 | 913100 | LAB Template Scanner Request → Found User-Agent ... scanner | Khớp đúng User-Agent "Nuclei", vốn là scanner UA điển hình trong CRS. |
| 1002027 | A2-T1595.003-02 | T1595.003 | 920440 | LAB Backup Artifact Enumeration → URL file extension is restricted by policy | Cùng đối tượng là đuôi/khuôn mẫu URL backup–dump. |
| 1002028 | A2-T1595.003-03 | T1595.003 | 930130 | LAB Repository Metadata Enumeration → Restricted File Access Attempt | Khớp đúng họ `.git/.svn/.hg/.env/config/settings` như 930130. |
| 1002046 | A2-T1505.003-01 | T1505.003 | 932160 | LAB Suspicious PHP Command Endpoint Access → Remote Command Execution: Unix Shell Code Found | Payload `?cmd=id` chứa shell token `id`; CRS 932160 thực sự bắt token này. |
| 1002047 | A2-T1505.003-02 | T1505.003 | 932160 | LAB Suspicious JSP Command Endpoint Access → Remote Command Execution: Unix Shell Code Found | Payload `cmd=whoami` chứa shell token `whoami`. |
| 1002049 | A2-T1505.003-04 | T1505.003 | 932160 | LAB Hidden Script Control Request → Remote Command Execution: Unix Shell Code Found | Payload `action=command&value=id` chứa shell token `id`. (biên) |
| 1002050 | A2-T1505.003-05 | T1505.003 | 932160 | LAB Plugin Command Console Access → Remote Command Execution: Unix Shell Code Found | Payload `c=whoami` chứa shell token `whoami`. |
| 1002051 | A2-T1499-01 | T1499 | 912170 | LAB Rapid Rendering Request Burst → Potential Denial of Service (DoS) ... | Rule dùng `detection_filter` đếm burst request; cùng cơ chế burst/DoS với CRS 912. |
| 1002052 | A2-T1499-02 | T1499 | 912170 | LAB Repeated Aggregation Submissions → Potential DoS ... | Cùng cơ chế đếm burst. |
| 1002053 | A2-T1499-03 | T1499 | 912170 | LAB Search Endpoint Request Surge → Potential DoS ... | Cùng cơ chế đếm burst. |
| 1002054 | A2-T1499-04 | T1499 | 912170 | LAB Authentication Endpoint Request Surge → Potential DoS ... | Cùng cơ chế đếm burst. |
| 1002055 | A2-T1499-05 | T1499 | 912170 | LAB Multipart Processing Request Surge → Potential DoS ... | Cùng cơ chế đếm burst. |

Ghi chú nhóm biên: 1002012/2013/2014 dùng UA do lab tự đặt (`network-audit-client/1.0`, `service-banner-audit/1.0`, `infrastructure-inventory/1.0`) nên CRS 913100 bản gốc **sẽ không** khớp literal; chúng chỉ được xếp Chấp nhận vì *cùng trường và cùng cơ chế* (User-Agent → scanner). Nếu yêu cầu là "khớp đúng literal của CRS" thì 3 rule này chuyển sang Không chấp nhận.

## 4. Nhóm Không thể chấp nhận (41 rule)

### N1. CRS 913100 gán cho rule không hề quan sát User-Agent (15 rule)

Tên mới nói "Found User-Agent associated with security scanner", nhưng rule chỉ khớp SYN sweep, UDP probe, URI hoặc request body — **không có điều kiện `http.user_agent` nào**. Điều này tạo tuyên bố sai ngay ở tầng dữ liệu: gói tin không mang User-Agent.

| SID | Scenario | Tech | Tên cũ | Điều kiện thực tế của rule |
|---|---|---|---|---|
| 1002001 | A2-T1046-01 | T1046 | LAB Internal Common Service Sweep | TCP SYN tới dải cổng dịch vụ |
| 1002002 | A2-T1046-02 | T1046 | LAB Internal Administrative Port Sweep | TCP SYN tới cổng admin/DB |
| 1002003 | A2-T1046-03 | T1046 | LAB Internal UDP Service Probe | UDP probe + content marker |
| 1002011 | A2-T1595-01 | T1595 | LAB Sequential Public Service Probes | TCP SYN sweep 7 cổng |
| 1002016 | A2-T1595.001-01 | T1595.001 | LAB Web Address Range Sweep | SYN tới 5 IP, cổng 80 |
| 1002017 | A2-T1595.001-02 | T1595.001 | LAB TLS Address Range Sweep | SYN tới 5 IP, cổng 443 |
| 1002018 | A2-T1595.001-03 | T1595.001 | LAB Remote Access Address Sweep | SYN tới 5 IP, cổng 22 |
| 1002019 | A2-T1595.001-04 | T1595.001 | LAB Alternate Web Address Sweep | SYN tới 5 IP, cổng 8080 |
| 1002020 | A2-T1595.001-05 | T1595.001 | LAB Application Address Range Sweep | SYN tới 5 IP, cổng 3000 |
| 1002022 | A2-T1595.002-02 | T1595.002 | LAB CVE Exposure Check Request | khớp `http.uri` `cve_check=CVE-2021-44228` |
| 1002024 | A2-T1595.002-04 | T1595.002 | LAB Graph Query Schema Probe | khớp URI `/graphql` + body `__schema` |
| 1002025 | A2-T1595.002-05 | T1595.002 | LAB Server Status Exposure Check | khớp URI `/server-status?auto` |
| 1002026 | A2-T1595.003-01 | T1595.003 | LAB Administrative Resource Enumeration | pcre trên URI admin/console/... |
| 1002029 | A2-T1595.003-04 | T1595.003 | LAB API Documentation Enumeration | pcre trên URI swagger/openapi/... |
| 1002030 | A2-T1595.003-05 | T1595.003 | LAB CMS Resource Enumeration | pcre trên URI wp-admin/joomla/... |

### N2. CRS 912170 (DoS) gán cho brute-force / credential guessing / password spraying (15 rule)

Đây là lỗi nặng nhất về mặt ngữ nghĩa: scenario và technique dự kiến thuộc **Credential Access** (`T1110`, `T1110.001`, `T1110.003`), nhưng `msg:` lại tuyên bố **DoS (Impact)**. Tên mới mâu thuẫn trực tiếp với chính kỹ thuật mà kịch bản được gán.

| SID | Scenario | Tech | Tên cũ |
|---|---|---|---|
| 1002031 | A2-T1110-01 | T1110 | LAB Repeated JSON Authentication Failures |
| 1002032 | A2-T1110-02 | T1110 | LAB Repeated Form Authentication Failures |
| 1002033 | A2-T1110-03 | T1110 | LAB Repeated Basic Authentication Failures |
| 1002034 | A2-T1110-04 | T1110 | LAB Repeated Token Authentication Failures |
| 1002035 | A2-T1110-05 | T1110 | LAB Repeated PIN Authentication Failures |
| 1002036 | A2-T1110.001-01 | T1110.001 | LAB Repeated JSON Credential Guesses |
| 1002037 | A2-T1110.001-02 | T1110.001 | LAB Repeated Form Credential Guesses |
| 1002038 | A2-T1110.001-03 | T1110.001 | LAB Repeated Basic Credential Guesses |
| 1002039 | A2-T1110.001-04 | T1110.001 | LAB Repeated Token Credential Guesses |
| 1002040 | A2-T1110.001-05 | T1110.001 | LAB Repeated PIN Credential Guesses |
| 1002041 | A2-T1110.003-01 | T1110.003 | LAB Shared JSON Credential Across Accounts |
| 1002042 | A2-T1110.003-02 | T1110.003 | LAB Shared Form Credential Across Accounts |
| 1002043 | A2-T1110.003-03 | T1110.003 | LAB Shared Basic Credential Across Accounts |
| 1002044 | A2-T1110.003-04 | T1110.003 | LAB Shared Token Credential Across Accounts |
| 1002045 | A2-T1110.003-05 | T1110.003 | LAB Shared PIN Credential Across Accounts |

### N3. CRS 912170 (HTTP-layer) gán cho UDP flood (5 rule)

CRS 912 là bộ đếm request burst ở tầng ModSecurity/HTTP; nó không thể quan sát lưu lượng UDP. Family "DoS" thì khớp (T1498), nhưng lớp telemetry sai hoàn toàn.

| SID | Scenario | Tech | Tên cũ |
|---|---|---|---|
| 1002066 | A2-T1498-01 | T1498 | LAB High Rate DNS Service Traffic |
| 1002067 | A2-T1498-02 | T1498 | LAB High Rate Time Service Traffic |
| 1002068 | A2-T1498-03 | T1498 | LAB High Rate Management Service Traffic |
| 1002069 | A2-T1498-04 | T1498 | LAB High Rate Discovery Service Traffic |
| 1002070 | A2-T1498-05 | T1498 | LAB High Rate Cache Service Traffic |

### N4. CRS 943120 gán cho rule phát hiện "đăng nhập hợp lệ thành công" (1 rule)

| SID | Scenario | Tech | Tên cũ | Tên mới | Vấn đề |
|---|---|---|---|---|---|
| 1002005 | A2-T1078-02 | T1078 | LAB Successful Web Session Reuse | Possible Session Fixation Attack: SessionID Parameter Name with No Referer | Rule chỉ khớp response body `"authenticated":true` + `"channel":"session"`; **đảo nghĩa** từ benign-success (T1078) thành tấn công session fixation. Rule không kiểm tra SessionID param lẫn Referer. |

Đặc biệt bất nhất: 3 rule anh em cùng nhóm T1078 (1002004 bearer, 1002006 api-key, 1002007 basic) **giữ nguyên** tên "LAB Successful ... Credential Use", chỉ 1002005 bị đổi thành tên tấn công.

### N5. CRS XSS/HTML-injection (inbound) gán cho rule response-side (3 rule)

CRS 941110/941160 là rule **request inbound**; các rule này khớp `flow:established,to_client` + `http.response_body`, tức phát hiện nội dung bị chèn về phía client — bản chất là drive-by / content injection (T1189, T1659), không phải XSS filter ở request.

| SID | Scenario | Tech | Tên cũ | Tên mới |
|---|---|---|---|---|
| 1002009 | A2-T1189-02 | T1189 | LAB Hidden Loader Script Delivery | XSS Filter - Category 1: Script Tag Vector |
| 1002062 | A2-T1659-02 | T1659 | LAB Unexpected External Script Insertion | XSS Filter - Category 1: Script Tag Vector |
| 1002063 | A2-T1659-03 | T1659 | LAB Unexpected Hidden Frame Insertion | NoScript XSS InjectionChecker: HTML Injection |

### N6. CRS 932160 "Unix Shell Code" gán cho endpoint không hề chứa shell token (1 rule)

| SID | Scenario | Tech | Tên cũ | Vấn đề |
|---|---|---|---|---|
| 1002048 | A2-T1505.003-03 | T1505.003 | LAB Suspicious ASPX Execution Endpoint Access | Rule chỉ khớp đường dẫn `/aspnet_client/update.aspx?action=exec`; không có shell token, và đây là ASPX/Windows nên càng sai khi gọi là "Unix Shell Code". |

### N7. CRS 911100 "Method is not allowed by policy" gán cho OPTIONS/WebDAV (1 rule)

| SID | Scenario | Tech | Tên cũ | Vấn đề |
|---|---|---|---|---|
| 1002023 | A2-T1595.002-03 | T1595.002 | LAB WebDAV Capability Check | CRS 911100 mặc định **cho phép OPTIONS** trong `tx.allowed_methods`, nên câu "Method is not allowed by policy" tự mâu thuẫn với chính cơ chế của 911100. (biên) |

## 5. So sánh với kỳ vọng ban đầu của bạn

- **Nhóm A:** trùng khớp — cả **13/13** đều Chấp nhận được.
- **Nhóm B:** gần khớp — **41/44** Không thể chấp nhận, nhưng có **3/44** tôi xếp Chấp nhận được (biên):
  - `1002012`, `1002013`, `1002014` — vì rule khớp trực tiếp `http.user_agent`, cùng trường và cùng cơ chế với CRS 913100; khác biệt duy nhất là literal UA do lab tự đặt. Nếu tiêu chí là "khớp literal CRS" thì chuyển 3 rule này sang Không chấp nhận.
- Ca biên đáng lưu ý ở nhóm B: `1002023` (OPTIONS/WebDAV) — tôi vẫn xếp Không chấp nhận nhưng có thể "cứu" nếu đặt tên lại đúng bản chất (ví dụ "WebDAV OPTIONS capability probe").

## 6. Khuyến nghị xử lý

1. **Rollback ưu tiên cao** cho N4 (1002005) và N5 (1002009, 1002062, 1002063) — đây là các ca đảo nghĩa/tuyên bố sai rõ ràng.
2. **Rollback N2** (1002031–1002045): không thể để alert brute-force mang nhãn DoS; tên gốc khớp technique T1110*.
3. **Rollback N1** (15 rule 913100 không có User-Agent): giữ tên mô tả hành vi, không gán nhãn "User-Agent".
4. **Với các ca tương đồng:** giữ tên mô tả hành vi làm `msg:`, đưa CRS vào `metadata:`/`reference:` (ví dụ `metadata:crs_ref 913100, mapping_group B, mapping_strength semantic_only;`) để vẫn truy vết được CRS mà không tạo alert sai.
5. Trước khi freeze dataset, chạy lại 75 scenario A2 để đo tác động lên `event.type`/`event.action`/Mapper, vì normalizer dùng tên signature như tín hiệu ngữ nghĩa mạnh.

## 7. Phụ lục — Bảng đánh giá đầy đủ 57 rule đổi tên

| SID | Scenario | Tech | CRS | Tên cũ | Tên mới (rút gọn) | Nhóm gốc | Kết luận |
|---|---|---|---|---|---|---|---|
| 1002001 | A2-T1046-01 | T1046 | 913100 | LAB Internal Common Service Sweep | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002002 | A2-T1046-02 | T1046 | 913100 | LAB Internal Administrative Port Sweep | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002003 | A2-T1046-03 | T1046 | 913100 | LAB Internal UDP Service Probe | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002005 | A2-T1078-02 | T1078 | 943120 | LAB Successful Web Session Reuse | Possible Session Fixation ... | B | Không chấp nhận |
| 1002009 | A2-T1189-02 | T1189 | 941110 | LAB Hidden Loader Script Delivery | XSS Filter - Cat 1: Script Tag | B | Không chấp nhận |
| 1002011 | A2-T1595-01 | T1595 | 913100 | LAB Sequential Public Service Probes | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002012 | A2-T1595-02 | T1595 | 913100 | LAB HTTP Capability Assessment | Found User-Agent ... scanner | B | Chấp nhận (biên) |
| 1002013 | A2-T1595-03 | T1595 | 913100 | LAB Service Banner Identification | Found User-Agent ... scanner | B | Chấp nhận (biên) |
| 1002014 | A2-T1595-04 | T1595 | 913100 | LAB Infrastructure Metadata Probe | Found User-Agent ... scanner | B | Chấp nhận (biên) |
| 1002015 | A2-T1595-05 | T1595 | 911100 | LAB Legacy Method Reconnaissance | Method is not allowed by policy | A | Chấp nhận |
| 1002016 | A2-T1595.001-01 | T1595.001 | 913100 | LAB Web Address Range Sweep | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002017 | A2-T1595.001-02 | T1595.001 | 913100 | LAB TLS Address Range Sweep | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002018 | A2-T1595.001-03 | T1595.001 | 913100 | LAB Remote Access Address Sweep | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002019 | A2-T1595.001-04 | T1595.001 | 913100 | LAB Alternate Web Address Sweep | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002020 | A2-T1595.001-05 | T1595.001 | 913100 | LAB Application Address Range Sweep | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002021 | A2-T1595.002-01 | T1595.002 | 913100 | LAB Template Scanner Request | Found User-Agent ... scanner | A | Chấp nhận |
| 1002022 | A2-T1595.002-02 | T1595.002 | 913100 | LAB CVE Exposure Check Request | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002023 | A2-T1595.002-03 | T1595.002 | 911100 | LAB WebDAV Capability Check | Method is not allowed by policy | B | Không chấp nhận |
| 1002024 | A2-T1595.002-04 | T1595.002 | 913100 | LAB Graph Query Schema Probe | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002025 | A2-T1595.002-05 | T1595.002 | 913100 | LAB Server Status Exposure Check | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002026 | A2-T1595.003-01 | T1595.003 | 913100 | LAB Administrative Resource Enumeration | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002027 | A2-T1595.003-02 | T1595.003 | 920440 | LAB Backup Artifact Enumeration | URL file extension restricted | A | Chấp nhận |
| 1002028 | A2-T1595.003-03 | T1595.003 | 930130 | LAB Repository Metadata Enumeration | Restricted File Access Attempt | A | Chấp nhận |
| 1002029 | A2-T1595.003-04 | T1595.003 | 913100 | LAB API Documentation Enumeration | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002030 | A2-T1595.003-05 | T1595.003 | 913100 | LAB CMS Resource Enumeration | Found User-Agent ... scanner | B | Không chấp nhận |
| 1002031 | A2-T1110-01 | T1110 | 912170 | LAB Repeated JSON Authentication Failures | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002032 | A2-T1110-02 | T1110 | 912170 | LAB Repeated Form Authentication Failures | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002033 | A2-T1110-03 | T1110 | 912170 | LAB Repeated Basic Authentication Failures | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002034 | A2-T1110-04 | T1110 | 912170 | LAB Repeated Token Authentication Failures | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002035 | A2-T1110-05 | T1110 | 912170 | LAB Repeated PIN Authentication Failures | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002036 | A2-T1110.001-01 | T1110.001 | 912170 | LAB Repeated JSON Credential Guesses | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002037 | A2-T1110.001-02 | T1110.001 | 912170 | LAB Repeated Form Credential Guesses | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002038 | A2-T1110.001-03 | T1110.001 | 912170 | LAB Repeated Basic Credential Guesses | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002039 | A2-T1110.001-04 | T1110.001 | 912170 | LAB Repeated Token Credential Guesses | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002040 | A2-T1110.001-05 | T1110.001 | 912170 | LAB Repeated PIN Credential Guesses | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002041 | A2-T1110.003-01 | T1110.003 | 912170 | LAB Shared JSON Credential Across Accounts | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002042 | A2-T1110.003-02 | T1110.003 | 912170 | LAB Shared Form Credential Across Accounts | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002043 | A2-T1110.003-03 | T1110.003 | 912170 | LAB Shared Basic Credential Across Accounts | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002044 | A2-T1110.003-04 | T1110.003 | 912170 | LAB Shared Token Credential Across Accounts | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002045 | A2-T1110.003-05 | T1110.003 | 912170 | LAB Shared PIN Credential Across Accounts | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002046 | A2-T1505.003-01 | T1505.003 | 932160 | LAB Suspicious PHP Command Endpoint Access | RCE: Unix Shell Code Found | A | Chấp nhận |
| 1002047 | A2-T1505.003-02 | T1505.003 | 932160 | LAB Suspicious JSP Command Endpoint Access | RCE: Unix Shell Code Found | A | Chấp nhận |
| 1002048 | A2-T1505.003-03 | T1505.003 | 932160 | LAB Suspicious ASPX Execution Endpoint Access | RCE: Unix Shell Code Found | B | Không chấp nhận |
| 1002049 | A2-T1505.003-04 | T1505.003 | 932160 | LAB Hidden Script Control Request | RCE: Unix Shell Code Found | A | Chấp nhận (biên) |
| 1002050 | A2-T1505.003-05 | T1505.003 | 932160 | LAB Plugin Command Console Access | RCE: Unix Shell Code Found | A | Chấp nhận |
| 1002051 | A2-T1499-01 | T1499 | 912170 | LAB Rapid Rendering Request Burst | Potential DoS ... Request Bursts | A | Chấp nhận |
| 1002052 | A2-T1499-02 | T1499 | 912170 | LAB Repeated Aggregation Submissions | Potential DoS ... Request Bursts | A | Chấp nhận |
| 1002053 | A2-T1499-03 | T1499 | 912170 | LAB Search Endpoint Request Surge | Potential DoS ... Request Bursts | A | Chấp nhận |
| 1002054 | A2-T1499-04 | T1499 | 912170 | LAB Authentication Endpoint Request Surge | Potential DoS ... Request Bursts | A | Chấp nhận |
| 1002055 | A2-T1499-05 | T1499 | 912170 | LAB Multipart Processing Request Surge | Potential DoS ... Request Bursts | A | Chấp nhận |
| 1002062 | A2-T1659-02 | T1659 | 941110 | LAB Unexpected External Script Insertion | XSS Filter - Cat 1: Script Tag | B | Không chấp nhận |
| 1002063 | A2-T1659-03 | T1659 | 941160 | LAB Unexpected Hidden Frame Insertion | NoScript XSS: HTML Injection | B | Không chấp nhận |
| 1002066 | A2-T1498-01 | T1498 | 912170 | LAB High Rate DNS Service Traffic | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002067 | A2-T1498-02 | T1498 | 912170 | LAB High Rate Time Service Traffic | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002068 | A2-T1498-03 | T1498 | 912170 | LAB High Rate Management Service Traffic | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002069 | A2-T1498-04 | T1498 | 912170 | LAB High Rate Discovery Service Traffic | Potential DoS ... Request Bursts | B | Không chấp nhận |
| 1002070 | A2-T1498-05 | T1498 | 912170 | LAB High Rate Cache Service Traffic | Potential DoS ... Request Bursts | B | Không chấp nhận |

Tổng: 16 Chấp nhận được, 41 Không thể chấp nhận (trên 57 rule đổi tên).
