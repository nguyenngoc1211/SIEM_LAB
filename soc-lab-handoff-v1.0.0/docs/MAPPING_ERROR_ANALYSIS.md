# Phân tích nguyên nhân mapping MITRE sai sau lần chạy A1/A2

Ngày phân tích: 2026-09-27.

## Phạm vi

Phân tích này dùng 90 report hiện tại trong `runtime/reports/a1/` và `runtime/reports/a2/`, đặc biệt là `normalized_alert`, `candidate_trace`, `supporting_evidence`, `contradictory_evidence` và `alternative_candidates`. Quy tắc evidence được đối chiếu trực tiếp với `../data/mitre-mapping/artifacts/attack/attack_final.mapping.json`.

Sau khi sửa SID 1002030, cả 90/90 scenario đều có Suricata alert và Wazuh alert. Kết quả mapping hiện tại:

| Chỉ số | Kết quả |
|---|---:|
| Primary khớp chính xác | 35/90 (38,9%) |
| Primary sai nhưng có kết quả | 46/90 (51,1%) |
| Không chấp nhận primary (`insufficient_evidence`) | 9/90 (10,0%) |
| Tổng không exact | 55/90 (61,1%) |
| Expected technique nằm trong top 3 | 73/90 (81,1%) |

Top-3 recall 81,1% nhưng top-1 exact chỉ 38,9% cho thấy lỗi chính nằm ở chuẩn hóa, evidence gate và xếp hạng cuối, không chỉ ở retrieval.

## Các nguyên nhân chính

### 1. Normalizer làm mất ý nghĩa hành vi mà evidence yêu cầu

- `T1071.001` yêu cầu `event.type = network_communication`, nhưng cả năm alert Periodic Web Traffic bị chuẩn hóa thành `web_request`. Candidate đúng đứng hạng 2–3 nhưng bị `required_passed=false`; `T1190` thắng nhờ hai tín hiệu rất chung là `web_request` và `target.type=application`.
- `T1595.002` yêu cầu `event.type = network_scan`. Ba request kiểm tra CVE/WebDAV/server-status bị chuẩn hóa thành `web_request/unknown`, nên `T1190` thắng. Hai alert được nhận là scan vẫn bị lẫn với `T1046` hoặc technique cha `T1595`.
- `T1498` và phần lớn `T1499` có tên rule thể hiện high-rate, burst hoặc surge nhưng `event.action` vẫn là `unknown`. Evidence của cả hai technique cần `event.action=flood`; kết quả là năm `T1498` và hai `T1499` bị từ chối dù candidate đúng có điểm cao.
- `T1659` có chiều `to_client`, nhưng normalizer thường trả `web_request` hoặc `data_transfer`, action `unknown`, và target `application`. Evidence lại tìm `network_communication`, content injection/modification và recipient host/application, nên candidate đúng yếu hoặc không vào top 5.
- Với `T1189`, chiều `to_client` đã đúng nhưng target vẫn là `application`; evidence mong `target.type=host` cho nội dung độc hại được giao tới client.

### 2. Evidence từ khóa không bao phủ cách đặt tên rule thực tế

- `T1595.003` chỉ nhận các cụm như `wordlist scan`, `directory enumeration`, `content discovery`. Các rule thật dùng `Administrative Resource Enumeration`, `Backup Artifact Enumeration`, `Repository Metadata Enumeration`, `API Documentation Enumeration`, `CMS Resource Enumeration`. Vì vậy cả năm alert đều bị `T1046` vượt qua dù đã chuẩn hóa đúng thành `network_scan/discover`.
- `T1110.001` tìm `password guessing`, `many passwords one account`; rule dùng `Repeated ... Credential Guesses`. `T1110.003` tìm `password spray`, `same password across accounts`; rule dùng `Shared ... Credential Across Accounts`. Alert đơn cũng không mang cardinality user/password, nên parent `T1110` với evidence authentication/failure rộng hơn luôn thắng.
- `T1505.003` không nhận `Hidden Script Control Request` và `Plugin Command Console Access` là web-shell access vì rule name không chứa các cụm web shell trong evidence.
- `T1659` tìm `content injection`, `response injection`, `traffic data modification`; rule dùng các biến thể `banner insertion`, `script insertion`, `download link insertion`.

### 3. `T1190` quá rộng và không có required gate

`T1190` có positive evidence cho `event.type=web_request` và `target.type=application`, nhưng không yêu cầu `event.action=exploit` hoặc một signature thực sự nói về exploitation. Vì vậy nó trở thành fallback mặc định cho traffic HTTP và chiếm nhầm nhiều nhóm: `T1071.001`, `T1189`, `T1499`, `T1505.003`, `T1595`, `T1595.002` và `T1659`.

Trong trace của `A2-T1071.001-01`, retrieval đưa `T1071.001` lên đầu trước rerank, nhưng reranker đẩy `T1190` từ hạng 12 lên hạng 1. Candidate `T1190` sau đó được evidence chung hợp thức hóa dù không có exploit signal. Đây là kết hợp giữa rerank quá mạnh và evidence gate quá lỏng.

### 4. Thiếu cơ chế phân giải technique cha–con

`T1110` thắng toàn bộ mười scenario của `T1110.001` và `T1110.003`; `T1595`/`T1046` cạnh tranh với các sub-technique scan. Pipeline đang chấm độc lập từng technique, chưa có quy tắc “ưu tiên sub-technique khi có tín hiệu đặc hiệu, dùng parent làm fallback”. Vì thế evidence rộng của parent thường lấn evidence hẹp của child.

### 5. Một phần ground truth cần được audit, đặc biệt `T1210`

Năm rule A1 mang TechID ET Open `T1210` đều là HTTP command-injection/RCE vào D-Link, Comtrend, router hoặc Log4j, được normalizer mô tả là `web_request/exploit`, protocol HTTP, target application. Evidence của `T1210` lại mô tả remote-service/lateral exploitation, ưu tiên SMB/RDP/SSH; evidence của `T1190` phù hợp trực tiếp với public-facing web application exploit.

Vì vậy năm kết quả này “sai so với nhãn ET” nhưng có thể đúng hơn về ngữ nghĩa ATT&CK. Không nên ép mapper trả `T1210` chỉ để tăng điểm; cần review nhãn với chuyên gia và ghi nhận trường hợp đa nhãn hoặc nhãn gây tranh luận.

## Đề xuất giảm hai loại lỗi

### A. Giảm primary sai (hiện 46/90)

1. **Siết gate của `T1190`:** chỉ cho phép mapping khi có `event.action=exploit` hoặc signature chứa exploit class cụ thể như SQL injection, command injection, RCE, path traversal, authentication bypass. `web_request + application` không được đủ để map.
2. **Bổ sung semantic normalization:** sinh các field hành vi độc lập với TechID như `behavior.family`, `auth.pattern`, `scan.kind`, `dos.layer`, `content.delivery_direction`. Ví dụ: `credential_guessing`, `password_spraying`, `wordlist_enumeration`, `vulnerability_assessment`, `network_flood`, `application_exhaustion`, `content_injection`.
3. **Mở rộng evidence bằng từ đồng nghĩa đang thực sự xuất hiện:** thêm `resource enumeration`, `artifact enumeration`, `shared credential across accounts`, `credential guesses`, `request burst/surge`, `banner/script/link insertion`, `command console`, nhưng không dùng SID hoặc expected TechID làm input.
4. **Phân giải cha–con:** nếu child vượt gate đặc hiệu thì chọn child; chỉ trả parent khi không child nào đủ evidence. Áp dụng trước cho `T1110.*` và `T1595.*`.
5. **Hiệu chỉnh reranker:** không min-max điểm theo từng alert khiến một raw score rất nhỏ thành 1.0; dùng calibration trên tập validation, giới hạn ảnh hưởng reranker khi evidence hành vi không đủ, và áp dụng margin giữa top 1/top 2.
6. **Thêm contradictory evidence:** phạt `T1190` khi direction là `to_client` hoặc không có exploit signal; phạt `T1046` khi HTTP path enumeration rõ ràng nhưng không có multi-port/service evidence; phạt parent khi child-specific pattern đã match.

### B. Giảm `MISSING/insufficient_evidence` (hiện 9/90)

1. Chuẩn hóa high-rate/burst/surge thành `action=flood`, sau đó phân biệt network DoS và endpoint DoS bằng application protocol, target và loại resource bị tiêu hao.
2. Cho normalizer khai thác context hành vi của signature và threshold/rate từ rule catalog, nhưng loại bỏ hoàn toàn metadata MITRE để tránh leakage.
3. Với alert tổng hợp từ threshold rule, bổ sung các thuộc tính như request/packet count, cửa sổ thời gian và cardinality user/password. Một alert đơn hiện không thể tự chứng minh các hành vi lặp hoặc phân phối credential.
4. Chỉ abstain khi candidate không qua required evidence; nếu evidence đủ nhưng confidence sát ngưỡng, trả `uncertain` cùng top 3 thay vì `MISSING`, để downstream có thể review.

## Thứ tự triển khai khuyến nghị

1. Thêm required gate và negative evidence cho `T1190`.
2. Sửa normalizer cho `T1071.001`, DoS, scan sub-technique, auth pattern, `to_client` target và content injection.
3. Mở rộng evidence synonyms từ các rule name hiện có.
4. Thêm parent/child resolver.
5. Audit ground truth `T1210`, rồi chạy lại toàn bộ 90 scenario và so sánh bốn metric: exact top 1, expected top 3, wrong-primary và insufficient-evidence.

Mục tiêu vòng tiếp theo hợp lý là giữ top-3 recall ít nhất 81%, giảm wrong-primary xuống dưới 25% và insufficient-evidence xuống dưới 5%, trước khi tối ưu confidence tuyệt đối.
