# Đánh giá bỏ event-gate và đề xuất evidence từ tên rule

Ngày đánh giá: 2026-10-01.

## 1. Phạm vi và cách đánh giá

Phân tích này dùng 90 report A1/A2 hiện có trong `runtime/reports/a1/` và
`runtime/reports/a2/`, cùng với:

- `candidate_trace`, `primary_mapping`, `alternative_candidates` và
  `normalized_alert` trong từng report;
- 90 tên rule trong catalog/scenario A1 và A2;
- bộ evidence đang dùng tại
  `../data/mitre-mapping/artifacts/attack/attack_final.mapping.json`;
- logic gate trong `mitre_mapper/evidence.py` và cách chọn final pool trong
  `mitre_mapper/pipeline.py`.

Không chạy lại hệ thống, không gọi mapper và không sửa cấu hình mapping.

Mô phỏng phản thực tế chỉ thay điều kiện hợp lệ của candidate từ:

```text
required_passed AND event_signal_present AND NOT excluded
```

thành:

```text
required_passed AND NOT excluded
```

Các rank retrieval/reranker, điểm evidence, `confusion_guard`, ngưỡng quyết
định `0.55`, giới hạn final pool bằng 5 và các exclusion hiện tại được giữ
nguyên. Vì vậy đây là ước lượng trực tiếp từ trace hiện có, không phải kết quả
benchmark sau khi build/reindex/chạy lại.

## 2. Hiệu quả dự kiến khi bỏ event-gate

| Chỉ số | Hiện tại | Bỏ event-gate | Thay đổi |
|---|---:|---:|---:|
| Exact primary | 41/90 (45,6%) | 40/90 (44,4%) | -1 |
| Expected technique trong top 3 | 72/90 (80,0%) | 83/90 (92,2%) | +11 |
| `insufficient_evidence`/không có primary | 10/90 (11,1%) | 7/90 (7,8%) | -3 |
| Primary thay đổi | — | 4/90 (4,4%) | — |

### Các primary thay đổi

| Scenario | Expected | Hiện tại | Sau khi bỏ gate | Nhận xét |
|---|---|---|---|---|
| `A2-T1595.002-02` | `T1595.002` | `T1595.002` | `T1190` | Regression: candidate HTTP quá rộng chiếm primary. |
| `A2-T1499-04` | `T1499` | MISSING | `T1190` | Thoát MISSING nhưng vẫn sai. |
| `A2-T1595-01` | `T1595` | MISSING | `T1046` | Thoát MISSING nhưng vẫn sai. |
| `A2-T1659-05` | `T1659` | MISSING | `T1095` | Thoát MISSING nhưng vẫn sai. |

Không có case top-1 sai nào được sửa thành đúng chỉ nhờ bỏ event-gate. Lợi ích
chính nằm ở candidate recall: expected technique có thể vào final pool/top 3
dù normalizer không sinh đúng `event.type` hoặc `event.action`.

Top-3 tăng ròng 11 case (13 gain, 2 loss). Năm scenario `T1071.001`, nhiều
case `T1078`, hai A1 `T1046` và ba case đang MISSING được hưởng lợi về recall.
Hai loss top-3 là `A1-T1210-05` và `A2-T1505.003-05`, do candidate không có
event signal chen vào giới hạn top 5 trước khi final pool được sắp theo điểm.

### Kết luận về event-gate

- Nếu mục tiêu là **không bỏ sót candidate để analyst/downstream review**, bỏ
  hard gate có hiệu quả rõ: top-3 recall dự kiến tăng từ 80,0% lên 92,2%.
- Nếu mục tiêu là **primary tự động chính xác**, bỏ gate không có lợi: exact
  top-1 giảm một case và cả ba MISSING được giải phóng đều thành primary sai.
- Bỏ gate không giải quyết lỗi xếp hạng cha–con (`T1110` so với `T1110.*`,
  `T1595`/`T1046` so với `T1595.*`) hoặc evidence quá rộng của `T1190`.

Khuyến nghị là bỏ `event_signal_present` khỏi điều kiện vào candidate pool,
nhưng không coi candidate thiếu event signal là primary mạnh chỉ nhờ
retrieval/reranker. Candidate loại này nên được phép vào alternatives; để làm
primary, nó nên có ít nhất một phrase `producer.rule_name` đặc hiệu bên dưới,
không match negative/exclusion, và vượt margin quyết định. Cách này giữ phần
recall tăng thêm mà giảm nguy cơ biến MISSING thành confident wrong mapping.

## 3. Nguyên tắc chọn phrase từ tên rule

Các giá trị dưới đây dành cho trường `producer.rule_name`. Matcher hiện tại
không phân biệt hoa/thường và `contains_any` là phép OR, nên mỗi giá trị phải
đủ ý nghĩa khi đứng một mình.

1. Ưu tiên cụm hành vi gồm 2–5 từ; không dùng một token rộng như `session`,
   `periodic`, `probe`, `sweep`, `traffic`, `request`, `fake`, `deceptive`,
   `credential` hoặc `insertion`.
2. Không đưa `LAB`, `ET`, SID, vendor hoặc CVE vào evidence chính. Chúng làm
   tăng điểm trên bộ scenario nhưng không tổng quát sang rule ngoài tập test.
3. Phrase đặc hiệu có thể dùng trọng số `+0.35` đến `+0.40`. Phrase yếu hơn
   chỉ nên dùng `+0.15` đến `+0.25` và kết hợp evidence field khác.
4. Negative phrase phân biệt trực tiếp technique dễ nhầm nên dùng khoảng
   `-0.30` đến `-0.40`; không biến negative thành exclusion trừ khi quan hệ
   loại trừ chắc chắn.
5. Với parent/sub-technique, phrase của child phải thắng parent. Parent nên là
   fallback khi không phrase child nào match.

## 4. Danh sách phrase đề xuất

Các phrase được viết chữ thường để dễ đọc; engine hiện tại vẫn match được tên
rule có chữ hoa. Cột positive là tập nên thêm hoặc thay cho keyword quá rộng
đang có. Cột negative là đề xuất mới cho `negative_evidence` trên
`producer.rule_name`.

| Technique | `positive_evidence` đề xuất | `negative_evidence` đề xuất | Lý do/phạm vi |
|---|---|---|---|
| `T1046` Network Service Discovery | `common service sweep`; `administrative port sweep`; `udp service probe` | `public service probes`; `address range sweep`; `template scanner`; `exposure check`; `resource enumeration` | Bao phủ 3 rule A2 và tách internal discovery khỏi các nhóm recon. Hai rule A1 chứa `insecure proxy discovery` không nên được dùng để sinh keyword vì hành vi AWS metadata/proxy không phải bằng chứng tổng quát cho Network Service Discovery. |
| `T1071.001` Web Protocols | `periodic web` | `request burst`; `request surge`; `capability check`; `address range sweep`; `banner insertion`; `script insertion` | Một phrase bao phủ cả 5 biến thể Telemetry/Checkin/Heartbeat/Sync/Tasks. Nên thay keyword hiện tại `periodic` bằng `periodic web`. |
| `T1078` Valid Accounts | `successful bearer session`; `web session reuse`; `successful api credential use`; `successful basic credential use`; `hardcoded admin credentials` | `authentication failures`; `credential guesses`; `credential across accounts` | Phân biệt việc dùng credential/session thành công với brute force. Nên bỏ keyword quá rộng `session`. |
| `T1095` Non-Application Layer Protocol | `tcp node greeting`; `udp node greeting`; `length prefixed tcp beacon`; `tcp heartbeat frame`; `udp synchronization frame` | `periodic web`; `http beacon`; `https beacon` | Bao phủ 5 framing TCP/UDP tùy biến mà không nhầm `web heartbeat` của `T1071.001`. |
| `T1110` Brute Force | `authentication failures` | `credential guesses`; `credential across accounts` | Bao phủ 5 rule `Repeated <format> Authentication Failures`. Hai negative đẩy pattern cụ thể xuống sub-technique tương ứng thay vì để parent luôn thắng. |
| `T1110.001` Password Guessing | `credential guesses` | `credential across accounts` | `credential guesses` bao phủ cả 5 format và đặc hiệu hơn `repeated`. Không phạt `authentication failures` vì failure vẫn tương thích với password guessing. |
| `T1110.003` Password Spraying | `credential across accounts`; `shared credential` | `credential guesses` | Cụm `credential across accounts` xuất hiện trong cả 5 rule và thể hiện đúng cardinality của spraying. Không phạt `authentication failures` vì spraying cũng thường tạo failure. |
| `T1189` Drive-by Compromise | `fake updates`; `victim click confirmation`; `fake verification page delivery`; `loader script delivery`; `browser update delivery` | `banner insertion`; `script insertion`; `hidden frame insertion`; `configuration redirection`; `download link insertion`; `sql injection`; `command injection` | Bao phủ 2 A1 và 3 A2, đồng thời tách content delivery/client compromise khỏi `T1659` và server-side exploit. Nên thay các keyword đơn `fake`/`deceptive` bằng phrase đầy đủ. |
| `T1190` Exploit Public-Facing Application | `sql injection scan`; `sql injection scanner`; `local file inclusion`; `rce attempt` | `periodic web`; `request burst`; `request surge`; `template scanner`; `exposure check`; `capability check`; `schema probe`; `resource enumeration`; `command endpoint access`; `command console access`; `banner insertion`; `script insertion` | Bổ sung LFI và cách đặt tên scanner trong A1, nhưng vẫn yêu cầu exploit signal. Không dùng `web_request`/`application` làm bằng chứng đủ. |
| `T1210` Exploitation of Remote Services | Chưa có phrase an toàn để thêm từ các tên rule hiện tại | `sql injection`; `local file inclusion` | Năm rule A1 đều là HTTP command injection/RCE vào D-Link, Comtrend, router hoặc Log4j; các cụm `command injection` và `rce` cũng là evidence mạnh của `T1190`. Thêm chúng cho `T1210` sẽ tối ưu theo nhãn ET nhưng làm xấu ngữ nghĩa ATT&CK. Cần audit/relabel trước; không dùng vendor/CVE làm shortcut. |
| `T1498` Network Denial of Service | `high rate dns service traffic`; `high rate time service traffic`; `high rate management service traffic`; `high rate discovery service traffic`; `high rate cache service traffic` | `request burst`; `request surge`; `aggregation submissions` | Phrase giữ cả high-rate và service/network context; không dùng `high rate` một mình. |
| `T1499` Endpoint Denial of Service | `request burst`; `request surge`; `aggregation submissions` | `high rate dns service traffic`; `high rate time service traffic`; `high rate management service traffic`; `high rate discovery service traffic`; `high rate cache service traffic`; `packet flood`; `network flood` | Ba phrase positive bao phủ cả 5 rule application exhaustion và phân biệt với network/service flood. |
| `T1505.003` Web Shell | `command endpoint access`; `execution endpoint access`; `script control request`; `command console access` | `injection attempt`; `rce attempt`; `template scanner`; `exposure check` | `access`/`control`/`console` thể hiện sử dụng endpoint đã tồn tại, khác initial exploitation của `T1190`. Bao phủ PHP/JSP/ASPX mà không phụ thuộc ngôn ngữ. |
| `T1595` Active Scanning | `public service probes`; `capability assessment`; `service banner identification`; `infrastructure metadata probe`; `method reconnaissance` | `internal common service sweep`; `internal administrative port sweep`; `address range sweep`; `template scanner`; `exposure check`; `capability check`; `schema probe`; `resource enumeration`; `artifact enumeration` | Giữ parent cho active recon chưa đủ đặc hiệu; negative chuyển IP-range, vulnerability và wordlist scan xuống child, internal scan sang `T1046`. |
| `T1595.001` Scanning IP Blocks | `address range sweep` | `internal common service sweep`; `internal administrative port sweep`; `service banner identification`; `exposure check`; `resource enumeration` | Một phrase bao phủ đủ Web/TLS/Remote Access/Alternate Web/Application Address Range Sweep. |
| `T1595.002` Vulnerability Scanning | `template scanner`; `exposure check`; `capability check`; `schema probe` | `sql injection`; `command injection`; `local file inclusion`; `rce attempt`; `address range sweep`; `resource enumeration`; `capability assessment` | Bao phủ cả 5 rule mà vẫn tách scan/check khỏi exploit thật, IP sweep, wordlist scan và parent scenario `HTTP Capability Assessment`. |
| `T1595.003` Wordlist Scanning | `resource enumeration`; `artifact enumeration`; `metadata enumeration`; `documentation enumeration` | `authentication failures`; `credential guesses`; `credential across accounts`; `address range sweep`; `service sweep`; `port sweep` | Bao phủ Administrative/CMS Resource, Backup Artifact, Repository Metadata và API Documentation Enumeration; tránh dùng `enumeration` một mình. |
| `T1659` Content Injection | `banner insertion`; `script insertion`; `hidden frame insertion`; `configuration redirection`; `download link insertion` | `fake updates`; `verification page delivery`; `loader script delivery`; `browser update delivery`; `sql injection`; `command injection`; `path traversal` | Bao phủ đủ 5 rule content modification và tách khỏi drive-by delivery hoặc input khai thác server. |

## 5. Các keyword không nên thêm dù xuất hiện trong tên rule

| Keyword | Vấn đề |
|---|---|
| `session` | Quá rộng; có thể là valid account, web session bình thường hoặc C2 session. |
| `periodic` | Có thể là HTTP C2, TCP beacon hoặc tác vụ hợp lệ; dùng `periodic web` cho `T1071.001`. |
| `probe`, `sweep`, `scan` | Không phân biệt `T1046`, `T1595`, `T1595.001` và `T1595.002`. |
| `request`, `traffic`, `service` | Hầu như không mang nghĩa ATT&CK nếu đứng một mình. |
| `credential`, `authentication`, `repeated`, `shared` | Không đủ phân giải `T1078`, `T1110`, `T1110.001` và `T1110.003`. |
| `fake`, `deceptive`, `unexpected`, `suspicious` | Là tính từ mức độ nghi ngờ, không mô tả hành vi. |
| `insertion` | Cần loại nội dung cụ thể để không nhầm content injection với SQL/command injection. |
| Vendor/CVE/SID (`D-Link`, `Comtrend`, `CVE-*`, `1002xxx`) | Tạo leakage theo bộ test, không tổng quát cho rule mới. |

## 6. Thứ tự triển khai đề xuất

1. Thêm positive/negative phrase đặc hiệu cho `T1110.*`, `T1595.*`,
   `T1498`/`T1499`, `T1505.003`, `T1659`, `T1078` và `T1095` trước.
2. Thay `periodic` bằng `periodic web`, bỏ `session`, `fake` và `deceptive`
   dạng token đơn.
3. Cho candidate thiếu event signal vào alternative pool, nhưng chỉ cho làm
   primary khi có rule-name phrase mạnh và không có contradiction.
4. Thêm resolver ưu tiên child khi phrase child match; parent chỉ fallback.
5. Audit riêng nhãn `T1210` và hai A1 `T1046`; không dùng keyword để ép các
   nhãn còn tranh luận.
6. Sau khi sửa evidence, chạy lại 90 scenario và đo đồng thời exact top-1,
   top-3 recall, MISSING và wrong-primary. Không đánh giá chỉ bằng việc giảm
   MISSING.

## 7. Kết luận ngắn

Bỏ event-gate theo đúng đề xuất làm candidate recall tốt hơn đáng kể nhưng
không làm primary chính xác hơn. Phần có giá trị nhất của thay đổi là cho
expected technique quay lại top 3; phần rủi ro là những candidate có reranker
cao nhưng semantics sai có thể chiếm slot hoặc trở thành primary. Vì vậy nên
kết hợp soft gate với phrase rule-name đặc hiệu và negative evidence, thay vì
xóa lớp kiểm soát mà không bổ sung điều kiện thay thế.
