Cách chấm điểm hiện tại có thể tóm tắt như sau:

```text
BM25 Top 30 ─┐
              ├─ Fusion Top 20 ─ Reranker Top 5 ─ Evidence/Gate
Dense Top 30 ─┘                                      │
                                                    ▼
                         Final score → Confusion/Parent → Decision
```

Các trọng số được cấu hình tại [settings.json](<C:\Users\DELL\Documents\Zalo Received Files\NCKH\NCKH_Code\code\data\mitre-mapping\configs\settings.json:11>).

## 1. BM25 score

BM25 so sánh từ vựng trong `alert_retrieval_text` với `sparse_text` của từng technique.

Những nội dung thường có trong `sparse_text`:

- Technique ID và tên.
- Retrieval keywords.
- Behavioral indicators.
- Tool và tên procedure.
- Protocol, hành vi, tên kỹ thuật liên quan.

Công thức BM25 của mỗi term:

```text
IDF(term) = ln(1 + (N - df + 0.5) / (df + 0.5))

BM25(term, document) =
    IDF × tf × (k1 + 1)
    ─────────────────────────────
    tf + k1 × (1 - b + b × dl/avgdl)
```

Hiện tại:

```text
k1 = 1.5
b  = 0.75
```

Qdrant tính tổng trọng số các term chung giữa alert và technique.

Sau khi nhận Top 30, raw BM25 được chuẩn hóa min-max:

```text
bm25_score =
    (raw_score - min_raw)
    ─────────────────────
    (max_raw - min_raw)
```

Do đó:

- Technique BM25 cao nhất trong truy vấn nhận `1.0`.
- Thấp nhất nhận `0.0`.
- Đây là điểm tương đối trong alert hiện tại, không phải xác suất.
- `matched_terms` chỉ phục vụ giải thích, không được cộng thêm lần nữa.

Phần này nằm tại [clients.py](<C:\Users\DELL\Documents\Zalo Received Files\NCKH\NCKH_Code\code\data\mitre-mapping\src\mitre_mapper\clients.py:155>).

## 2. Dense score

Alert retrieval text được ATTACK-BERT chuyển thành vector 768 chiều. Vector này được so sánh cosine với dense vector của từng technique trong Qdrant.

Dense retrieval cũng lấy Top 30 và chuẩn hóa min-max:

```text
dense_score =
    (raw_cosine - min_cosine)
    ─────────────────────────
    (max_cosine - min_cosine)
```

Dense score giúp tìm các technique gần nghĩa dù không trùng chính xác từ khóa.

Ví dụ alert có “Suspicious inbound traffic” vẫn có thể gần với:

- Active Scanning.
- Network Service Discovery.
- Adversary-in-the-Middle.

Vì vậy dense score chỉ dùng để tìm candidate, chưa đủ để kết luận mapping.

## 3. Fusion score

BM25 và dense được kết hợp:

```text
fusion_score =
    0.4 × bm25_score
  + 0.6 × dense_score
```

Sau đó hệ thống sắp xếp và giữ Top 20.

Ví dụ T1595.002:

```text
bm25_score = 0.422664
dense_score = 0.398424

fusion_score =
    0.4 × 0.422664
  + 0.6 × 0.398424
  = 0.408120
```

Nếu một technique chỉ xuất hiện trong một nhánh retrieval, nhánh còn lại được coi là `0`.

## 4. Reranker score

Cross-encoder nhận trực tiếp từng cặp:

```text
[ALERT]
ET SCAN Suspicious inbound traffic...
network scan...
one source IP scanning one server...

[TECHNIQUE]
T1595 Active Scanning...
inbound reconnaissance...
pre-compromise probing...
```

Khác với dense embedding, cross-encoder đọc đồng thời alert và technique rồi đánh giá mức phù hợp của cặp.

Quy trình:

```text
Top 20 fusion
→ cross-encoder
→ chuẩn hóa min-max reranker score
→ Top 5
```

Điểm reranker chuẩn hóa:

```text
reranker_score =
    (model_score - min_model_score)
    ───────────────────────────────
    (max_model_score - min_model_score)
```

Technique cao nhất trong Top 20 nhận `1.0`.

Lưu ý: field `reranker_raw_score` hiện thực tế đang lưu score sau sigmoid do thứ tự đọc response, không phải logit thô của model. Vì vậy không nên diễn giải nó như xác suất hoặc raw logit. `reranker_score` mới là giá trị được dùng trong công thức cuối.

## 5. Required evidence — điều kiện bắt buộc

Required evidence là gate, không trực tiếp cộng vào `evidence_score`.

Ví dụ T1595 yêu cầu `producer.rule_name` chứa một trong các dấu hiệu:

```text
active scanning
active reconnaissance
external scan
pre-compromise scan
suspicious inbound traffic
```

Alert mẫu có:

```text
ET SCAN Suspicious inbound traffic
```

Nên:

```text
required_passed = true
```

Nếu technique có nhiều required rule thì hiện tại tất cả rule đều phải đạt:

```text
required_passed = all(required_rules)
```

Nếu không đạt, technique vẫn có `candidate_score` để analyst xem, nhưng bị đánh dấu `valid=false` và không thể trở thành primary mapping.

Nếu một technique không định nghĩa required evidence, gate mặc định là đạt.

## 6. Exclusion indicators — điều kiện loại

Nếu bất kỳ exclusion rule nào match:

```text
excluded = true
valid = false
```

Exclusion không chỉ trừ điểm mà loại hẳn technique.

Ví dụ technique scanning có thể bị loại nếu:

```text
event.type = authentication
```

Thứ tự logic:

```text
valid =
    required_passed
    AND không có exclusion match
```

## 7. Positive và negative evidence

Với mỗi technique:

```text
raw_evidence_score =
    tổng positive weight đã match
  + tổng negative weight đã match
```

Negative weight đã là số âm, ví dụ `-0.4`.

Sau đó chuẩn hóa theo tổng trọng số positive tối đa của technique:

```text
positive_capacity =
    tổng tất cả positive weight của technique

evidence_score =
    clamp(raw_evidence_score / positive_capacity, 0, 1)
```

Required weight không nằm trong phép cộng này; nó chỉ là gate.

### Ví dụ T1595

Các positive rule của T1595 có tổng capacity:

```text
0.10  data_source.category = network_traffic
0.60  event.action = scan/probe
0.60  event.type = network_scan
0.15  network.direction = inbound
0.10  target.type = host/service/application/cloud_resource
────
1.55  positive_capacity
```

Alert mẫu match:

```text
0.10  network_traffic
0.60  action = scan
0.60  type = network_scan
0.10  target = service
────
1.40  raw_evidence_score
```

Không match `network.direction = inbound` vì field đó không có trong alert.

Vì vậy:

```text
evidence_score = 1.40 / 1.55
               = 0.903226
```

Code evidence nằm tại [evidence.py](<C:\Users\DELL\Documents\Zalo Received Files\NCKH\NCKH_Code\code\data\mitre-mapping\src\mitre_mapper\evidence.py:72>).

## 8. Candidate score cuối

Với candidate Top 5:

```text
candidate_score =
    0.3 × fusion_score
  + 0.5 × reranker_score
  + 0.2 × evidence_score
```

Kết quả bị giới hạn trong `[0, 1]`.

Reranker có trọng số cao nhất vì nó đánh giá trực tiếp cặp alert–technique.

### Ví dụ T1595

```text
fusion_score   = 1.000000
reranker_score = 1.000000
evidence_score = 0.903226

candidate_score =
    0.3 × 1.000000
  + 0.5 × 1.000000
  + 0.2 × 0.903226

= 0.980645
```

Đây chính là confidence hiện tại trong kết quả.

Công thức nằm tại [pipeline.py](<C:\Users\DELL\Documents\Zalo Received Files\NCKH\NCKH_Code\code\data\mitre-mapping\src\mitre_mapper\pipeline.py:92>).

## 9. Vì sao technique điểm cao vẫn có thể bị loại?

Ví dụ T1595.002:

```text
BM25          = 0.422664
Dense         = 0.398424
Fusion        = 0.408120
Reranker      = 0.161964
Evidence      = 0.545455
Final score   = 0.312509
Required      = false
```

Công thức:

```text
0.3 × 0.408120
+ 0.5 × 0.161964
+ 0.2 × 0.545455
= 0.312509
```

Tuy nhiên, alert không có bằng chứng về:

- Vulnerability scan.
- CVE probing.
- Banner grabbing.
- Software fingerprinting.
- Nessus/OpenVAS/Nuclei.

Do đó T1595.002 bị loại vì `required_passed=false`.

Tương tự, T1557 có dense score rất cao `0.965235`, nhưng:

```text
reranker_score = 0.022417
required_passed = false
```

Nó bị loại vì alert không có interception, poisoning hoặc relay. Đây là vai trò quan trọng của reranker và evidence guard: ngăn dense similarity quyết định một mình.

## 10. Parent fallback

Nếu một sub-technique không đạt evidence bắt buộc:

1. Lấy parent technique.
2. Giảm fusion và reranker 5%:

```text
parent_fusion   = child_fusion × 0.95
parent_reranker = child_reranker × 0.95
```

3. Chấm lại evidence theo rule riêng của parent.
4. Nếu parent đạt required evidence, parent có thể được giữ lại.

Ví dụ:

```text
T1595.001 Scanning IP Blocks
```

Nếu alert xác nhận active scanning nhưng không chứng minh quét nhiều IP/subnet, sub-technique bị loại và có thể fallback:

```text
T1595 Active Scanning
```

Nếu parent đã có sẵn trong Top 5 thì không tạo thêm candidate fallback.

## 11. Confusion guard

Nếu hai technique được đánh dấu confusable và cả hai đều valid, hệ thống so sánh `evidence_score`.

Nếu technique đối thủ mạnh hơn ít nhất `0.2`:

```text
other.evidence_score >= current.evidence_score + 0.2
```

Technique hiện tại bị trừ:

```text
-0.2  nếu hard_negative = true
-0.1  nếu hard_negative = false
```

Ví dụ:

```text
T1595 Active Scanning
vs
T1046 Network Service Discovery
```

- Inbound/pre-compromise → ưu tiên T1595.
- Internal/lateral/post-compromise → ưu tiên T1046.

Penalty được áp dụng sau khi đã tính candidate score.

## 12. Quyết định trạng thái cuối

Chỉ những candidate:

```text
required_passed = true
excluded = false
```

mới được xét thắng.

Cấu hình hiện tại:

```text
decision_threshold = 0.55
uncertainty_margin = 0.07
```

Quyết định:

```text
Nếu không có valid candidate
→ insufficient_evidence

Nếu Top 1 < 0.55
→ insufficient_evidence

Nếu Top 1 >= 0.55
và Top 1 - Top 2 < 0.07
→ uncertain

Nếu Top 1 >= 0.55
và Top 1 - Top 2 >= 0.07
→ mapped
```

Nếu chỉ có một valid candidate, Top 2 được coi là `0`.

## Bảng tổng hợp alert mẫu

| Technique | BM25 | Dense | Fusion | Reranker | Evidence | Final | Gate | Kết quả |
|---|---:|---:|---:|---:|---:|---:|---|---|
| T1595 | 1.000 | 1.000 | 1.000 | 1.000 | 0.903 | 0.981 | Đạt | Map |
| T1595.002 | 0.423 | 0.398 | 0.408 | 0.162 | 0.545 | 0.313 | Thiếu required | Loại |
| T1557 | 0.259 | 0.965 | 0.683 | 0.022 | 0.333 | 0.283 | Thiếu required | Loại |
| T1557.003 | 0.230 | 0.657 | 0.486 | 0.047 | 0.400 | 0.249 | Thiếu required | Loại |
| T1046 | 0.563 | 0.679 | 0.633 | 0.026 | 0.200 | 0.243 | Thiếu required | Loại |

Chi tiết từng candidate có thể xem trong [báo cáo alert mẫu](<C:\Users\DELL\Documents\Zalo Received Files\NCKH\NCKH_Code\code\data\mitre-mapping\reports\test-alert-scan-CH.result.json:72>).

Điểm `confidence` hiện là candidate score tổng hợp, không phải xác suất đã calibration và không nên so sánh trực tiếp giữa hai alert khác nhau.