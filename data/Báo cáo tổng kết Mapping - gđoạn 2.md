# BÁO CÁO TỔNG KẾT HỆ THỐNG MAPPING MITRE ATT&CK – GIAI ĐOẠN 2

## 1. Mục tiêu và phạm vi

Hệ thống Mapping MITRE ATT&CK giai đoạn 2 có nhiệm vụ nhận **một alert an ninh mạng đã được chuẩn hóa**, đối chiếu alert đó với cơ sở tri thức ATT&CK cục bộ và trả về một quyết định mapping có thể kiểm tra, giải thích và truy vết.

Phạm vi của hệ thống trong báo cáo này bắt đầu tại đối tượng alert chuẩn hóa và kết thúc tại kết quả JSON của Mapping API. Các bước nhận log thô từ Wazuh/Suricata, orchestration bằng n8n, gọi Gemini và gửi thông báo cho analyst nằm ngoài lõi quyết định mapping. Gemini không tham gia chọn ATT&CK ID; kết quả technique được quyết định hoàn toàn bởi pipeline xác định trong Mapper.

Ba trạng thái đầu ra chính là:

- `mapped`: có một ứng viên hợp lệ, điểm đạt ngưỡng và cách biệt đủ rõ với ứng viên thứ hai;
- `uncertain`: có một ứng viên hợp lệ đạt ngưỡng nhưng cách biệt với ứng viên thứ hai còn nhỏ;
- `insufficient_evidence`: không có ứng viên hợp lệ đạt ngưỡng; hệ thống chủ động không gán ATT&CK ID.

Thiết kế tổng quát:

```text
Normalized alert
      │
      ▼
Tạo retrieval_text
      │
      ├── BM25 sparse retrieval ── Top 30 ──┐
      │                                     ├── Chuẩn hóa + fusion ── Top 20
      └── ATTACK-BERT dense retrieval ─ Top 30 ┘
                                                  │
                                                  ▼
                                     Cross-encoder reranking ─ Top 5
                                                  │
                                                  ▼
                           Required / positive / negative / exclusion evidence
                                                  │
                                                  ▼
                              Parent fallback + confusion guard + scoring
                                                  │
                                                  ▼
                         mapped / uncertain / insufficient_evidence
```

## 2. Kiến trúc logic và các thành phần

Lõi mapping gồm các thành phần sau:

| Thành phần | Vai trò |
|---|---|
| Mapping API | Cung cấp `POST /map` và `POST /webhook/map`, điều phối toàn bộ pipeline. |
| Alert renderer | Bảo đảm alert có `derived.retrieval_text`, là truy vấn chung cho các tầng retrieval. |
| ATTACK-BERT embedding API | Sinh vector dense biểu diễn ngữ nghĩa cho alert và tài liệu technique. |
| Qdrant | Lưu và truy vấn đồng thời named vector `dense` và `sparse` trong collection `attack_techniques_v1`. |
| BM25 index | Biểu diễn từ khóa, tên kỹ thuật, alias, công cụ và hành vi dưới dạng sparse vector. |
| Cross-encoder reranker | Chấm trực tiếp từng cặp alert–tài liệu để sắp xếp lại danh sách ứng viên. |
| Evidence rule engine | Kiểm tra bằng chứng cấu trúc trong alert, điều kiện bắt buộc và điều kiện loại trừ. |
| Decision layer | Tính điểm cuối, xử lý quan hệ cha–con, kỹ thuật dễ nhầm và quyết định trạng thái mapping. |

`indexer` chỉ là job chuẩn bị dữ liệu: nó tạo embedding và upsert các point vào Qdrant, sau đó thoát. Khi phục vụ truy vấn, hệ thống chỉ cần Qdrant, embedding API, reranker API và mapper API.

## 3. Dữ liệu đầu vào

### 3.1. Hợp đồng alert chuẩn hóa

Theo schema phiên bản `1.0`, alert tối thiểu cần có:

```json
{
  "schema_version": "1.0",
  "producer": {
    "rule_name": "..."
  },
  "event": {},
  "derived": {
    "retrieval_text": "...",
    "renderer_version": "..."
  }
}
```

Schema cho phép các nhóm trường mở rộng như `data_source`, `source`, `target`, `severity`, `network`, `http`, `dns`, `tls`, `file`, `user` và `derived`. Các trường này không bắt buộc đồng loạt, nhưng càng đầy đủ thì rule engine càng có nhiều evidence để phân biệt các technique gần nhau.

Nếu alert đã có `producer` và `event`, Mapper giữ nguyên dữ liệu, bổ sung `schema_version`, `derived.retrieval_text` hoặc `renderer_version` nếu thiếu. Một alert không tạo được `retrieval_text` có nội dung sẽ bị từ chối với lỗi HTTP `422`.

### 3.2. Cách tạo `retrieval_text`

`retrieval_text` được dựng bằng các trường có giá trị, theo nhãn ổn định:

- tên rule IDS;
- loại, hành động, kết quả và disposition của sự kiện;
- data source và loại target;
- transport/application protocol;
- source port, destination port và hướng mạng;
- HTTP method, path, query, status;
- DNS query;
- attack pattern đã suy diễn.

Các dấu gạch dưới trong giá trị được đổi thành khoảng trắng. IP nguồn/đích không được đưa vào retrieval text mặc định, nhờ đó tránh để các giá trị biến động và ít ý nghĩa ngữ nghĩa chi phối truy hồi. IP vẫn có thể được giữ trong alert chuẩn hóa để phục vụ điều tra hoặc evidence rule nếu cần.

## 4. Chuẩn bị cơ sở tri thức ATT&CK

### 4.1. Snapshot dữ liệu

Nguồn `attack_final.json` được hợp nhất với `configs/technique_overrides.json` để tạo snapshot `attack_final.mapping.json`. Cách làm này giữ nguyên dữ liệu nguồn và ghi lại phần bổ sung dành riêng cho thực nghiệm.

Validator kiểm tra:

- định dạng technique ID `Txxxx` hoặc `Txxxx.xxx`;
- trường metadata, phiên bản và nguồn ATT&CK;
- ID trùng lặp và quan hệ cha–con;
- rule ID trùng;
- field và operator được hỗ trợ;
- miền giá trị weight từ `-1` đến `1`;
- negative evidence không được có weight dương;
- tham chiếu tới sub-technique hoặc confusable technique ngoài tập hỗ trợ.

Snapshot hiện tại có:

| Tham số | Giá trị |
|---|---:|
| ATT&CK version | `19.1` |
| Số technique/sub-technique | 21 |
| Số procedure example | 488 |
| Số sub-technique trong tập | 9 |
| Required evidence rule | 20 |
| Positive evidence rule | 109 |
| Negative evidence rule | 47 |
| Exclusion rule | 21 |

Tập 21 technique hiện tại là một **supported subset**, không phải toàn bộ MITRE ATT&CK Enterprise. Vì vậy hệ thống chỉ có thể trả về technique nằm trong tập đã được lập chỉ mục.

### 4.2. Tài liệu dense và sparse

Mỗi technique tương ứng với một document retrieval.

`dense_text` ưu tiên:

1. technique ID và tên;
2. behavioral indicators;
3. retrieval text hoặc mô tả ATT&CK khi thiếu behavioral indicators;
4. điều kiện phân biệt với technique dễ nhầm;
5. tối đa tám procedure đại diện.

`sparse_text` gồm technique ID, tên, alias, retrieval keywords, behavioral indicators, associated tools và tên các procedure đại diện. Nếu các trường tối ưu quá ít, hệ thống bổ sung retrieval text hoặc description.

Ngoài document theo technique, hệ thống còn xuất riêng 488 procedure document để bảo toàn dữ liệu phục vụ mở rộng về sau; pipeline hiện tại truy hồi trên 21 technique document.

### 4.3. Lập chỉ mục Qdrant

Mỗi point trong Qdrant dùng UUID xác định sinh từ technique ID và chứa:

- named vector `dense`: embedding ATTACK-BERT;
- named vector `sparse`: trọng số BM25;
- payload: ATT&CK ID, tên, tactic, platform, quan hệ cha–con, evidence rule, confusion metadata, phiên bản index và SHA-256 của snapshot.

Vector dense hiện có 768 chiều, dùng khoảng cách cosine. Embedding được tạo bởi `basel/ATTACK-BERT`, revision `81e30f983a822c606825507b63ae318a6830a8a2`; request bật `normalize=true` và `truncate=true`.

Manifest lưu `index_version=1.0.0`, phiên bản model, số document, thời điểm build và SHA-256 của cả dữ liệu nguồn lẫn snapshot. Nhờ đó một kết quả mapping có thể truy ngược chính xác phiên bản cơ sở tri thức đã sử dụng.

## 5. Thuật toán mapping

### 5.1. Sparse retrieval bằng BM25

Tokenizer lấy token chữ–số, chuyển về chữ thường và giữ được một số cấu trúc kỹ thuật chứa `.`, `_`, `/` hoặc `-`. Chỉ mục hiện có 21 document, 915 token và độ dài document trung bình khoảng `126.048` token.

BM25 sử dụng:

- `k1 = 1.5`: điều khiển mức bão hòa tần suất từ;
- `b = 0.75`: điều chỉnh ảnh hưởng độ dài document;
- IDF: `ln(1 + (N - df + 0.5) / (df + 0.5))`.

Trọng số của term `t` trong document `d`:

```text
BM25(t,d) = IDF(t) × f(t,d) × (k1 + 1)
            -------------------------------------------
            f(t,d) + k1 × (1 - b + b × |d| / avgdl)
```

Query sparse sử dụng mỗi token đã biết một lần với trọng số `1.0`. Qdrant trả tối đa 30 ứng viên sparse.

### 5.2. Dense retrieval bằng ATTACK-BERT

Cùng `retrieval_text` được biến đổi thành vector bằng ATTACK-BERT. Qdrant so sánh vector alert với vector `dense_text` của technique bằng cosine similarity và trả tối đa 30 ứng viên dense.

Dense retrieval giúp nhận diện tương đồng ngữ nghĩa khi alert và tài liệu không dùng đúng cùng một từ; BM25 giữ độ nhạy với ID, tên công cụ, giao thức và keyword cụ thể. Việc chạy song song hai nhánh giảm phụ thuộc vào một loại tín hiệu duy nhất.

### 5.3. Chuẩn hóa và fusion

Điểm dense và sparse được chuẩn hóa min–max độc lập trong tập kết quả:

```text
normalized(x) = (x - min) / (max - min)
```

Nếu mọi điểm trong một nhánh bằng nhau, các điểm của nhánh đó được gán `1.0`.

Điểm fusion:

```text
fusion_score = 0.6 × dense_score + 0.4 × bm25_score
```

Hệ thống hợp nhất ID xuất hiện ở một trong hai nhánh, sắp giảm dần theo `fusion_score` và giữ Top 20. `matched_terms` lưu tối đa 12 token chung giữa query và sparse document để phục vụ audit.

### 5.4. Cross-encoder reranking

Top 20 được đưa qua `cross-encoder/ms-marco-MiniLM-L-6-v2`, revision cố định `c5ee24cb16019beea0893ab7796b1df96625c6b8`. Model đánh giá trực tiếp từng cặp:

```text
(retrieval_text của alert, dense_text của technique)
```

Độ dài đầu vào tối đa của cross-encoder là 512 token. Logit của model được giới hạn trong `[-60, 60]`, chuyển qua sigmoid, sau đó Mapper tiếp tục chuẩn hóa min–max các điểm trong batch. Kết quả được sắp xếp lại và giữ Top 5 để đánh giá evidence.

Trường `reranker_raw_score` trong trace hiện lưu điểm do reranker API trả về khi `raw_scores=false`, tức điểm sau sigmoid; `reranker_score` là giá trị đã chuẩn hóa min–max tại Mapper.

### 5.5. Rule engine và evidence score

Rule engine hỗ trợ sáu operator:

| Operator | Ý nghĩa |
|---|---|
| `equals` | So sánh bằng, không phân biệt hoa/thường với chuỗi. |
| `contains_any` | Ít nhất một giá trị mong đợi là chuỗi con của giá trị thực tế. |
| `exists` | Kiểm tra field có hoặc không có. |
| `in` | Giá trị thực tế thuộc tập cho trước. |
| `greater_than_or_equal` | So sánh số lớn hơn hoặc bằng. |
| `matches_regex` | So khớp biểu thức chính quy, không phân biệt hoa/thường. |

Bốn nhóm evidence có chức năng khác nhau:

- `required_evidence`: tất cả rule bắt buộc phải khớp; thiếu một rule làm candidate không hợp lệ;
- `positive_evidence`: cộng điểm khi có bằng chứng ủng hộ;
- `negative_evidence`: trừ điểm khi có bằng chứng mâu thuẫn;
- `exclusion_indicators`: nếu bất kỳ rule nào khớp thì candidate bị loại, không phụ thuộc điểm retrieval.

Điểm evidence được tính từ positive và negative evidence đã khớp:

```text
raw_evidence_score = Σ matched_positive.weight + Σ matched_negative.weight

positive_capacity = Σ max(0, weight của toàn bộ positive rule)

evidence_score = clamp(raw_evidence_score / max(positive_capacity, 0.001), 0, 1)
```

Weight của required evidence được ghi vào `supporting_evidence` để giải thích nhưng không được cộng trực tiếp vào `evidence_score`. Required evidence đóng vai trò cổng hợp lệ. Exclusion cũng là cổng loại trừ, không phải một thành phần số học của evidence score.

Candidate hợp lệ khi:

```text
valid = required_passed AND NOT excluded
```

### 5.6. Điểm ứng viên cuối

Với mỗi candidate trong Top 5:

```text
candidate_score = clamp(
    0.3 × fusion_score
  + 0.5 × reranker_score
  + 0.2 × evidence_score,
  0, 1
)
```

Reranker có trọng số lớn nhất (`0.5`), retrieval hybrid giữ `0.3`, và structured evidence đóng góp `0.2`. Tuy nhiên evidence vẫn có quyền phủ quyết thông qua required/exclusion, nên vai trò của nó lớn hơn trọng số số học đơn thuần.

### 5.7. Parent fallback

Nếu một sub-technique không hợp lệ vì thiếu required evidence, nhưng có parent hợp lệ trong cơ sở dữ liệu và parent chưa xuất hiện trong danh sách, hệ thống tạo một ứng viên fallback cho parent:

- kế thừa dense và BM25 score;
- giảm `fusion_score` và `reranker_score` còn 95%;
- đánh giá lại toàn bộ evidence theo rule của parent;
- ghi sub-technique nguồn vào `fallback_from`.

Cơ chế này tránh ép mapping quá cụ thể khi alert chỉ đủ bằng chứng cho technique cha.

### 5.8. Confusion guard

Các cặp dễ nhầm được khai báo trong `confusable_techniques`. Ví dụ, T1595 Active Scanning mô tả reconnaissance trước xâm nhập, trong khi T1046 Network Service Discovery yêu cầu dấu hiệu quét nội bộ/lateral hoặc sau xâm nhập.

Với hai candidate đều hợp lệ, nếu evidence score của technique đối chiếu cao hơn candidate hiện tại ít nhất `0.2`, candidate hiện tại bị phạt:

- `0.2` nếu quan hệ là `hard_negative`;
- `0.1` nếu là quan hệ nhầm lẫn thông thường.

Penalty được ghi thành contradictory evidence với rule ID `CONFUSION-GUARD`.

### 5.9. Abstention và ba trạng thái quyết định

Sau khi áp dụng evidence, parent fallback và confusion guard, chỉ các candidate `valid=true` được xét làm kết quả chính.

Các tham số quyết định:

| Tham số | Giá trị |
|---|---:|
| `decision_threshold` | `0.55` |
| `uncertainty_margin` | `0.07` |

Gọi `S1` là điểm candidate hợp lệ cao nhất và `S2` là điểm candidate hợp lệ thứ hai; nếu không có ứng viên thứ hai thì `S2=0`.

```text
Nếu không có candidate hợp lệ                 → insufficient_evidence
Nếu S1 < 0.55                                 → insufficient_evidence
Nếu S1 ≥ 0.55 và (S1 - S2) < 0.07             → uncertain
Nếu S1 ≥ 0.55 và (S1 - S2) ≥ 0.07             → mapped
```

Ở trạng thái `mapped` và `uncertain`, `primary_mapping` chứa technique thắng cuộc. Ở trạng thái `insufficient_evidence`, `primary_mapping=null` dù hệ thống vẫn trả candidate trace và alternative candidates để analyst biết những khả năng đã được xem xét.

Tên `insufficient_evidence` bao quát cả hai tình huống: thiếu điều kiện evidence bắt buộc, hoặc có candidate hợp lệ nhưng điểm tổng hợp chưa đạt `0.55`.

## 6. Hợp đồng dữ liệu đầu ra

Kết quả Mapping API gồm:

| Trường | Nội dung |
|---|---|
| `mapping_status` | `mapped`, `uncertain` hoặc `insufficient_evidence`. |
| `primary_mapping` | `technique_id`, `name`, `confidence`; null nếu abstain. |
| `supporting_evidence` | Rule và giá trị thực tế ủng hộ kết quả chính. |
| `contradictory_evidence` | Negative evidence, exclusion hoặc confusion penalty. |
| `alternative_candidates` | Các ứng viên còn lại, điểm và lý do không được chọn. |
| `candidate_trace` | Toàn bộ điểm BM25, dense, fusion, rerank, evidence, rank và fallback. |
| `normalized_alert` | Alert được sử dụng thực tế để mapping. |
| `pipeline` | Phiên bản model/index/rule engine, SHA-256, degraded mode và latency. |

Trường `confidence` chính là `candidate_score`. Đây là điểm tổng hợp dùng để xếp hạng và ra quyết định trong pipeline hiện tại, **không phải xác suất thống kê đã được calibration**. Vì dense, sparse và reranker đều có bước min–max theo tập candidate của từng truy vấn, cùng một điểm số ở hai alert khác nhau không nhất thiết thể hiện cùng một xác suất đúng tuyệt đối.

## 7. Ví dụ kết quả thực nghiệm

Với alert `ET SCAN Suspicious inbound traffic`, hệ thống trả:

```json
{
  "mapping_status": "mapped",
  "primary_mapping": {
    "technique_id": "T1595",
    "name": "Active Scanning",
    "confidence": 0.980645
  }
}
```

Chi tiết điểm của T1595:

| Thành phần | Điểm |
|---|---:|
| BM25 | 1.000000 |
| Dense | 1.000000 |
| Fusion | 1.000000 |
| Reranker | 1.000000 |
| Evidence | 0.903226 |
| Candidate score | 0.980645 |

Kiểm tra công thức:

```text
0.3 × 1.0 + 0.5 × 1.0 + 0.2 × 0.903226 = 0.9806452
```

T1595 vượt ngưỡng `0.55` và cách xa ứng viên hợp lệ tiếp theo. T1595.002, T1557, T1557.003 và T1046 đều được trả như alternative nhưng không vượt qua required evidence tương ứng. Pipeline chạy đủ dịch vụ, không có degraded mode, và latency được ghi nhận khoảng `1653.273 ms` trong lần thử đã lưu.

Các test hành vi khác xác nhận:

- alert quét nội bộ/lateral có thể map sang T1046 Network Service Discovery;
- alert DNS lành tính không đủ evidence và trả `insufficient_evidence`;
- các operator của rule engine đều có unit test;
- bộ kiểm thử hiện ghi nhận 8 test đạt, 0 test thất bại.

## 8. Cấu hình vận hành và chế độ suy giảm

Cấu hình mặc định trong `configs/settings.json` cho phép local fallback. Tuy nhiên cấu hình Docker đang vận hành đặt:

```text
LOCAL_FALLBACK=false
```

Do đó hệ thống triển khai thực tế đang **fail closed** ở tầng dịch vụ: nếu embedding, Qdrant hoặc reranker không khả dụng, Mapping API trả lỗi `503` thay vì âm thầm thay thuật toán. Đây là lựa chọn phù hợp cho việc đánh giá thực nghiệm có kiểm soát.

Khi bật local fallback, cơ chế thay thế là:

- sparse: tích vô hướng giữa sparse query và BM25 document vector cục bộ;
- dense thay thế: cosine trên vector tần suất token, không phải ATTACK-BERT;
- reranker thay thế: `0.55 × fusion_score + 0.45 × lexical_overlap`.

Mọi fallback được ghi trong `pipeline.degraded_modes`, đồng thời `reranker_version` đổi thành `lexical-fallback-1.0.0`. Kết quả degraded hữu ích cho test và khả năng phục hồi, nhưng không nên so sánh trực tiếp với kết quả full-model khi đánh giá chất lượng.

API có thể được bảo vệ bằng header `X-API-Key` khi biến `MAPPER_API_KEY` được cấu hình. Timeout mặc định cho mỗi request nội bộ là 60 giây. Collection mặc định là `attack_techniques_v1`.

## 9. Khả năng giải thích, tái lập và kiểm toán

Hệ thống hỗ trợ audit ở ba cấp:

1. **Dữ liệu:** SHA-256 của `attack_final.json` và snapshot mapping, ATT&CK version, số technique/procedure.
2. **Mô hình:** tên và revision cố định của ATTACK-BERT và cross-encoder.
3. **Quyết định:** candidate trace, matched terms, thứ hạng trước/sau rerank, evidence thực tế, penalty, rejection reason và latency.

Thiết kế không chỉ trả một ATT&CK ID mà còn trả lời được các câu hỏi: ứng viên nào từng được xét, vì sao ứng viên thắng, rule nào thiếu, bằng chứng nào mâu thuẫn, có fallback hay không, và pipeline có chạy degraded hay không.

## 10. Giới hạn và lưu ý khi diễn giải

- Tập index hiện chỉ có 21 technique/sub-technique; technique ngoài tập này không thể được chọn.
- Mapper xử lý từng alert độc lập, chưa thực hiện correlation nhiều sự kiện theo thời gian, host hoặc campaign.
- Cross-encoder MS MARCO là baseline tiếng Anh, chưa phải model được fine-tune/calibrate trên tập alert SOC của dự án.
- Điểm `confidence` mang tính tương đối trong mỗi truy vấn, không phải xác suất đúng tuyệt đối.
- Required evidence và exclusion phụ thuộc vào chất lượng trường chuẩn hóa. Field thiếu có thể làm hệ thống abstain dù retrieval ngữ nghĩa tốt.
- Negative evidence chỉ làm giảm evidence score; chỉ exclusion mới loại trực tiếp candidate.
- Min–max normalization có thể nhạy với phân bố candidate của từng alert, đặc biệt khi tập technique còn nhỏ.
- Các ngưỡng `0.55` và `0.07` hiện là cấu hình thực nghiệm; cần validation set được gán nhãn bởi analyst trước khi tối ưu hoặc đưa vào tự động hóa có tác động.
- Kết quả `mapped` nên được dùng để enrichment và ưu tiên điều tra, không mặc nhiên chứng minh hành vi tấn công đã thành công.

## 11. Tệp cấu hình và mã nguồn tham chiếu

- `mitre-mapping/configs/settings.json`: trọng số, ngưỡng, URL và timeout.
- `mitre-mapping/src/mitre_mapper/pipeline.py`: công thức điểm và logic quyết định.
- `mitre-mapping/src/mitre_mapper/clients.py`: embedding, Qdrant, hybrid retrieval và reranking.
- `mitre-mapping/src/mitre_mapper/evidence.py`: operator và evidence rule engine.
- `mitre-mapping/src/mitre_mapper/database.py`: validator, document builder và BM25.
- `mitre-mapping/schemas/normalized_alert.schema.json`: hợp đồng đầu vào.
- `mitre-mapping/schemas/mapping_result.schema.json`: hợp đồng đầu ra.
- `mitre-mapping/artifacts/attack/index_manifest.json`: dấu vết snapshot/index.
- `mitre-mapping/reports/test-alert-scan-CH.result.json`: kết quả thử nghiệm chi tiết.

## 12. Tóm tắt (Summary)

Hệ thống Mapping MITRE ATT&CK giai đoạn 2 nhận một alert đã chuẩn hóa và tạo `retrieval_text` ổn định. Alert được truy hồi song song bằng BM25 và ATTACK-BERT, với trọng số fusion lần lượt là `0.4` và `0.6`. Top 20 ứng viên được cross-encoder rerank xuống Top 5. Mỗi ứng viên sau đó được kiểm tra bằng required, positive, negative và exclusion evidence; hệ thống còn xử lý fallback từ sub-technique về parent và phạt các technique dễ nhầm khi evidence của đối thủ mạnh hơn.

Điểm cuối được tính theo công thức `0.3 × retrieval + 0.5 × reranker + 0.2 × evidence`. Candidate phải vượt qua evidence guard và đạt ít nhất `0.55`. Nếu cách biệt Top 1–Top 2 từ `0.07` trở lên, kết quả là `mapped`; nếu cách biệt nhỏ hơn, kết quả là `uncertain`; nếu không có candidate hợp lệ đạt ngưỡng, hệ thống trả `insufficient_evidence` và không ép gán ATT&CK ID.

Snapshot hiện tại bao phủ 21 technique/sub-technique ATT&CK 19.1 và 488 procedure, sử dụng vector ATTACK-BERT 768 chiều, BM25 và cross-encoder MiniLM. Toàn bộ kết quả kèm evidence, alternative, candidate trace, phiên bản index/model, hash dữ liệu và degraded mode, qua đó đáp ứng mục tiêu giải thích được và tái lập được. Hạn chế chính là phạm vi technique còn nhỏ, xử lý theo từng alert độc lập và confidence chưa được hiệu chuẩn thành xác suất; vì vậy kết quả nên hỗ trợ analyst thay vì thay thế bước xác minh của analyst.
