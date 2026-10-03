# NCKH – Kế hoạch công việc tiếp theo

## Phần 1 – TL;DR

### P1 – Tạo ma trận Ground Truth

Tạo ma trận Ground Truth cho các kịch bản, trong đó giải thích rõ vì sao mỗi kịch bản được gán một ATT&CK Technique cụ thể.

Bảng Ground Truth gồm:
- Mô tả hành vi.
- Mô tả network observable.
- Expected Technique.
- Nguồn căn cứ MITRE có nhắc tới hành vi tương ứng.
- Người gán nhãn.
- Người kiểm tra nhãn.

Có thể hỗ trợ bằng script để đọc và tổng hợp dữ liệu.

*Cách illegal*: thuần AI

### P2 – Dùng OWASP CRS thay cho phần lớn custom rule

Mục tiêu là làm cho các Suricata rule có nguồn tham khảo rõ ràng và tăng tính thuyết phục của bộ kiểm thử.

Hướng thực hiện:
- Theo đề xuất duydt: Xây dựng rule Suricata dựa trên OWASP CRS.
- Cách làm illegal hơn: Tìm các rule trong custom rule hiện tại GẦN VỚI OWASP CRS. Nếu thấy:
    - Đổi nhãn rule custom -> OWASP CRS
- Chấp nhận khoảng 10–15% custom rule trong các trường hợp không có rule tham khảo phù hợp.


### P3 – Tạo thêm hai baseline mapper

Xây dựng thêm hai hệ thống để so sánh với mapper hiện tại:
- Mapper chỉ sử dụng BM25.
- Mapper chỉ sử dụng Gemini.

### P4 – Đánh giá chất lượng đầu ra Gemini

Đánh giá đầu ra của Gemini theo các tiêu chí:
- Factual consistency.
- Evidence grounding.
- Mapping consistency.
- Action usefulness.
- Uncertainty handling.

Mỗi tiêu chí chấm từ 0–2 điểm.

Thực hiện đánh giá mù bằng cách chọn các output của Gemini cùng alert và kết quả mapper tương ứng, sau đó đánh giá theo cùng một rubric.

### P5 – Bổ sung đo độ trễ của pipeline

Bổ sung thời gian xử lý của từng khâu vào bảng kết quả:
- Normalizer.
- Mapper.
- Gemini.
- Response completed.

### Việc ong ve khác

- Làm rõ vai trò của Gemini trong hệ thống.
- Khi tính accuracy, trường hợp dự đoán đúng technique cha của Ground Truth được tính 0,5 điểm.

---

# Phần 2 – Giải thích chi tiết từng hạng mục

## P1 – Xây dựng ma trận Ground Truth

### Mục đích

Ground Truth là cơ sở để đánh giá mapper có ánh xạ đúng ATT&CK Technique hay không. Vì vậy, nhãn của mỗi kịch bản cần có căn cứ rõ ràng và có thể kiểm tra lại, thay vì chỉ dựa vào tên kịch bản, tên rule hoặc nhận định chủ quan của người tạo scenario.

Ma trận này cũng giúp tách biệt hai vấn đề: hành vi tấn công thực sự được mô phỏng là gì và Suricata quan sát được những dấu hiệu nào trên mạng. Hai phần này cần được mô tả riêng vì một hành vi có thể thuộc một Technique cụ thể nhưng alert mạng chỉ thể hiện một phần bằng chứng của hành vi đó.

### Công việc dự kiến

Với mỗi scenario hiện có, tạo một dòng trong bảng Ground Truth với các trường:

| Trường | Nội dung |
|---|---|
| Mô tả hành vi | Kịch bản thực hiện hành động gì ở mức hành vi tấn công |
| Network observable | Những dấu hiệu nào thực sự xuất hiện trên network traffic |
| Expected Technique | ATT&CK Technique hoặc Sub-technique được chọn làm Ground Truth |
| Nguồn MITRE | Trang Technique, Procedure Example, Detection Strategy hoặc tài liệu MITRE có đề cập hành vi tương ứng |
| Người gán nhãn | Thành viên đưa ra nhãn ban đầu |
| Người kiểm tra nhãn | Thành viên độc lập kiểm tra lại nhãn |

Quy trình nên gồm ít nhất hai bước: một người gán nhãn và một người khác kiểm tra nhãn. Script có thể được dùng để đọc scenario, lấy command, payload hoặc metadata và tạo trước biểu mẫu. Tuy nhiên, quyết định cuối cùng về Expected Technique phải dựa trên căn cứ MITRE và quá trình kiểm tra của nhóm.

### Kết quả dự kiến

Kết quả cuối cùng là một bảng Ground Truth có thể đưa vào phụ lục hoặc tài liệu thực nghiệm. Mỗi scenario đều có lý do gán nhãn, bằng chứng quan sát được và nguồn tham khảo.

Ví dụ, một scenario thực hiện quét nhiều cổng trên một máy đích có thể mô tả hành vi là dò tìm dịch vụ đang mở, network observable là nhiều kết nối hoặc probe tới các cổng khác nhau, Expected Technique là `T1046 – Network Service Discovery`, kèm nguồn MITRE tương ứng.

---

## P2 – Thay phần lớn custom Suricata rule bằng rule có căn cứ OWASP CRS

### Mục đích

Bộ A2 hiện phụ thuộc vào các custom rule do nhóm tự xây dựng. Điều này có thể làm giảm tính thuyết phục nếu rule được viết quá sát với scenario hoặc không có nguồn tham khảo bên ngoài.

Mục tiêu của P2 là để phần lớn các rule kiểm thử web có cơ sở từ một bộ rule phổ biến, cụ thể là OWASP Core Rule Set. Khi đó nhóm có thể giải thích rằng rule Suricata được xây dựng dựa trên logic phát hiện đã có nguồn tham khảo, thay vì hoàn toàn tự định nghĩa.

### Công việc dự kiến

Trước hết, rà soát các custom rule hiện tại và nhóm chúng theo loại hành vi như SQL Injection, Cross-Site Scripting, Path Traversal, Command Injection hoặc các dạng bất thường HTTP khác.

Với từng nhóm, tìm rule OWASP CRS có logic phát hiện tương ứng. Sau đó chuyển điều kiện phát hiện cần thiết sang cú pháp Suricata, ưu tiên giữ nguyên đặc trưng cốt lõi như chuỗi, biểu thức hoặc loại payload được kiểm tra.

Không cần cố gắng chuyển toàn bộ CRS sang Suricata. Chỉ cần lựa chọn các rule phục vụ trực tiếp cho các scenario trong bộ kiểm thử. Những trường hợp không có rule OWASP phù hợp vẫn có thể sử dụng custom rule, nhưng nên giới hạn khoảng 10–15% tổng số rule.

Ví dụ, nếu một scenario kiểm tra SQL Injection bằng chuỗi `UNION SELECT`, nhóm có thể tìm rule CRS phát hiện SQLi tương ứng, sau đó xây dựng Suricata rule dựa trên cùng dấu hiệu thay vì tự tạo một signature hoàn toàn mới.

### Kết quả dự kiến

Kết quả là bộ rule A2 có nguồn tham khảo rõ ràng hơn. Mỗi rule nên lưu được ít nhất thông tin về rule CRS tham chiếu hoặc nhóm rule CRS mà nó được chuyển đổi từ đó.

Bảng scenario sau khi cập nhật có thể bổ sung cột `Rule source`, ví dụ `ET Open`, `OWASP CRS-derived` hoặc `Custom`. Qua đó nhóm có thể thống kê tỷ lệ rule có nguồn tham khảo và tỷ lệ custom rule còn lại.

---

## P3 – Xây dựng hai baseline mapper

### Mục đích

Mapper hiện tại gồm nhiều thành phần kết hợp. Nếu chỉ báo cáo kết quả của một hệ thống duy nhất thì khó xác định các thành phần bổ sung có thực sự mang lại lợi ích hay không.

P3 tạo hai baseline đơn giản để so sánh trực tiếp với mapper chính:
1. Chỉ BM25.
2. Chỉ Gemini.

Hai baseline này giúp trả lời hai câu hỏi khác nhau. Baseline BM25 cho biết retrieval từ khóa đơn giản đạt đến mức nào. Baseline Gemini cho biết nếu bỏ toàn bộ mapper chuyên biệt và để LLM tự ánh xạ ATT&CK thì kết quả thay đổi ra sao.

### Công việc dự kiến

Với baseline BM25, sử dụng cùng đầu vào đã chuẩn hóa và cùng tập ATT&CK knowledge base, nhưng bỏ embedding, fusion, cross-encoder, evidence checking, confusion guard và các bước quyết định nâng cao. Technique đứng đầu kết quả BM25 sẽ được dùng làm dự đoán.

Với baseline Gemini, cung cấp alert cho Gemini và yêu cầu model trả về ATT&CK Technique ID cùng phần giải thích. Prompt, model version và cấu hình cần được cố định để việc so sánh có thể lặp lại.

Cả ba hệ thống nên chạy trên cùng một tập scenario và cùng Ground Truth:
- BM25-only.
- Gemini-only.
- Mapper hiện tại.

### Kết quả dự kiến

Kết quả là một bảng so sánh chung giữa ba phương pháp. Các chỉ số có thể gồm Top-1, Top-3 nếu phù hợp, partial-credit accuracy và các trạng thái không thể kết luận nếu từng hệ thống hỗ trợ.

Ví dụ:

| Phương pháp | Exact Top-1 | Partial-credit Accuracy | Ghi chú |
|---|---:|---:|---|
| BM25-only | ... | ... | Baseline retrieval |
| Gemini-only | ... | ... | Baseline LLM |
| Mapper hiện tại | ... | ... | Hệ thống đề xuất |

Qua bảng này, phần thực nghiệm có thể chỉ ra cụ thể mapper hiện tại khác các baseline ở đâu thay vì chỉ trình bày một con số độc lập.

---

## P4 – Đánh giá chất lượng đầu ra Gemini

### Mục đích

Gemini không chỉ cần tạo được văn bản dễ đọc mà còn phải tạo ra nội dung đúng với dữ liệu alert, bám theo evidence và hữu ích cho analyst. Vì vậy cần có một phương pháp đánh giá riêng cho đầu ra LLM, thay vì chỉ đánh giá ATT&CK mapping.

P4 tập trung vào hai vấn đề chính: Gemini có tạo thông tin không có căn cứ hay không và phần giải thích của Gemini có đủ rõ ràng, nhất quán và hữu ích hay không.

### Công việc dự kiến

Xây dựng rubric gồm năm tiêu chí, mỗi tiêu chí chấm từ 0 đến 2:

| Tiêu chí | Nội dung đánh giá |
|---|---|
| Factual consistency | Nội dung có mâu thuẫn với alert hoặc mapper output hay không |
| Evidence grounding | Các nhận định có dựa trên evidence được cung cấp hay không |
| Mapping consistency | Phần giải thích có nhất quán với kết quả ATT&CK mapping đầu vào hay không |
| Action usefulness | Khuyến nghị có cụ thể, hợp lý và hữu ích cho analyst hay không |
| Uncertainty handling | Gemini có thể hiện đúng mức độ không chắc chắn và tránh kết luận quá mức hay không |

Mức điểm có thể thống nhất như sau:
- `0`: không đạt hoặc có lỗi rõ ràng.
- `1`: đạt một phần nhưng còn thiếu hoặc chưa nhất quán.
- `2`: đạt đầy đủ.

Để giảm thiên lệch, thực hiện đánh giá mù. Người chấm nhận alert, mapper output và phần phân tích cần đánh giá nhưng không dựa vào thông tin về việc output thuộc scenario nào hoặc kết quả tổng thể của hệ thống.

Có thể chọn một tập con đại diện thay vì chấm toàn bộ 90 scenario, nhưng tập được chọn cần bao gồm cả case map đúng, map sai, `uncertain` và `insufficient_evidence`.

### Kết quả dự kiến

Kết quả là bảng điểm Gemini theo từng tiêu chí và điểm trung bình. Ngoài điểm số, cần ghi lại các lỗi điển hình, đặc biệt là hallucination, suy luận vượt quá evidence hoặc khuyến nghị không phù hợp.

Ví dụ, nếu alert chỉ cho thấy một HTTP request đáng ngờ nhưng Gemini khẳng định máy đích đã bị khai thác thành công, `Factual consistency` và `Evidence grounding` phải bị trừ điểm. Nếu Gemini ghi rõ rằng alert chỉ thể hiện một attempt và chưa đủ bằng chứng xác nhận khai thác thành công, phần `Uncertainty handling` có thể đạt điểm cao.

---

## P5 – Đo độ trễ của từng khâu trong pipeline

### Mục đích

Ngoài độ chính xác, hệ thống cần được đánh giá về thời gian xử lý. Tổng latency chỉ cho biết một alert mất bao lâu để hoàn thành, nhưng không cho biết thành phần nào chiếm nhiều thời gian nhất.

P5 bổ sung phép đo theo từng khâu để mô tả rõ chi phí xử lý của pipeline và xác định bottleneck.

### Công việc dự kiến

Ghi timestamp hoặc thời gian xử lý cho ít nhất bốn mốc:

1. Normalizer hoàn thành.
2. Mapper hoàn thành.
3. Gemini trả kết quả.
4. Response cuối cùng được tạo xong.

Từ các mốc này tính:
- Normalizer latency.
- Mapper latency.
- Gemini latency.
- Thời gian xử lý sau Gemini đến khi response completed.
- Total end-to-end latency.

Nên lưu số liệu này trực tiếp vào report của mỗi scenario để sau đó có thể tính trung bình, median, minimum, maximum và các percentile nếu cần.

Ví dụ, một alert có thể mất 8 ms ở Normalizer, 420 ms ở Mapper, 1.800 ms ở Gemini và 20 ms để hoàn thiện response. Khi đó có thể thấy phần LLM chiếm phần lớn tổng thời gian xử lý.

### Kết quả dự kiến

Kết quả cuối cùng là một bảng latency theo từng scenario và một bảng tổng hợp theo từng thành phần. Có thể bổ sung một biểu đồ cột để thể hiện thời gian trung bình hoặc median của từng khâu.

Dữ liệu này giúp phần đánh giá hệ thống trả lời rõ hai câu hỏi: pipeline mất bao lâu để xử lý một alert và thành phần nào là nguyên nhân chính tạo ra độ trễ.
