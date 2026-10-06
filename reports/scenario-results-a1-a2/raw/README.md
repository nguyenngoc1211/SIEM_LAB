# Tier 2 - raw artifacts (không commit)

Thư mục này là chỗ dành cho bản sao/kết xuất thô của bundle. Hiện tại **artifact
thô không được sao chép vào đây**, vì nguồn chính là bind mount của Docker và
phải giữ nguyên tại chỗ:

```text
soc-lab-handoff-v1.0.0/runtime/reports/
  a1/<Scenario>.json      # 15 kết quả A1
  a2/<Scenario>.json      # 75 kết quả A2
  archive/<mốc-chạy>/     # snapshot các lần chạy trước
```

`runtime/` đã bị ignore trong `.gitignore`, nên toàn bộ tier 2 này không vào git.
Thông tin kiểm chứng (số lượng, hash, mốc thời gian) nằm ở `../MANIFEST.json`.

Nếu cần đóng băng một lần chạy để lưu trữ dài hạn, copy `runtime/reports/a1|a2`
vào đây; các file trong `raw/` sẽ tiếp tục được git bỏ qua.
