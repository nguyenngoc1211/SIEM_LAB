# SIEM LAB

Môi trường nghiên cứu và thực hành SOC kết hợp phát hiện tấn công, quản lý sự kiện bảo mật và ánh xạ cảnh báo sang MITRE ATT&CK.

## Kiến trúc

```text
Attacker -> Nginx Gateway -> OWASP Juice Shop
                         -> Suricata -> Wazuh -> n8n
                                                -> ATTACK-BERT + BM25
                                                -> Qdrant + Reranker
                                                -> MITRE ATT&CK Mapping
```

## Thành phần

- `soc-lab-handoff-v1.0.0/`: lab Juice Shop, Nginx, Suricata, công cụ mô phỏng tấn công, script vận hành và tài liệu bàn giao.
- `data/mitre-mapping/`: API và pipeline ánh xạ cảnh báo IDS sang MITRE ATT&CK.
- `data/docker-compose.yaml`: n8n, Qdrant, embedding API, reranker, indexer và mapper API.
- `wazuh-custom/`: các file tùy chỉnh trên nền Wazuh Docker 4.8.0.
- `reports/`: kho báo cáo của dự án, gồm 2 bundle `scenario-results-a1-a2/`
  và `baseline-comparison/` (xem `reports/README.md`).

## Dữ liệu không lưu trong Git

Repository không lưu file `.env`, credential n8n, dữ liệu Qdrant, model đã tải, log runtime, database hoặc khóa/chứng chỉ riêng. Hãy tạo cấu hình cục bộ từ các file `.env.example`. Trong `reports/`, chỉ tầng curated được commit; các thư mục `raw/`, `raw_results/`, `checkpoints/`, `snapshots/`, `archive/` bị git bỏ qua.

## Tài liệu chính

- `soc-lab-handoff-v1.0.0/README.md`
- `soc-lab-handoff-v1.0.0/docs/HUONG_DAN_BAN_GIAO.md`
- `soc-lab-handoff-v1.0.0/docs/RUNBOOK.md`
- `data/mitre-mapping/README.md`
- `data/mitre-mapping/Hướng dẫn vận hành Mapping.md`
- `reports/README.md`
