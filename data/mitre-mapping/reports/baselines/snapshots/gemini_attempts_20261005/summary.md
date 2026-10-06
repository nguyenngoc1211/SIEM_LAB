# Gemini baseline attempts archive

- Created at: `2026-10-05T14:11:44.598058+00:00`
- Total successful rows: 24
- Unique scenarios with a successful Gemini mapping: 23

| Arm | Model | Attempted | Successful | Failed | Error reasons |
|---|---|---:|---:|---:|---|
| gemini_only | gemini-2.5-flash | 40 | 23 | 17 | {'HTTP 404': 17} |
| gemini_only_38flash | gemini-3.8-flash | 7 | 1 | 6 | {'HTTP 429': 4, 'HTTP 503': 2} |
| gemini_only_38flash_nothink | gemini-3.8-flash | 1 | 0 | 1 | {'HTTP 429': 1} |
| gemini_only_pro31 | gemini-3.1-pro-preview | 1 | 0 | 1 | {'HTTP 429': 1} |

## Successful scenario ids

- `gemini_only`: A1-T1046-01, A1-T1046-02, A1-T1078-01, A1-T1189-01, A1-T1189-02, A1-T1190-01, A1-T1190-02, A1-T1190-03, A1-T1190-04, A1-T1190-05, A1-T1210-01, A1-T1210-02, A1-T1210-03, A1-T1210-04, A1-T1210-05, A2-T1046-01, A2-T1046-02, A2-T1046-03, A2-T1071.001-01, A2-T1071.001-02, A2-T1071.001-03, A2-T1071.001-05, A2-T1078-03
- `gemini_only_38flash`: A1-T1046-01
