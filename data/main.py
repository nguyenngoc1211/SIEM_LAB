import argparse
import json
import sys
import uvicorn
from fastapi import FastAPI, HTTPException
from typing import Any, Dict
from search import MITRESearchEngine

app = FastAPI(
    title="Suricata Alert MITRE ATT&CK Mapper API",
    description="REST API to map Suricata alerts to MITRE ATT&CK techniques and tactics in real time.",
    version="1.0.0"
)

# Khởi tạo search engine
engine = None

@app.on_event("startup")
def startup_event():
    global engine
    engine = MITRESearchEngine()

@app.post("/analyze")
def analyze_alert(payload: Dict[str, Any], disable_rules: bool = False):
    """
    Nhận JSON alert và trả về kỹ thuật MITRE ATT&CK được ánh xạ.
    """
    if engine is None:
        raise HTTPException(status_code=500, detail="Search engine is not initialized.")
    try:
        result = engine.hybrid_search_alert(payload, disable_rules=disable_rules)
        if "error" in result:
            raise HTTPException(status_code=500, detail=result["error"])
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def run_cli(file_path, disable_rules=False):
    """
    Chạy công cụ qua Command Line Interface để kiểm tra file alert log.
    """
    cli_engine = MITRESearchEngine()
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            alert_json = json.load(f)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

    result = cli_engine.hybrid_search_alert(alert_json, disable_rules=disable_rules)
    if "error" in result:
        print(f"Search failed: {result['error']}")
        sys.exit(1)

    query_info = result["query"]
    result_list = result["result"]

    print("\n" + "="*70)
    print("              SURICATA ALERT ANALYSIS RESULTS (HYBRID SEARCH)")
    print("="*70)
    print(f"Alert ID            : {result.get('id', 'N/A')}")
    print(f"Signature           : {query_info.get('signature', 'N/A')}")
    print(f"Original Severity   : {query_info.get('Suricata_severity', 'N/A')}")
    print(f"Original Confidence : {query_info.get('mapping_confidence', 'N/A')}")
    print("-" * 70)
    print("TOP MAPPED MITRE ATT&CK TECHNIQUES:")
    
    for idx, hit in enumerate(result_list):
        payload = hit["payload"]
        print(f"\n[{idx+1}] RRF Score: {hit['rrf_score']:.4f} | Mapping Confidence: {hit['mapping_confidence']:.4f}")
        print(f"    Technique ID  : {payload['technique_id']}")
        print(f"    Technique Name: {payload['technique_name']}")
        print(f"    Tactic        : {payload['tactic']} ({payload['tactic_id']})")
        # Cắt ngắn description hiển thị
        desc_snippet = payload['description'].replace('\n', ' ').strip()
        print(f"    Description   : {desc_snippet[:150]}...")
        
    print("-" * 70)
    
    # Đối chiếu với nhãn thực tế trong log wazuh (nếu có)
    actual_ids = []
    _source = alert_json.get("_source", {})
    
    # Thử check _source.rule.mitre.id
    mitre_info = _source.get("rule", {}).get("mitre", {}) if isinstance(_source, dict) else {}
    if mitre_info and isinstance(mitre_info, dict) and "id" in mitre_info:
        actual_ids = mitre_info["id"]
        
    # Thử check _source.data.alert.metadata.mitre_technique_id
    if not actual_ids and isinstance(_source, dict):
        metadata = _source.get("data", {}).get("alert", {}).get("metadata", {}) if isinstance(_source, dict) else {}
        if metadata and isinstance(metadata, dict) and "mitre_technique_id" in metadata:
            actual_ids = metadata["mitre_technique_id"]
            
    if actual_ids:
        # Chuẩn hóa về list
        if not isinstance(actual_ids, list):
            actual_ids = [actual_ids]
        print(f"Actual Technique ID in log: {actual_ids}")
        
        # Kiểm tra xem kết quả số 1 có khớp không
        top_matched = False
        if result_list:
            top_tid = result_list[0]['payload']['technique_id']
            # So sánh (cho phép so khớp sub-technique ví dụ T1059 khớp với T1059.007)
            for aid in actual_ids:
                if top_tid.lower() == aid.lower() or top_tid.lower().startswith(aid.lower() + ".") or aid.lower().startswith(top_tid.lower() + "."):
                    top_matched = True
                    break
        
        if top_matched:
            print("\n>>> SUCCESS: Predicted top technique matches the actual label in the log!")
        else:
            print("\n>>> WARNING: Predicted top technique does not match the actual label in the log.")
    else:
        print("No actual MITRE Technique ID found in the input alert log to compare.")
    print("="*70)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MITRE ATT&CK Mapper")
    parser.add_argument("--file", type=str, help="Path to alert JSON log file to analyze via CLI")
    parser.add_argument("--disable-rules", action="store_true", help="Bypass and disable Rule Engine constraints")
    parser.add_argument("--serve", action="store_true", help="Start the FastAPI API Server")
    parser.add_argument("--port", type=int, default=8000, help="API Server port")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="API Server host")
    
    args = parser.parse_args()
    
    if args.serve:
        print(f"Starting FastAPI server on {args.host}:{args.port}...")
        uvicorn.run("main:app", host=args.host, port=args.port, reload=True)
    elif args.file:
        run_cli(args.file, disable_rules=args.disable_rules)
    else:
        parser.print_help()

# python main.py --serve --port 8000