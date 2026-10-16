"""
1-Click Automated Scenario Tester for VEYLIX / Invaders 3.0
===========================================================
Runs each test condition against the live backend and prints
the exact results in clean, human-readable format.
"""
import urllib.request
import urllib.error
import json
import time

BASE_URL = "http://127.0.0.1:5000"

def send_flow(test_title, flow_data):
    print(f"\n{'='*70}")
    print(f"  TEST: {test_title}")
    print(f"{'='*70}")
    payload = json.dumps(flow_data).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/model/predict",
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            print(f"  • Anomaly Score     : {data.get('anomaly_score')}")
            print(f"  • Trained Threshold : {data.get('threshold')} (Score > Threshold = Threat)")
            print(f"  • Is Anomalous?     : {data.get('is_anomalous')}")
            print(f"  • Risk Level        : {data.get('risk_level')}")
            
            top_feats = data.get("top_contributing_features", [])
            if top_feats:
                print(f"  • Top Deviation     : {top_feats[0]['name']} (Reconstruction Error: {top_feats[0]['error']})")
            
            signals = data.get("detector_signals", [])
            if signals:
                print(f"  • Triggered Rules   : {len(signals)} detector(s)")
                for s in signals[:3]:
                    print(f"      - [{s.get('detector_id')}] {s.get('name')}: {s.get('reason')}")
            else:
                print("  • Triggered Rules   : None (Clean traffic)")
            
            if data.get("is_anomalous"):
                print("  --> RESULT: [!] FRAUD DETECTED - Alert Generated in SOC Dashboard")
            else:
                print("  --> RESULT: [OK] Normal benign traffic - Allowed")
    except Exception as e:
        print(f"  Error running test: {e}")

def main():
    print("\n" + "#"*70)
    print("  VEYLIX / INVADERS 3.0 - SIMPLIFIED TEST RUNNER")
    print("#"*70)
    
    # -------------------------------------------------------------
    # CONDITION 1: Normal Legitimate Web Browsing
    # -------------------------------------------------------------
    send_flow(
        "Condition 1: Normal Business Browsing (Small packets, Port 443, Business Hours)",
        {
            "Src Port": 51200, "Dst Port": 443, "Protocol": 6,
            "Flow Duration": 1500, "Tot Fwd Pkts": 12, "Tot Bwd Pkts": 15,
            "TotLen Fwd Pkts": 1500, "TotLen Bwd Pkts": 4500,
            "HourSin": 0.25, "HourCos": 0.96, # 11:00 AM
            "DaySin": 0.0, "DayCos": 1.0
        }
    )

    # -------------------------------------------------------------
    # CONDITION 2: Massive Data Exfiltration (Bulk Dumping)
    # -------------------------------------------------------------
    send_flow(
        "Condition 2: Rogue Bulk Data Exfiltration (Spike in Bytes & Packets)",
        {
            "Src Port": 49152, "Dst Port": 443, "Protocol": 6,
            "Flow Duration": 850000, "Tot Fwd Pkts": 35000, "Tot Bwd Pkts": 100,
            "TotLen Fwd Pkts": 52000000, "TotLen Bwd Pkts": 5000, # 52 MB Outbound!
            "Flow Byts/s": 61176.0, "Flow Pkts/s": 41.2,
            "HourSin": 0.25, "HourCos": 0.96,
            "DaySin": 0.0, "DayCos": 1.0
        }
    )

    # -------------------------------------------------------------
    # CONDITION 3: Stealth Off-Hours Transmission (Night-time Siphoning)
    # -------------------------------------------------------------
    send_flow(
        "Condition 3: Off-Hours Siphoning (Transferred at 2:30 AM night)",
        {
            "Src Port": 50100, "Dst Port": 443, "Protocol": 6,
            "Flow Duration": 250000, "Tot Fwd Pkts": 5000, "Tot Bwd Pkts": 20,
            "TotLen Fwd Pkts": 7500000, "TotLen Bwd Pkts": 1000,
            "HourSin": 0.60, "HourCos": 0.79, # 2:30 AM off-hours
            "DaySin": 0.97, "DayCos": -0.22,
            "Timestamp": 1600052400
        }
    )

    # -------------------------------------------------------------
    # CONDITION 4: Unusual Outbound Port (Reverse Shell / Tunneling)
    # -------------------------------------------------------------
    send_flow(
        "Condition 4: Suspicious Port / Backdoor Communication (Port 9001 / Raw Egress)",
        {
            "Src Port": 55432, "Dst Port": 9001, "Protocol": 6,
            "Flow Duration": 12000, "Tot Fwd Pkts": 800, "Tot Bwd Pkts": 10,
            "TotLen Fwd Pkts": 1200000, "TotLen Bwd Pkts": 500,
            "HourSin": 0.0, "HourCos": 1.0,
            "DaySin": 0.0, "DayCos": 1.0
        }
    )

    print("\n" + "="*70)
    print("  ALL CONDITIONS TESTED! Now open http://localhost:5000/soc/alerts")
    print("  to see each of these alerts logged with their XAI forensic breakdown!")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
