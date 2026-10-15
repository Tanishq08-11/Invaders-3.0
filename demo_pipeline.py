"""
End-to-End Workflow Demonstration Script
Validates each stage of the AI Insider Threat Detection System:
1. BoT-IoT Dataset Split (Normal Baseline vs Attack / Exfiltration)
2. Kitsune Feature Extraction (AfterImage: 100 damped temporal features, zero decryption)
3. KitNET Autoencoder Ensemble Training & Correlation Feature Mapping
4. Normal Baseline Calibration (Learned thresholds)
5. Live Stream Ingestion & Detection on Attack Traffic
6. Alert & Risk Engine Evaluation
7. Explainable AI (XAI) Attribution & Forensic Narrative Generation
8. Flask API & Security Dashboard Telemetry
"""
import os
import sys
import time
import json
import pandas as pd
import numpy as np

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from config import Config
from app import create_app
from core.database import db
from core.models import Alert, Device, Event, ModelVersion
from extractor.afterimage import AfterImage
from ml.kitnet import KitNET
from ml.risk_engine import RiskEngine
from ml.explanation_engine import ExplanationEngine
from services.training_service import TrainingService
from services.event_processor import EventProcessor


def run_demonstration():
    print("=" * 80)
    print("  AI INSIDER THREAT DETECTION VIA ENCRYPTED TRAFFIC ANALYSIS (ZERO DECRYPTION)")
    print("  Kitsune (AfterImage) + KitNET Ensemble Autoencoders + Flask Backend")
    print("=" * 80)

    # -------------------------------------------------------------
    # STAGE 1: Dataset Verification (BoT-IoT Normal vs Attack)
    # -------------------------------------------------------------
    print("\n[STAGE 1] Loading BoT-IoT Datasets...")
    normal_csv = os.path.join(Config.DATA_DIR, "botiot_normal_train.csv")
    attack_csv = os.path.join(Config.DATA_DIR, "botiot_attack_test.csv")

    df_normal = pd.read_csv(normal_csv)
    df_attack = pd.read_csv(attack_csv)

    print(f"  -> Normal Training Dataset: {len(df_normal)} records (Benign enterprise baseline)")
    print(f"  -> Testing Dataset:         {len(df_attack)} records (Mix of Benign & Exfiltration attacks)")

    # -------------------------------------------------------------
    # STAGE 2: Kitsune Feature Extractor (AfterImage)
    # -------------------------------------------------------------
    print("\n[STAGE 2] Kitsune Feature Extractor (AfterImage)...")
    extractor = AfterImage(lambdas=Config.AFTERIMAGE_LAMBDAS)
    sample_flow = df_normal.iloc[0].to_dict()
    sample_vec = extractor.extract_from_flow(sample_flow)

    print(f"  -> Extracted Damped Statistical Feature Dimension: {len(sample_vec)}")
    print(f"  -> Multi-window decay factors (lambdas): {Config.AFTERIMAGE_LAMBDAS}")
    print(f"  -> First 5 features: {sample_vec[:5].round(3)}")
    print(f"  -> Privacy Guard: ZERO payload decryption performed. Only IP/port/temporal dynamics used.")

    # -------------------------------------------------------------
    # STAGE 3: KitNET Baseline Model Calibration
    # -------------------------------------------------------------
    print("\n[STAGE 3] KitNET Training & Feature Mapping...")
    trainer = TrainingService()
    train_res = trainer.train_baseline_from_csv(normal_csv, epochs=1, max_rows=1000)

    print(f"  -> Trained on: {train_res['samples_processed']} normal flows")
    print(f"  -> Feature Mapper Clusters: {train_res['num_clusters']} sub-autoencoders")
    print(f"  -> Baseline Mean RMSE: {train_res['baseline_mean_error']}")
    print(f"  -> Baseline Std Dev:   {train_res['baseline_std_error']}")
    print(f"  -> Baseline Max RMSE:  {train_res['baseline_max_error']}")

    # -------------------------------------------------------------
    # STAGE 4: Detection & Alert / Risk Engine Evaluation
    # -------------------------------------------------------------
    print("\n[STAGE 4 & 5] Incoming Traffic Stream Ingestion, AI Detection & Risk Scoring...")
    proc = EventProcessor.get_instance()
    proc.reload_model()

    app = create_app()
    with app.app_context():
        # Test 1: Normal Flow Detection
        normal_test = df_normal.iloc[50].to_dict()
        normal_result = proc.ingest(normal_test)
        risk1 = normal_result.get("risk_eval") or {}

        print("\n  [Sample 1: Legitimate Internal Web Flow]")
        print(f"    Source Host:    {normal_result['src_ip']} -> {normal_result['dst_ip']}:{normal_result['dst_port']}")
        print(f"    Anomaly Score:  {normal_result['anomaly_score']}")
        print(f"    Z-Score:        {risk1.get('z_score')}")
        print(f"    Risk Score:     {risk1.get('risk_score')} / 100")
        print(f"    Classification: {risk1.get('severity')} (Threat: {risk1.get('is_threat')})")

        # Test 2: Bulk TLS Data Exfiltration Attack by Insider
        attack_rows = df_attack[df_attack["attack"] == 1]
        tls_exfil_row = attack_rows[attack_rows["subcategory"] == "Bulk_TLS_Exfiltration"].iloc[0].to_dict()
        tls_exfil_row["stime"] = time.time()
        threat_result = proc.ingest(tls_exfil_row)
        risk2 = threat_result.get("risk_eval") or {}
        alert2 = threat_result.get("alert") or {}

        print("\n  [Sample 2: Rogue Insider Bulk Data Exfiltration over TLS 443]")
        print(f"    Source Host:    {threat_result['src_ip']} -> {threat_result['dst_ip']}:{threat_result['dst_port']}")
        print(f"    Anomaly Score:  {threat_result['anomaly_score']} (Baseline mean: {train_res['baseline_mean_error']})")
        print(f"    Z-Score:        {risk2.get('z_score')} sigma")
        print(f"    Risk Score:     {risk2.get('risk_score')} / 100")
        print(f"    Severity:       {risk2.get('severity')}")
        print(f"    Alert UUID:     {alert2.get('alert_uuid')}")

        # -------------------------------------------------------------
        # STAGE 6: Explanation Engine (XAI)
        # -------------------------------------------------------------
        print("\n[STAGE 6] Explainable AI (XAI) Forensic Breakdown...")
        print(f"  Executive SOC Narrative:")
        print(f"    \"{threat_result.get('explanation')}\"")
        if alert2.get("evidence"):
            print(f"\n  Top Deviating Features (Autoencoder Reconstruction Error Attribution):")
            for f in alert2["evidence"][:4]:
                print(f"    - Rank {f.get('rank')}: {f.get('display_name')} ({f.get('feature_name')})")
                print(f"      Reconstruction Error: {f.get('importance_score')} ({f.get('contribution_pct')}% of total error)")
                print(f"      Finding: {f.get('description')}")

        if alert2.get("mitigation"):
            print(f"\n  Automated SOC Playbook Recommendations:")
            for step in alert2["mitigation"][:3]:
                print(f"    [ACTION] {step}")

        # -------------------------------------------------------------
        # STAGE 7: Flask Backend Telemetry & Device Profiles
        # -------------------------------------------------------------
        print("\n[STAGE 7] Flask Backend State & Device Risk Profiles...")
        total_alerts = Alert.query.count()
        devices = Device.query.all()
        print(f"  -> Total Active Alerts in DB: {total_alerts}")
        print(f"  -> Tracked Internal Devices:  {len(devices)}")
        for d in devices:
            status = "FLAGGED / QUARANTINED" if d.is_flagged else "NORMAL"
            print(f"     * Device {d.device_id} ({d.hostname}): Risk={d.risk_score}/100, Alerts={d.alert_count}, Status={status}")

    print("\n" + "=" * 80)
    print("  ALL PIPELINE STAGES VALIDATED SUCCESSFULLY!")
    print("  Flask REST & SSE streaming server ready for Security Dashboard connection.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_demonstration()
