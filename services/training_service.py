"""
Training Service — trains KitNET baseline from normal BoT-IoT data.
Records the model version in the database for traceability.
"""
import os
import time
from typing import Dict, Any, Optional
import pandas as pd
import numpy as np

from config import Config
from core.database import db
from core.models import ModelVersion
from extractor.afterimage import AfterImage
from ml.kitnet import KitNET


class TrainingService:
    def __init__(self, checkpoint_path: Optional[str] = None):
        self.checkpoint_path = checkpoint_path or os.path.join(
            Config.CHECKPOINTS_DIR, "kitnet_baseline.pkl"
        )

    def train_baseline_from_csv(
        self,
        csv_path: str,
        epochs: int = 1,
        max_rows: Optional[int] = None,
    ) -> Dict[str, Any]:
        start = time.time()
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"Training dataset not found: {csv_path}")

        df = pd.read_csv(csv_path)
        if "attack" in df.columns:
            df = df[df["attack"] == 0]
        elif "category" in df.columns:
            df = df[df["category"].astype(str).str.lower() == "normal"]

        if max_rows and len(df) > max_rows:
            df = df.iloc[:max_rows]

        total = len(df)
        if total < 50:
            raise ValueError(f"Need ≥50 normal samples, got {total}")

        # Feature extraction
        extractor = AfterImage(lambdas=Config.AFTERIMAGE_LAMBDAS)
        features = []
        for _, row in df.iterrows():
            flow = {
                "timestamp": float(row.get("stime", row.get("timestamp", time.time()))),
                "src_ip":    str(row.get("saddr", row.get("src_ip", "192.168.1.100"))),
                "dst_ip":    str(row.get("daddr", row.get("dst_ip", "10.0.0.1"))),
                "src_port":  int(row.get("sport", row.get("src_port", 49152))),
                "dst_port":  int(row.get("dport", row.get("dst_port", 443))),
                "protocol":  str(row.get("proto", row.get("protocol", "tcp"))),
                "length":    float(row.get("bytes", row.get("length", 500.0))),
            }
            features.append(extractor.extract_from_flow(flow))

        X = np.array(features, dtype=np.float32)
        dim = X.shape[1]

        # KitNET training
        kitnet = KitNET(
            input_dim=dim,
            max_cluster_size=Config.KITNET_MAX_CLUSTER_SIZE,
            hidden_ratio=Config.KITNET_HIDDEN_RATIO,
            lr=Config.KITNET_LEARNING_RATE,
            grace_fm=min(Config.KITNET_GRACE_FEATURE_MAPPING, max(30, total // 4)),
            grace_train=min(Config.KITNET_GRACE_TRAINING, total - 30),
        )
        kitnet.fit_batch(X, epochs=epochs)
        kitnet.save(self.checkpoint_path)

        duration = round(time.time() - start, 2)

        # Record model version in DB
        version_id = None
        try:
            ModelVersion.query.update({ModelVersion.is_active: False})
            mv = ModelVersion(
                version=f"v{int(time.time())}",
                training_samples=total,
                feature_dimension=dim,
                num_clusters=len(kitnet.clusters),
                baseline_mean=kitnet.baseline_mean,
                baseline_std=kitnet.baseline_std,
                baseline_max=kitnet.baseline_max,
                dataset_name=os.path.basename(csv_path),
                checkpoint_path=self.checkpoint_path,
                is_active=True,
            )
            db.session.add(mv)
            db.session.commit()
            version_id = mv.id
        except Exception:
            pass

        return {
            "status": "success",
            "samples":           total,
            "samples_processed": total,
            "features":          dim,
            "clusters":          len(kitnet.clusters),
            "num_clusters":      len(kitnet.clusters),
            "baseline_mean":       round(kitnet.baseline_mean, 5),
            "baseline_mean_error": round(kitnet.baseline_mean, 5),
            "baseline_std":        round(kitnet.baseline_std, 5),
            "baseline_std_error":  round(kitnet.baseline_std, 5),
            "baseline_max":        round(kitnet.baseline_max, 5),
            "baseline_max_error":  round(kitnet.baseline_max, 5),
            "duration_s":        duration,
            "checkpoint":        self.checkpoint_path,
            "model_version_id":  version_id,
        }
