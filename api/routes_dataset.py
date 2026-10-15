"""
Dataset Management API Blueprint
Provides endpoints to inspect available datasets, download samples,
upload custom BoT-IoT CSV or PCAP files, and regenerate test data.
"""
import os
import pandas as pd
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from config import Config
from data.dataset_generator import generate_botiot_datasets

bp_dataset = Blueprint("dataset", __name__, url_prefix="/api/v1/dataset")


@bp_dataset.route("/info", methods=["GET"])
def dataset_info():
    """Lists available datasets in the data directory."""
    files = []
    if os.path.exists(Config.DATA_DIR):
        for fname in os.listdir(Config.DATA_DIR):
            fpath = os.path.join(Config.DATA_DIR, fname)
            if os.path.isfile(fpath) and fname.endswith((".csv", ".pcap")):
                size_kb = round(os.path.getsize(fpath) / 1024, 1)
                row_count = None
                if fname.endswith(".csv"):
                    try:
                        row_count = sum(1 for _ in open(fpath, "r", encoding="utf-8", errors="ignore")) - 1
                    except Exception:
                        pass
                files.append({
                    "filename": fname,
                    "size_kb": size_kb,
                    "row_count": row_count
                })

    return jsonify({"datasets": files})


@bp_dataset.route("/sample", methods=["GET"])
def get_sample():
    """
    Returns sample records from specified dataset for quick frontend inspection.
    Query params: filename (default: botiot_attack_test.csv), limit (default: 15)
    """
    fname = request.args.get("filename", "botiot_attack_test.csv")
    limit = min(50, int(request.args.get("limit", 15)))
    fpath = os.path.join(Config.DATA_DIR, secure_filename(fname))

    if not os.path.exists(fpath):
        return jsonify({"error": f"File not found: {fname}"}), 404

    try:
        df = pd.read_csv(fpath)
        sample_rows = df.head(limit).to_dict(orient="records")
        return jsonify({
            "filename": fname,
            "total_rows": len(df),
            "columns": list(df.columns),
            "sample": sample_rows
        })
    except Exception as e:
        return jsonify({"error": f"Failed to read dataset: {str(e)}"}), 500


@bp_dataset.route("/upload", methods=["POST"])
def upload_dataset():
    """Uploads a custom BoT-IoT CSV or PCAP file."""
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    if not (filename.endswith(".csv") or filename.endswith(".pcap")):
        return jsonify({"error": "Only .csv or .pcap files are supported"}), 400

    dest_path = os.path.join(Config.DATA_DIR, filename)
    file.save(dest_path)

    return jsonify({
        "message": f"Dataset {filename} uploaded successfully",
        "filepath": dest_path,
        "size_bytes": os.path.getsize(dest_path)
    })


@bp_dataset.route("/generate", methods=["POST"])
def regenerate_dataset():
    """Regenerates fresh BoT-IoT sample datasets."""
    data = request.get_json() or {}
    normal_count = int(data.get("normal_count", 1500))
    attack_count = int(data.get("attack_count", 600))

    try:
        n_path, t_path = generate_botiot_datasets(
            Config.DATA_DIR, num_normal=normal_count, num_attack=attack_count
        )
        return jsonify({
            "message": "BoT-IoT datasets regenerated successfully",
            "normal_dataset": n_path,
            "test_dataset": t_path
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
