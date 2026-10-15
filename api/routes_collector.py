"""
Live Network Collector API Blueprint
====================================
Exposes endpoints to start/stop live traffic capture, list network interfaces,
inspect collector throughput, and ingest raw PCAP captures into the pipeline.
"""
import os
from flask import Blueprint, request, jsonify
from werkzeug.utils import secure_filename
from config import Config
from services.live_collector import LiveCollector

bp_collector = Blueprint("collector", __name__, url_prefix="/api/v1/collector")


@bp_collector.route("/status", methods=["GET"])
def collector_status():
    """Returns current live network packet collection status and telemetry."""
    collector = LiveCollector.get_instance()
    return jsonify(collector.get_status())


@bp_collector.route("/interfaces", methods=["GET"])
def list_interfaces():
    """Lists available network adapters (WiFi, Ethernet, Loopback) on host."""
    collector = LiveCollector.get_instance()
    interfaces = collector.list_interfaces()
    return jsonify({
        "total": len(interfaces),
        "interfaces": interfaces
    })


@bp_collector.route("/start", methods=["POST"])
def start_capture():
    """
    Starts live network packet capture and automated metadata extraction.
    Payload (optional): { "interface": "...", "filter": "tcp or udp" }
    """
    data = request.get_json(silent=True) or {}
    iface = data.get("interface")
    bpf = data.get("filter", "ip")
    collector = LiveCollector.get_instance()
    result = collector.start_live_capture(interface=iface, bpf_filter=bpf)
    return jsonify(result)


@bp_collector.route("/stop", methods=["POST"])
def stop_capture():
    """Stops the active live network packet collector."""
    collector = LiveCollector.get_instance()
    result = collector.stop_capture()
    return jsonify(result)


@bp_collector.route("/pcap", methods=["POST"])
def process_pcap():
    """
    Uploads and streams a raw .pcap or .pcapng file through the metadata extractor.
    Extracts headers packet-by-packet without decrypting payload.
    """
    if "file" not in request.files:
        return jsonify({"error": "No PCAP file provided in multipart upload"}), 400

    file = request.files["file"]
    if not file.filename or not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        return jsonify({"error": "Only .pcap, .pcapng, or .cap files are supported"}), 400

    safe_name = secure_filename(file.filename)
    dest_path = os.path.join(Config.DATA_DIR, safe_name)
    file.save(dest_path)

    auto_ingest = request.form.get("auto_ingest", "true").lower() in ("true", "1")
    max_pkts = request.form.get("max_packets")
    max_pkts_int = int(max_pkts) if max_pkts else None

    collector = LiveCollector.get_instance()
    try:
        res = collector.process_pcap_file(dest_path, max_packets=max_pkts_int, auto_ingest=auto_ingest)
        return jsonify(res)
    except Exception as exc:
        return jsonify({"error": f"PCAP metadata extraction failed: {str(exc)}"}), 500
