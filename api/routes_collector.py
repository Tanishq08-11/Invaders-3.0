"""
Live Network Collector API Blueprint
====================================
Exposes endpoints to start/stop live traffic capture, list network interfaces,
inspect collector throughput, and ingest raw PCAP captures into the pipeline.
"""
import os
import logging
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename
from config import Config
from services.live_collector import LiveCollector

bp_collector = Blueprint("collector", __name__, url_prefix="/api/v1/collector")
logger = logging.getLogger(__name__)


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
    Starts live network packet capture or simulation.
    Payload (optional): { "interface": "...", "filter": "tcp or udp", "simulate": false }
    """
    data = request.get_json(silent=True) or {}
    iface = data.get("interface")
    bpf = data.get("filter", "ip")
    simulate = bool(data.get("simulate", False))
    collector = LiveCollector.get_instance()
    result = collector.start_live_capture(interface=iface, bpf_filter=bpf, simulate=simulate)
    status_code = 200 if result.get("status") in ("started", "already_running") else 400
    return jsonify(result), status_code


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
    Strictly validates input parameters before processing.
    """
    # 1. Validate max_packets before opening or processing any file
    max_pkts_raw = request.form.get("max_packets")
    max_pkts_int = None
    if max_pkts_raw is not None and max_pkts_raw != "":
        try:
            max_pkts_int = int(max_pkts_raw)
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid max_packets: must be a positive integer"}), 400

        if max_pkts_int <= 0:
            return jsonify({"error": "max_packets must be greater than zero"}), 400

        max_allowed = getattr(Config, "MAX_PCAP_PACKETS", 50000)
        if max_pkts_int > max_allowed:
            return jsonify({
                "error": f"max_packets exceeds maximum allowable limit of {max_allowed}"
            }), 400

    # 2. Validate file presence
    if "file" not in request.files:
        return jsonify({"error": "No PCAP file provided in multipart upload"}), 400

    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"error": "Empty filename provided"}), 400

    # 3. Validate file extension
    lower_name = file.filename.lower()
    if not lower_name.endswith((".pcap", ".pcapng", ".cap")):
        return jsonify({"error": "Only .pcap, .pcapng, or .cap files are supported"}), 400

    # 4. Check for empty file
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size == 0:
        return jsonify({"error": "Uploaded PCAP file is empty (0 bytes)"}), 400

    # 5. Sanitize filename to prevent directory traversal
    safe_name = secure_filename(file.filename)
    if not safe_name:
        safe_name = "upload.pcap"

    dest_path = os.path.join(Config.DATA_DIR, safe_name)
    file.save(dest_path)

    auto_ingest = request.form.get("auto_ingest", "true").lower() in ("true", "1")
    collector = LiveCollector.get_instance()

    try:
        res = collector.process_pcap_file(
            dest_path,
            max_packets=max_pkts_int,
            auto_ingest=auto_ingest
        )
        if res.get("status") == "error":
            return jsonify(res), 422
        return jsonify(res), 200
    except Exception as exc:
        logger.error(f"PCAP metadata extraction error: {exc}", exc_info=True)
        return jsonify({
            "error": "PCAP metadata extraction failed. Verify the file is an uncorrupted capture."
        }), 500
