"""
Network Collector API
======================
GET  /api/v1/collector/status       — operating mode, counters, errors, capabilities (SOC)
GET  /api/v1/collector/interfaces   — capture interfaces on this host (SOC)
POST /api/v1/collector/start        — start live capture or simulation (ADMIN)
POST /api/v1/collector/stop         — stop, drain and flush open flows (ADMIN)
POST /api/v1/collector/pcap         — offline PCAP analysis (ADMIN)

Role checks live in core/auth.py (install_soc_guard): reads need SECURITY_ANALYST or
ADMIN, every POST here needs ADMIN.
"""
import logging
import os
import uuid

from flask import Blueprint, current_app, jsonify, request

from config import Config
from services.live_collector import LiveCollector, PcapValidationError

bp_collector = Blueprint("collector", __name__, url_prefix="/api/v1/collector")
logger = logging.getLogger(__name__)

_INVALID_REQUEST_HINTS = ("Select a capture interface", "was not found", "not in COLLECTOR_ALLOWED_INTERFACES",
                          "Invalid capture filter")


@bp_collector.route("/status", methods=["GET"])
def collector_status():
    return jsonify(LiveCollector.get_instance().get_status())


@bp_collector.route("/interfaces", methods=["GET"])
def list_interfaces():
    collector = LiveCollector.get_instance()
    interfaces = collector.list_interfaces()
    status = collector.get_status()
    return jsonify({
        "total": len(interfaces),
        "interfaces": interfaces,
        "live_capture_available": status["live_capture_available"],
        "live_capture_unavailable_reason": status["live_capture_unavailable_reason"],
    })


@bp_collector.route("/start", methods=["POST"])
def start_capture():
    """
    Body: { "mode": "live" | "simulation", "interface": "<name from /interfaces>",
            "filter": "tcp or udp", "allow_simulation_fallback": false }
    (legacy: "simulate": true is the same as mode=simulation)
    """
    data = request.get_json(silent=True) or {}
    mode = str(data.get("mode") or ("simulation" if data.get("simulate") else "live")).lower()
    if mode not in ("live", "simulation"):
        return jsonify({"status": "error", "error": "mode must be 'live' or 'simulation'"}), 400
    collector = LiveCollector.get_instance()
    result = collector.start_live_capture(
        interface=data.get("interface") or None,
        bpf_filter=str(data.get("filter") or "ip"),
        simulate=mode == "simulation",
        allow_fallback=bool(data.get("allow_simulation_fallback", False)),
    )
    if result.get("status") in ("started", "already_running"):
        return jsonify(result), 200
    if result.get("status") == "busy":
        return jsonify(result), 409
    err = result.get("error") or ""
    code = 400 if any(h in err for h in _INVALID_REQUEST_HINTS) else 503
    return jsonify(result), code


@bp_collector.route("/stop", methods=["POST"])
def stop_capture():
    return jsonify(LiveCollector.get_instance().stop_capture())


@bp_collector.route("/pcap/stop", methods=["POST"])
def stop_pcap():
    return jsonify(LiveCollector.get_instance().stop_pcap())


@bp_collector.route("/pcap", methods=["POST"])
def process_pcap():
    """
    multipart/form-data: file (.pcap/.pcapng/.cap), optional max_packets, auto_ingest.
    The upload is stored under a random name, analysed through the same metadata →
    flow → EventProcessor path as live capture (source="pcap"), then deleted.
    """
    max_pkts_raw = request.form.get("max_packets")
    max_pkts_int = None
    max_allowed = current_app.config.get("MAX_PCAP_PACKETS", Config.MAX_PCAP_PACKETS)
    if max_pkts_raw is not None and max_pkts_raw != "":
        try:
            max_pkts_int = int(max_pkts_raw)
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid max_packets: must be a positive integer"}), 400
        if max_pkts_int <= 0:
            return jsonify({"error": "max_packets must be greater than zero"}), 400
        if max_pkts_int > max_allowed:
            return jsonify({"error": f"max_packets exceeds maximum allowable limit of {max_allowed}"}), 400

    if "file" not in request.files:
        return jsonify({"error": "No PCAP file provided in multipart upload"}), 400
    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"error": "Empty filename provided"}), 400
    lower_name = file.filename.lower()
    if not lower_name.endswith((".pcap", ".pcapng", ".cap")):
        return jsonify({"error": "Only .pcap, .pcapng, or .cap files are supported"}), 400
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size == 0:
        return jsonify({"error": "Uploaded PCAP file is empty (0 bytes)"}), 400

    work_dir = os.path.join(current_app.config.get("INSTANCE_DIR", Config.INSTANCE_DIR), "pcap_work")
    os.makedirs(work_dir, exist_ok=True)
    dest_path = os.path.join(work_dir, f"{uuid.uuid4().hex}.pcap")
    file.save(dest_path)
    auto_ingest = request.form.get("auto_ingest", "true").lower() in ("true", "1")
    try:
        res = LiveCollector.get_instance().process_pcap_file(
            dest_path, max_packets=max_pkts_int, auto_ingest=auto_ingest,
        )
        res["file"] = os.path.basename(file.filename)[:255]
        if collector_last := LiveCollector.get_instance().last_pcap:
            collector_last["file"] = res["file"]
        return jsonify(res), 422 if res.get("status") == "error" else 200
    except PcapValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        logger.error("PCAP metadata extraction error: %s", exc, exc_info=True)
        return jsonify({"error": "PCAP metadata extraction failed. Verify the file is an uncorrupted capture."}), 500
    finally:
        try:
            os.remove(dest_path)
        except OSError:
            pass
