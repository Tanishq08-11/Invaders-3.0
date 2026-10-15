"""
Detection API Blueprint
Allows clients to submit ad-hoc packet headers or flow records for immediate inference.
"""
from flask import Blueprint, request, jsonify
from services.detection_service import DetectionService

bp_detection = Blueprint("detection", __name__, url_prefix="/api/v1/detection")


@bp_detection.route("/inspect", methods=["POST"])
def inspect_single_flow():
    """
    Submits a single encrypted network flow/packet for real-time inference.
    Payload: { "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length", "timestamp" }
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400

    persist = request.args.get("persist", "true").lower() in ["true", "1", "yes"]
    detection_svc = DetectionService.get_instance()
    result = detection_svc.process_flow(data, persist=persist)

    return jsonify(result)


@bp_detection.route("/batch", methods=["POST"])
def inspect_batch():
    """
    Submits an array of encrypted network flows for batch analysis.
    Payload: { "flows": [ ... ] }
    """
    data = request.get_json() or {}
    flows = data.get("flows", [])
    if not flows:
        return jsonify({"error": "No 'flows' array provided"}), 400

    persist = request.args.get("persist", "true").lower() in ["true", "1", "yes"]
    detection_svc = DetectionService.get_instance()

    results = []
    threat_count = 0
    for f in flows[:500]: # Cap at 500 per request
        res = detection_svc.process_flow(f, persist=persist)
        results.append(res)
        if res.get("is_threat"):
            threat_count += 1

    return jsonify({
        "total_processed": len(results),
        "threats_detected": threat_count,
        "results": results
    })
