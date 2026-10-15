"""
POST /api/v1/events — ingest one normalised event or an agreed batch format.
=============================================================================
Accepts:
  • Single event:  { "src_ip": …, "dst_ip": …, … }
  • Batch:         { "events": [ {…}, {…}, … ] }

The backend persists the event, calls the detector, and returns the result.
If the detector fails the event row records the failure and the response
includes a `_warning` field — the risk score is NEVER silently set to zero.
"""
from flask import Blueprint, request, jsonify
from services.event_processor import EventProcessor

bp_events = Blueprint("events", __name__, url_prefix="/api/v1/events")


@bp_events.route("", methods=["POST"])
def ingest_events():
    """
    Ingest one or more normalised network events.

    Single event body:
        { "src_ip": "192.168.1.105", "dst_ip": "198.51.100.77", … }

    Batch body:
        { "events": [ {…}, {…} ] }

    Returns the AI evaluation result for each event, including any alert
    that was generated and the XAI explanation.
    """
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    processor = EventProcessor.get_instance()

    # --- Batch format ---
    if "events" in data and isinstance(data["events"], list):
        events_list = data["events"]
        if not events_list:
            return jsonify({"error": "The 'events' array is empty"}), 400
        result = processor.ingest_batch(events_list)
        return jsonify(result), 201

    # --- Single event (the dict itself is the event) ---
    # Minimal validation: must have at least src_ip or saddr
    if not (data.get("src_ip") or data.get("saddr")):
        return jsonify({
            "error": "Missing required field: provide at least 'src_ip' (or 'saddr')"
        }), 400

    result = processor.ingest(data)
    status_code = 201 if result.get("ai_processed") else 202  # 202 if AI didn't run
    return jsonify(result), status_code
