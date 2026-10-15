"""
Real-time updates (Server-Sent Events) + dataset replay controls
=================================================================
GET /api/v1/stream/live — SOC only (SECURITY_ANALYST / ADMIN, enforced by install_soc_guard).

Every message is one JSON object on a `data:` line, preceded by an `id:` line:
    {"id": 42, "type": "<type>", "ts": "<ISO-8601>", "data": {…}}

types:
  hello              sent once on connect: collector + detector status snapshot
  event              a stored network_record / network_flow / application_activity event
  alert              an alert created from a genuine detector result
  correlation        a new application ↔ network correlation
  collector_status   collector mode/counters (every ~2 s while it runs, and on changes)

Individual packet events are not streamed (they surface through their flow and the
collector counters). Messages are notifications; clients re-read REST endpoints for
authoritative state, so a message received twice cannot create a duplicate record.
Subscribers are capped (SSE_MAX_SUBSCRIBERS); a client that stops reading is dropped.
"""
import json
import queue

from flask import Blueprint, Response, current_app, jsonify, request

from services.event_processor import EventProcessor
from services.live_collector import LiveCollector
from services.simulation_service import SimulationService

bp_stream = Blueprint("stream", __name__, url_prefix="/api/v1/stream")


def _sse(msg) -> str:
    return f"id: {msg['id']}\ndata: {json.dumps(msg, default=str)}\n\n"


@bp_stream.route("/live", methods=["GET"])
def live_sse():
    proc = EventProcessor.get_instance()
    q = proc.subscribe(max_subscribers=current_app.config.get("SSE_MAX_SUBSCRIBERS", 50))
    if q is None:
        return jsonify({"detail": "Too many live-update connections; the dashboard falls back to polling."}), 503
    heartbeat = float(current_app.config.get("SSE_HEARTBEAT_S", 15))
    hello = {
        "id": 0,
        "type": "hello",
        "data": {
            "collector": LiveCollector.get_instance().get_status(),
            "detector": proc.detector_status(),
        },
    }

    def generate():
        try:
            yield "retry: 5000\n\n"
            yield _sse(hello)
            while True:
                try:
                    yield _sse(q.get(timeout=heartbeat))
                except queue.Empty:
                    yield ": heartbeat\n\n"
        finally:
            # Runs on client disconnect (GeneratorExit) and on server shutdown.
            proc.unsubscribe(q)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# --- Dataset replay controls (BoT-IoT test rows, source="dataset_replay"; ADMIN for POST) ---
@bp_stream.route("/start", methods=["POST"])
def start_sim():
    sim = SimulationService.get_instance(current_app._get_current_object())
    data = request.get_json(silent=True) or {}
    try:
        speed = float(data.get("speed_fps", 2.0))
    except (TypeError, ValueError):
        return jsonify({"error": "speed_fps must be a number"}), 400
    return jsonify(sim.start(scenario=data.get("scenario", "mixed_botiot"), speed_fps=speed))


@bp_stream.route("/pause", methods=["POST"])
def pause_sim():
    return jsonify(SimulationService.get_instance().pause())


@bp_stream.route("/resume", methods=["POST"])
def resume_sim():
    return jsonify(SimulationService.get_instance().resume())


@bp_stream.route("/stop", methods=["POST"])
def stop_sim():
    return jsonify(SimulationService.get_instance().stop())


@bp_stream.route("/status", methods=["GET"])
def sim_status():
    return jsonify(SimulationService.get_instance().get_status())
