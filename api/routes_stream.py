"""
Real-time update routes: SSE live stream + simulation controls.
================================================================
Provides Server-Sent Events for the first working version (no WebSocket
dependency). The frontend connects via EventSource and receives every
detection result in real time.
"""
import json
import time
from flask import Blueprint, Response, request, jsonify, current_app
from services.event_processor import EventProcessor
from services.simulation_service import SimulationService

bp_stream = Blueprint("stream", __name__, url_prefix="/api/v1/stream")


@bp_stream.route("/live", methods=["GET"])
def live_sse():
    """
    SSE endpoint.  Dashboard opens:
        const es = new EventSource("/api/v1/stream/live");
        es.onmessage = (e) => console.log(JSON.parse(e.data));
    """
    proc = EventProcessor.get_instance()
    q = proc.subscribe()

    def generate():
        yield f"data: {json.dumps({'type': 'connected', 'ts': time.time()})}\n\n"
        try:
            while True:
                try:
                    event = q.get(timeout=25.0)
                    yield f"data: {json.dumps(event, default=str)}\n\n"
                except Exception:
                    yield ": heartbeat\n\n"
        except (GeneratorExit, Exception):
            pass
        finally:
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


# --- Simulation controls (replay BoT-IoT test data) ---
@bp_stream.route("/start", methods=["POST"])
def start_sim():
    sim = SimulationService.get_instance(current_app._get_current_object())
    data = request.get_json(silent=True) or {}
    return jsonify(sim.start(
        scenario=data.get("scenario", "mixed_botiot"),
        speed_fps=float(data.get("speed_fps", 2.0)),
    ))

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
