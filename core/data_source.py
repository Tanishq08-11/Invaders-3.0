"""Where the events currently being processed come from, as reported to the dashboard."""


def current_data_source() -> str:
    """'live' for real packet capture, 'replay' for simulated / dataset replay, else 'unknown'."""
    from services.live_collector import LiveCollector
    from services.simulation_service import SimulationService

    mode = LiveCollector.get_instance().mode
    if mode == "live":
        return "live"
    # Dataset replay (BoT-IoT via /api/v1/stream) only counts if it was ever started.
    sim = SimulationService._instance
    if mode == "simulation" or (sim is not None and sim.is_running):
        return "replay"
    return "unknown"
