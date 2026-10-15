"""Where the events currently being processed come from, as reported to the dashboard."""


def current_data_source() -> str:
    """
    live        the collector is capturing real packets
    simulation  the collector is generating synthetic packets
    replay      the BoT-IoT dataset replay (/api/v1/stream/start) is running
    otherwise   the source of the most recent network event (pcap, live, …) or 'unknown'
    """
    from services.live_collector import LiveCollector
    from services.simulation_service import SimulationService

    mode = LiveCollector.get_instance().mode
    if mode == "live":
        return "live"
    if mode == "simulation":
        return "simulation"
    sim = SimulationService._instance
    if sim is not None and sim.is_running:
        return "replay"
    try:
        from core.database import db
        from core.models import NETWORK_EVENT_TYPES, Event, source_to_data_source
        latest = (
            db.session.query(Event.source)
            .filter(Event.event_type.in_(NETWORK_EVENT_TYPES))
            .order_by(Event.id.desc())
            .limit(1)
            .scalar()
        )
        return source_to_data_source(latest)
    except Exception:
        return "unknown"
