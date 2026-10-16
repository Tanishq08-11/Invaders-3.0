"""
Background scheduler for sweep-based detectors (D11 device silence, D25 telemetry health)
==========================================================================================
One daemon thread per host calls DetectionEngine.sweep() every TELEMETRY_SWEEP_S seconds
(minimum 10 s) inside the Flask app context. Never a tight loop: it waits on an Event.

Exactly-one guarantees:
  • in-process: a module-level lock + singleton thread;
  • Flask debug reloader: the watcher (parent) process never starts it — only the child
    that serves requests (WERKZEUG_RUN_MAIN=true);
  • multiple worker processes: an OS file lock in INSTANCE_DIR; workers that cannot take
    it do not schedule.
No duplicate signals: DetectionEngine._persist() skips any dedup_key already stored
(D11 per silence episode, D25 per issue per hour), and sweeps never create alerts.
"""
import logging
import os
import threading

log = logging.getLogger(__name__)
MIN_INTERVAL_S = 10

_lock = threading.Lock()
_thread = None
_stop = threading.Event()
_lock_file = None
last_run = {"at": None, "signals": 0, "error": None, "runs": 0}


def _acquire_host_lock(instance_dir: str) -> bool:
    global _lock_file
    try:
        os.makedirs(instance_dir, exist_ok=True)
        fh = open(os.path.join(instance_dir, "detection_sweep.lock"), "a+")
        if os.name == "nt":
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        _lock_file = fh
        return True
    except OSError:
        return False


def run_once(app) -> dict:
    from core.database import db
    from services.detection.engine import DetectionEngine
    with app.app_context():
        try:
            out = DetectionEngine.get_instance().sweep()
            db.session.commit()
            last_run.update(signals=len(out["signals"]), error=None)
            if out["signals"]:
                from services.event_processor import EventProcessor
                for sig in out["signals"]:
                    EventProcessor.get_instance().broadcast("detection_signal", sig)
            return out
        except Exception as exc:
            db.session.rollback()
            last_run["error"] = f"{type(exc).__name__}: {exc}"
            log.exception("[sweep] detection sweep failed")
            return {"error": last_run["error"]}
        finally:
            from datetime import datetime, timezone
            last_run["at"] = datetime.now(timezone.utc).isoformat()
            last_run["runs"] += 1
            db.session.remove()


def _loop(app, interval: float):
    while not _stop.wait(interval):
        run_once(app)


def start(app) -> bool:
    """Start the scheduler if this process should own it. Returns True when started."""
    global _thread
    cfg = app.config
    if cfg.get("TESTING") or not cfg.get("DETECTION_SWEEP_ENABLED", True) or not cfg.get("DETECTION_ENABLED", True):
        return False
    if cfg.get("DEBUG") and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return False   # reloader watcher process — the serving child starts it
    with _lock:
        if _thread is not None and _thread.is_alive():
            return False
        if not _acquire_host_lock(cfg.get("INSTANCE_DIR") or "instance"):
            log.info("[sweep] another process owns the detection sweep scheduler")
            return False
        interval = max(MIN_INTERVAL_S, float(cfg.get("TELEMETRY_SWEEP_S") or 60))
        _stop.clear()
        _thread = threading.Thread(target=_loop, args=(app, interval), name="detection-sweep", daemon=True)
        _thread.start()
        log.info("[sweep] detection sweep every %.0f s", interval)
        return True


def stop():
    _stop.set()


def status() -> dict:
    return {"running": bool(_thread and _thread.is_alive()), **last_run}
