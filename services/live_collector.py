"""
Network Collector
==================
Observes authorised network traffic (Scapy) or offline PCAP files, extracts header
metadata (services/network_metadata.py — zero decryption, no payload retention),
aggregates bidirectional flows (services/flow_aggregator.py) and forwards both through
the shared EventProcessor.

Operating modes (`mode`, always explicit):
  stopped     nothing running
  starting    sniffer launched, waiting for the capture socket to open
  live        capture socket confirmed open — packets are real observations
  simulation  synthetic packets for development/demos; every event is source="simulation"
  failed      capture could not start or stopped unexpectedly (see last_collector_error)

Threading: the Scapy callback only extracts metadata and enqueues it (bounded queue;
overflow is counted in `packets_dropped`). One worker thread, inside a Flask app
context, aggregates flows, persists events and expires idle flows. Stopping the
collector stops the sniffer, drains the queue and flushes every open flow.

Privileged capture never starts implicitly — only through POST /api/v1/collector/start,
which requires an ADMIN session, an explicitly selected interface, and that interface to
be on COLLECTOR_ALLOWED_INTERFACES when that list is configured.
"""
import os
import queue
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from config import Config
from core.models import (
    EVENT_NETWORK_FLOW, EVENT_NETWORK_PACKET, SOURCE_LIVE, SOURCE_PCAP, SOURCE_SIMULATION,
)
from services import network_metadata, zeek_tls
from services.flow_aggregator import FlowAggregator
from services.tls_metadata import capabilities as tls_capabilities

try:
    from scapy.all import AsyncSniffer, conf, get_if_list
    from scapy.utils import PcapReader
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - hosts without scapy
    AsyncSniffer = conf = get_if_list = PcapReader = None
    SCAPY_AVAILABLE = False

MODE_STOPPED, MODE_STARTING, MODE_LIVE, MODE_SIMULATION, MODE_FAILED = (
    "stopped", "starting", "live", "simulation", "failed",
)
_ACTIVE_MODES = (MODE_STARTING, MODE_LIVE, MODE_SIMULATION)
_BPF_ALLOWED = re.compile(r"^[A-Za-z0-9 .:/()!&|<>=\-\[\]]{1,200}$")
PCAP_MAGICS = (
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",   # pcap (µs), both byte orders
    b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",   # pcap (ns)
    b"\x0a\x0d\x0d\x0a",                        # pcapng section header
)


class PcapValidationError(ValueError):
    pass


def capture_precheck() -> Dict[str, Any]:
    """Whether this host can open a live capture socket at all (driver/library level)."""
    if not SCAPY_AVAILABLE:
        return {"available": False, "reason": "Scapy is not installed."}
    listener = getattr(conf, "L2listen", None)
    # Scapy installs the *class* _NotAvailableSocket as a placeholder when no provider exists.
    name = getattr(listener, "__name__", None) or type(listener).__name__
    if listener is not None and name == "_NotAvailableSocket":
        # On Windows this means Npcap/WinPcap (wpcap.dll) is missing.
        return {"available": False, "reason": f"No packet-capture provider: {listener}. Install Npcap (Windows) or libpcap."}
    return {"available": True, "reason": None}


def validate_pcap_header(path: str) -> None:
    with open(path, "rb") as fh:
        magic = fh.read(4)
    if magic not in PCAP_MAGICS:
        raise PcapValidationError("File is not a pcap/pcapng capture (unrecognised header).")


class LiveCollector:
    _instance: Optional["LiveCollector"] = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "LiveCollector":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self._app = None
        self._state_lock = threading.Lock()   # serialises start/stop (no double collectors)
        self.mode: str = MODE_STOPPED
        self.is_running: bool = False
        self.active_interface: Optional[str] = None
        self.bpf_filter: str = "ip"
        self.source: Optional[str] = None
        self.live_capture_verified = False     # a live start succeeded in this process
        self.start_time: Optional[float] = None
        self.stopped_at: Optional[float] = None
        self.last_collector_error: Optional[str] = None
        self.last_processing_error: Optional[str] = None
        self.last_pcap: Optional[Dict[str, Any]] = None
        self._reset_run_counters()
        self._sniffer = None
        self._capture_thread: Optional[threading.Thread] = None   # simulation generator
        self._worker: Optional[threading.Thread] = None
        self._queue: "queue.Queue" = queue.Queue(maxsize=Config.COLLECTOR_QUEUE_SIZE)
        self._stop_event = threading.Event()
        self._ingest_callback: Optional[Callable[[Dict[str, Any]], Any]] = None
        self.packet_events_enabled = Config.COLLECTOR_PACKET_EVENTS
        self.aggregator = self._new_aggregator()

    # ------------------------------------------------------------------
    # Wiring
    # ------------------------------------------------------------------
    def init_app(self, app):
        """Bind the Flask app whose context background ingestion runs in."""
        self._app = app
        self.packet_events_enabled = app.config.get("COLLECTOR_PACKET_EVENTS", Config.COLLECTOR_PACKET_EVENTS)

    def set_ingest_callback(self, callback: Optional[Callable[[Dict[str, Any]], Any]]):
        """Test/extension hook: receives every packet/flow dict instead of the EventProcessor."""
        self._ingest_callback = callback

    def _cfg(self, name):
        if self._app is not None:
            return self._app.config.get(name, getattr(Config, name))
        return getattr(Config, name)

    def _new_aggregator(self) -> FlowAggregator:
        return FlowAggregator(
            idle_timeout=self._cfg("FLOW_IDLE_TIMEOUT_S"),
            active_timeout=self._cfg("FLOW_ACTIVE_TIMEOUT_S"),
            max_flows=self._cfg("FLOW_MAX_TRACKED"),
        )

    def _reset_run_counters(self):
        """Every counter in get_status() describes the current (or last) run."""
        self.processing_errors_count = 0
        self.corrupted_packets_count = 0
        self.last_processing_error = None
        self.collector_errors_count = 0
        self.packets_captured = 0       # packets observed with usable IP headers
        self.bytes_captured = 0
        self.packets_dropped = 0        # queue overflow — observed but not processed
        self.events_ingested = 0        # packet + flow events stored
        self.packet_events_ingested = 0
        self.flow_events_ingested = 0
        self.flows_completed = 0

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    @staticmethod
    def extract_packet_metadata(pkt) -> Optional[Dict[str, Any]]:
        return network_metadata.extract_packet_metadata(pkt)

    def _submit(self, payload: Dict[str, Any], event_type: str, source: str, dedup_key: Optional[str] = None):
        if self._ingest_callback:
            return self._ingest_callback({**payload, "event_type": event_type, "source": source})
        from services.event_processor import EventProcessor
        proc = EventProcessor.get_instance()
        from flask import has_app_context
        if has_app_context():
            return proc.submit(payload, event_type=event_type, source=source, dedup_key=dedup_key)
        if self._app is None:
            return {"error": "Collector is not bound to the application (init_app was not called)."}
        with self._app.app_context():
            return proc.submit(payload, event_type=event_type, source=source, dedup_key=dedup_key)

    def _record(self, result, kind: str, stats: Optional[Dict[str, int]] = None) -> bool:
        """Count one submission outcome. Only a stored event counts as ingested."""
        ok = isinstance(result, dict) and "error" not in result
        if ok:
            if stats is None:
                self.events_ingested += 1
                if kind == EVENT_NETWORK_FLOW:
                    self.flow_events_ingested += 1
                else:
                    self.packet_events_ingested += 1
            else:
                stats["events_ingested"] += 1
                stats["flow_events" if kind == EVENT_NETWORK_FLOW else "packet_events"] += 1
                if result.get("alert"):
                    stats["threats_detected"] += 1
        else:
            err = result.get("error") if isinstance(result, dict) else f"Unexpected ingest result: {type(result).__name__}"
            if stats is None:
                self.processing_errors_count += 1
                self.last_processing_error = str(err)
            else:
                stats["processing_errors"] += 1
                stats["last_error"] = str(err)
        return ok

    def _submit_counted(self, payload, event_type, source, stats=None):
        try:
            res = self._submit(payload, event_type, source,
                               dedup_key=f"flow:{payload['flow_id']}" if event_type == EVENT_NETWORK_FLOW else None)
        except Exception as exc:  # one failing event never stops the pipeline
            res = {"error": f"{type(exc).__name__}: {exc}"}
        return self._record(res, event_type, stats)

    def _emit_flows(self, flows: List[Dict[str, Any]], source: str, stats=None, enrich=None):
        for flow in flows:
            if enrich:
                enrich(flow)
            if stats is None:
                self.flows_completed += 1
            else:
                stats["flows"] += 1
            self._submit_counted(flow, EVENT_NETWORK_FLOW, source, stats)

    def _handle_metadata(self, meta: Dict[str, Any], source: str):
        """Aggregate one observed packet and store its packet event (when enabled)."""
        flow_id, completed = self.aggregator.update(meta)
        if flow_id:
            meta["flow_id"] = flow_id
        if self.packet_events_enabled or self._ingest_callback:
            self._submit_counted(meta, EVENT_NETWORK_PACKET, source)
        self._emit_flows(completed, source)

    def _observe(self, meta: Dict[str, Any], source: str):
        self.packets_captured += 1
        self.bytes_captured += meta.get("bytes", 0)
        if self._worker is not None and self._worker.is_alive():
            try:
                self._queue.put_nowait((meta, source))
            except queue.Full:
                self.packets_dropped += 1
        else:
            self._handle_metadata(meta, source)

    def _on_packet(self, pkt):
        """Scapy callback (sniffer thread). Must never raise."""
        if not self.is_running:
            return
        try:
            meta = self.extract_packet_metadata(pkt)
            if not meta:
                self.corrupted_packets_count += 1
                return
            self._observe(meta, self.source or SOURCE_LIVE)
        except Exception as exc:
            self.collector_errors_count += 1
            self.last_collector_error = f"Packet handling error: {type(exc).__name__}: {exc}"

    # ------------------------------------------------------------------
    # Worker
    # ------------------------------------------------------------------
    def _start_worker(self):
        self._worker = threading.Thread(target=self._worker_loop, name="collector-worker", daemon=True)
        self._worker.start()

    def _worker_loop(self):
        last_tick = time.time()
        ticks = 0
        while True:
            try:
                meta, source = self._queue.get(timeout=0.5)
                self._handle_metadata(meta, source)
            except queue.Empty:
                if self._stop_event.is_set():
                    break
            except Exception as exc:
                self.processing_errors_count += 1
                self.last_processing_error = f"Worker error: {type(exc).__name__}: {exc}"
            now = time.time()
            if now - last_tick >= 1.0:
                last_tick = now
                try:
                    self._emit_flows(self.aggregator.expire(now), self.source or SOURCE_LIVE)
                except Exception as exc:
                    self.processing_errors_count += 1
                    self.last_processing_error = f"Flow expiry error: {type(exc).__name__}: {exc}"
                self._watch_sniffer()
                ticks += 1
                if ticks % 2 == 0 or self.mode == MODE_FAILED:
                    self._broadcast_status()

    def _watch_sniffer(self):
        """Detect a live capture that died after starting (interface down, driver error)."""
        if self.mode != MODE_LIVE or self._sniffer is None:
            return
        thread = getattr(self._sniffer, "thread", None)
        if thread is not None and not thread.is_alive() and not self._stop_event.is_set():
            exc = getattr(self._sniffer, "exception", None)
            self.mode = MODE_FAILED
            self.is_running = False
            self.collector_errors_count += 1
            self.last_collector_error = (
                f"Live capture stopped unexpectedly: {type(exc).__name__}: {exc}" if exc else "Live capture stopped unexpectedly."
            )
            self._stop_event.set()

    def _broadcast_status(self):
        try:
            from services.event_processor import EventProcessor
            EventProcessor.get_instance().broadcast("collector_status", self.get_status())
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Start / stop
    # ------------------------------------------------------------------
    def list_interfaces(self) -> List[Dict[str, Any]]:
        if not SCAPY_AVAILABLE:
            return []
        allowed = self._cfg("COLLECTOR_ALLOWED_INTERFACES") or []
        out = []
        try:
            for iface in conf.ifaces.values():
                name = str(iface.name)
                ips = []
                by_family = getattr(iface, "ips", None)
                if isinstance(by_family, dict):
                    for addrs in by_family.values():
                        ips.extend(str(a) for a in addrs)
                out.append({
                    "name": name,
                    "description": str(getattr(iface, "description", "") or name),
                    "ips": ips,
                    "allowed": (not allowed) or name in allowed,
                })
        except Exception:
            try:
                out = [{"name": str(i), "description": str(i), "ips": [], "allowed": (not allowed) or str(i) in allowed}
                       for i in get_if_list()]
            except Exception:
                return []
        return sorted(out, key=lambda i: (not i["allowed"], i["name"].lower()))

    def _fail(self, message: str) -> Dict[str, Any]:
        self.mode = MODE_FAILED
        self.is_running = False
        self.collector_errors_count += 1
        self.last_collector_error = message
        return {"status": "error", "mode": MODE_FAILED, "error": message}

    def start_live_capture(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "ip",
        count: int = 0,
        simulate: bool = False,
        allow_fallback: bool = False,
    ) -> Dict[str, Any]:
        """
        Start live capture on an explicitly selected interface, or (simulate=True) the
        synthetic generator. Live mode is reported only after the capture socket opened.
        allow_fallback=True switches to *labelled* simulation when live capture fails.
        """
        if not self._state_lock.acquire(blocking=False):
            return {"status": "busy", "mode": self.mode, "error": "A start/stop request is already in progress."}
        try:
            if self.mode in _ACTIVE_MODES:
                return {
                    "status": "already_running",
                    "mode": self.mode,
                    "interface": self.active_interface,
                    "packets_captured": self.packets_captured,
                    "events_ingested": self.events_ingested,
                }
            bpf_filter = (bpf_filter or "ip").strip()
            if not _BPF_ALLOWED.match(bpf_filter):
                return {"status": "error", "mode": self.mode, "error": "Invalid capture filter."}

            self._prepare_run(bpf_filter)
            if simulate:
                return self._start_simulation("Simulation explicitly requested")

            # --- Live capture ---------------------------------------------------
            if not interface:
                return self._fail("Select a capture interface explicitly; live capture never starts on a default interface.")
            names = {i["name"]: i for i in self.list_interfaces()}
            if interface not in names:
                return self._fail(f"Interface '{interface}' was not found on this host.")
            if not names[interface]["allowed"]:
                return self._fail(f"Interface '{interface}' is not in COLLECTOR_ALLOWED_INTERFACES.")
            pre = capture_precheck()
            if not pre["available"]:
                result = self._fail(f"Live capture unavailable: {pre['reason']}")
                return self._fallback(result) if allow_fallback else result

            self.mode = MODE_STARTING
            self.active_interface = interface
            self.source = SOURCE_LIVE
            started = threading.Event()
            try:
                sniffer = AsyncSniffer(
                    iface=interface, filter=bpf_filter, prn=self._on_packet,
                    count=count, store=False, started_callback=started.set,
                )
                self.is_running = True   # the callback ignores packets until this is set
                sniffer.start()
            except Exception as exc:
                self._sniffer = None
                result = self._fail(f"Scapy startup failed: {type(exc).__name__}: {exc}")
                return self._fallback(result) if allow_fallback else result

            deadline = time.time() + float(self._cfg("COLLECTOR_START_TIMEOUT_S"))
            thread = getattr(sniffer, "thread", None)
            while time.time() < deadline and not started.is_set():
                if thread is not None and not thread.is_alive():
                    break
                time.sleep(0.05)
            if not started.is_set():
                exc = getattr(sniffer, "exception", None)
                try:
                    if getattr(sniffer, "running", False):
                        sniffer.stop(join=False)
                except Exception:
                    pass
                self._sniffer = None
                reason = f"{type(exc).__name__}: {exc}" if exc else "capture socket did not open before the timeout"
                result = self._fail(f"Live capture failed to start on '{interface}': {reason}")
                return self._fallback(result) if allow_fallback else result

            self._sniffer = sniffer
            self.mode = MODE_LIVE
            self.live_capture_verified = True
            self.last_collector_error = None
            self._start_worker()
            self._broadcast_status()
            return {"status": "started", "mode": MODE_LIVE, "interface": interface,
                    "filter": bpf_filter, "scapy_live": True}
        finally:
            self._state_lock.release()

    def _prepare_run(self, bpf_filter: str):
        self.bpf_filter = bpf_filter
        self._reset_run_counters()
        self.aggregator = self._new_aggregator()
        self._queue = queue.Queue(maxsize=self._cfg("COLLECTOR_QUEUE_SIZE"))
        self._stop_event.clear()
        self.start_time = time.time()
        self.stopped_at = None

    def _fallback(self, failure: Dict[str, Any]) -> Dict[str, Any]:
        res = self._start_simulation(f"Fallback after live capture failure: {failure['error']}")
        if res.get("status") == "started":
            res["warning"] = f"{failure['error']} — running in SIMULATION mode (synthetic traffic, not live capture)."
            res["interface"] = "simulated (fallback)"
            # Keep the live failure visible alongside the simulation.
            self.last_collector_error = failure["error"]
        return res

    def _start_simulation(self, reason: str) -> Dict[str, Any]:
        try:
            self._sniffer = None
            self.source = SOURCE_SIMULATION
            self.active_interface = "simulated"
            self.is_running = True
            self.mode = MODE_SIMULATION
            self._start_worker()
            self._start_simulated_worker()
            self._broadcast_status()
            return {"status": "started", "mode": MODE_SIMULATION, "interface": "simulated",
                    "filter": self.bpf_filter, "scapy_live": False, "reason": reason}
        except Exception as exc:
            return self._fail(f"Failed to start simulation worker: {exc}")

    def _start_simulated_worker(self):
        """Synthetic packet generator — every packet is labelled source=simulation."""
        def _worker():
            import random
            while not self._stop_event.is_set():
                try:
                    meta = {
                        "timestamp": time.time(),
                        "ip_version": 4,
                        "src_ip": f"192.168.1.{random.choice([18, 45, 105, 77])}",
                        "dst_ip": random.choice(["142.250.190.46", "172.217.16.206", "45.33.32.156"]),
                        "src_port": random.randint(49152, 65535),
                        "dst_port": random.choice([443, 80, 53, 22]),
                        "protocol": "TCP",
                        "bytes": random.randint(120, 1500),
                        "pkts": 1,
                        "duration": 0.0,
                        "tcp_flags": "PA",
                        "simulated": True,
                    }
                    meta["direction"] = network_metadata.classify_direction(meta["src_ip"], meta["dst_ip"])
                    self._observe(meta, SOURCE_SIMULATION)
                except Exception as exc:
                    self.collector_errors_count += 1
                    self.last_collector_error = f"Simulation error: {exc}"
                if self._stop_event.wait(timeout=1.0):
                    break

        self._capture_thread = threading.Thread(target=_worker, name="collector-simulation", daemon=True)
        self._capture_thread.start()

    def stop_capture(self) -> Dict[str, Any]:
        """Stop capture/simulation, drain queued packets and flush every open flow."""
        with self._state_lock:
            if self.mode not in _ACTIVE_MODES and not self.is_running:
                prev = self.mode
                # A capture that FAILED mid-run may still hold queued packets and open flows.
                self._stop_event.set()
                self._join_threads([])
                flushed = self._drain_and_flush()
                self.mode = MODE_STOPPED  # clears a FAILED state
                return {"status": "not_running", "mode": MODE_STOPPED, "previous_mode": prev,
                        "flows_flushed": flushed}

            prev_mode = self.mode
            self.is_running = False
            self._stop_event.set()
            errors = []
            if self._sniffer is not None:
                try:
                    if getattr(self._sniffer, "running", False):
                        self._sniffer.stop(join=True)
                except Exception as exc:
                    errors.append(f"Sniffer stop failed: {type(exc).__name__}: {exc}")
                self._sniffer = None
            self._join_threads(errors)
            self._drain_and_flush()

            if errors:
                self.collector_errors_count += len(errors)
                self.last_collector_error = "; ".join(errors)
            self.mode = MODE_STOPPED
            self.stopped_at = time.time()
            duration = round(self.stopped_at - (self.start_time or self.stopped_at), 2)
            self._broadcast_status()
            return {
                "status": "stopped",
                "previous_mode": prev_mode,
                "packets_captured": self.packets_captured,
                "events_ingested": self.events_ingested,
                "flows_completed": self.flows_completed,
                "bytes_captured": self.bytes_captured,
                "duration_s": duration,
                "errors": errors,
            }

    def _join_threads(self, errors: List[str]):
        for t in (self._capture_thread, self._worker):
            if t is not None and t.is_alive():
                t.join(timeout=5.0)
                if t.is_alive():
                    errors.append(f"{t.name} did not stop within 5s")
        self._capture_thread = None
        self._worker = None

    def _drain_and_flush(self) -> int:
        """Process anything still queued inline, then flush every open flow. Returns flows flushed."""
        while True:
            try:
                meta, source = self._queue.get_nowait()
            except queue.Empty:
                break
            self._handle_metadata(meta, source)
        flows = self.aggregator.flush("collector_stopped")
        self._emit_flows(flows, self.source or SOURCE_LIVE)
        return len(flows)

    # ------------------------------------------------------------------
    # Offline PCAP processing (same metadata → flow → EventProcessor path)
    # ------------------------------------------------------------------
    def process_pcap_file(
        self,
        pcap_path: str,
        max_packets: Optional[int] = None,
        auto_ingest: bool = True,
    ) -> Dict[str, Any]:
        if not os.path.exists(pcap_path):
            raise FileNotFoundError("PCAP file not found.")
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for PCAP parsing.")
        validate_pcap_header(pcap_path)

        zeek = {"available": False, "records": {}, "error": None}
        zeek_bin = self._cfg("ZEEK_BIN")
        if auto_ingest and zeek_tls.zeek_path(zeek_bin):
            zeek = zeek_tls.run_on_pcap(pcap_path, zeek_bin, int(self._cfg("ZEEK_TIMEOUT_S")))
        zeek_records = zeek.get("records") or {}

        def enrich(flow):
            key = (flow["src_ip"], flow["src_port"], flow["dst_ip"], flow["dst_port"])
            rec = zeek_records.get(key)
            if rec:
                details = flow["details"]
                details["tls"] = {**details.get("tls", {}), **{f"zeek_{k}" if k != "extraction_source" else k: v for k, v in rec.items()}}
                details["tls"]["extraction_source"] = "builtin+zeek" if "client_hello_complete" in details["tls"] else "zeek"

        stats = {"events_ingested": 0, "packet_events": 0, "flow_events": 0, "flows": 0,
                 "threats_detected": 0, "processing_errors": 0, "last_error": None}
        aggregator = self._new_aggregator()
        total = parsed = malformed = tls_handshakes = 0
        samples: List[Dict[str, Any]] = []
        error = None
        limit = max_packets or int(self._cfg("MAX_PCAP_PACKETS"))
        try:
            with PcapReader(pcap_path) as reader:
                for pkt in reader:
                    if total >= limit:
                        break
                    total += 1
                    meta = self.extract_packet_metadata(pkt)
                    if not meta:
                        malformed += 1
                        continue
                    parsed += 1
                    if meta.get("tls"):
                        tls_handshakes += 1
                    if len(samples) < 5:
                        samples.append(dict(meta))
                    flow_id, completed = aggregator.update(meta)
                    if flow_id:
                        meta["flow_id"] = flow_id
                    if auto_ingest:
                        if self.packet_events_enabled:
                            self._submit_counted(meta, EVENT_NETWORK_PACKET, SOURCE_PCAP, stats)
                        self._emit_flows(completed, SOURCE_PCAP, stats, enrich)
        except Exception as exc:
            error = f"Failed to parse PCAP file: {type(exc).__name__}"
        # Flows built from packets read so far are real observations even after a parse error.
        remaining = aggregator.flush("pcap_end")
        if auto_ingest:
            self._emit_flows(remaining, SOURCE_PCAP, stats, enrich)
        else:
            stats["flows"] = aggregator.flows_emitted

        summary = {
            "status": "error" if error else "completed",
            "file": os.path.basename(pcap_path),
            "total_packets": total,
            "packets_parsed": parsed,
            "malformed_packets": malformed,
            "truncated_at_limit": total >= limit,
            "events_ingested": stats["events_ingested"],
            "packet_events": stats["packet_events"],
            "flow_events": stats["flow_events"],
            "flows": stats["flows"],
            "threats_detected": stats["threats_detected"],
            "processing_errors": stats["processing_errors"],
            "tls_handshakes": tls_handshakes,
            "zeek": {"available": zeek.get("available", False), "tls_records": len(zeek_records), "error": zeek.get("error")},
            "sample_metadata": samples,
            "processed_at": time.time(),
        }
        if error:
            summary["error"] = error
        if stats["last_error"]:
            summary["last_processing_error"] = stats["last_error"]
        self.last_pcap = {k: v for k, v in summary.items() if k != "sample_metadata"}
        return summary

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def get_status(self) -> Dict[str, Any]:
        running = self.mode in (MODE_LIVE, MODE_SIMULATION) and self.is_running
        uptime = round(time.time() - self.start_time, 2) if (running and self.start_time) else 0.0
        pps = round(self.packets_captured / max(uptime, 0.001), 1) if running else 0.0
        pre = capture_precheck()
        zeek = zeek_tls.status(self._cfg("ZEEK_BIN"))
        return {
            "mode":                    self.mode,
            "is_running":              running,
            "is_capturing":            running,
            "is_live":                 self.mode == MODE_LIVE,
            "is_simulated":            self.mode == MODE_SIMULATION,
            "source":                  self.source if running else None,
            "active_interface":        self.active_interface if running or self.mode == MODE_STARTING else None,
            "bpf_filter":              self.bpf_filter,
            "packets_captured":        self.packets_captured,
            "bytes_captured":          self.bytes_captured,
            "packets_dropped":         self.packets_dropped,
            "events_ingested":         self.events_ingested,
            "packet_events_ingested":  self.packet_events_ingested,
            "flow_events_ingested":    self.flow_events_ingested,
            "flows_completed":         self.flows_completed,
            "active_flows":            self.aggregator.active_flows,
            "packet_events_enabled":   bool(self.packet_events_enabled),
            "queue_depth":             self._queue.qsize(),
            "corrupted_packets":       self.corrupted_packets_count,
            "collector_errors":        self.collector_errors_count,
            "processing_errors":       self.processing_errors_count,
            "last_collector_error":    self.last_collector_error,
            "last_processing_error":   self.last_processing_error,
            "uptime_seconds":          uptime,
            "packets_per_sec":         pps,
            "throughput_pps":          pps,
            "scapy_available":         SCAPY_AVAILABLE,
            "live_capture_available":  pre["available"],
            "live_capture_unavailable_reason": pre["reason"],
            "live_capture_verified":   self.live_capture_verified,
            "allowed_interfaces":      self._cfg("COLLECTOR_ALLOWED_INTERFACES") or None,
            "flow_config": {
                "idle_timeout_s": self.aggregator.idle_timeout,
                "active_timeout_s": self.aggregator.active_timeout,
                "max_flows": self.aggregator.max_flows,
            },
            "tls": {**tls_capabilities(), "zeek": zeek},
            "last_pcap":               self.last_pcap,
        }
