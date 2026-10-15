"""
Live Network Metadata Collector
================================
Captures live network traffic from active interfaces (WiFi, Ethernet) or PCAP files,
extracts unencrypted 5-tuple packet header metadata (ZERO payload decryption),
and automatically feeds it into the EventProcessor pipeline.

Features:
  1. Live interface sniffing via Scapy (AsyncSniffer).
  2. Offline PCAP / PCAPNG packet stream ingestion.
  3. Explicit operating modes: "stopped", "live", "simulation".
  4. Safe fallback driver for headless CI / review environments without root / Npcap.
  5. Accurate error tracking: separate packet, ingestion, and processing error counters.
"""
import os
import time
import threading
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timezone

# Optional Scapy import with graceful fallback
try:
    from scapy.all import sniff, AsyncSniffer, IP, IPv6, TCP, UDP, get_if_list, conf
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


class LiveCollector:
    """
    Background network packet collector and metadata extractor.
    Tracks operating modes: "stopped", "live", "simulation".
    """
    _instance: Optional["LiveCollector"] = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "LiveCollector":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self.is_running: bool = False
        self.mode: str = "stopped"  # "stopped", "live", "simulation"
        self.active_interface: Optional[str] = None
        self.bpf_filter: str = "ip"
        self.packets_captured: int = 0
        self.bytes_captured: int = 0
        self.events_ingested: int = 0
        self.corrupted_packets_count: int = 0
        self.collector_errors_count: int = 0
        self.processing_errors_count: int = 0
        self.last_collector_error: Optional[str] = None
        self.last_processing_error: Optional[str] = None
        self.start_time: Optional[float] = None
        self._sniffer = None
        self._capture_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._ingest_callback: Optional[Callable[[Dict[str, Any]], Any]] = None

    def set_ingest_callback(self, callback: Optional[Callable[[Dict[str, Any]], Any]]):
        """Sets callback function invoked with every extracted packet metadata."""
        self._ingest_callback = callback

    def _default_ingest(self, metadata: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Feeds extracted metadata directly into EventProcessor."""
        try:
            from services.event_processor import EventProcessor
            proc = EventProcessor.get_instance()
            return proc.ingest(metadata)
        except Exception as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Packet Metadata Extractor (Zero Decryption)
    # ------------------------------------------------------------------
    @staticmethod
    def extract_packet_metadata(pkt) -> Optional[Dict[str, Any]]:
        """
        Extracts 5-tuple network metadata from a raw packet header.
        NEVER decrypts or inspects packet payload content.
        Safely handles corrupted or malformed packets without throwing exceptions.
        """
        if not SCAPY_AVAILABLE:
            return None

        try:
            # 1. IP Layer
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            if pkt.haslayer(IP):
                src_ip = str(pkt[IP].src)
                dst_ip = str(pkt[IP].dst)
            elif pkt.haslayer(IPv6):
                src_ip = str(pkt[IPv6].src)
                dst_ip = str(pkt[IPv6].dst)
            else:
                return None  # Ignore non-IP link layer frames

            # 2. Transport Layer
            src_port = 0
            dst_port = 0
            proto = "OTHER"
            if pkt.haslayer(TCP):
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
                proto = "TCP"
            elif pkt.haslayer(UDP):
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
                proto = "UDP"

            # 3. Size & Timing
            pkt_len = int(len(pkt))
            pkt_time = float(getattr(pkt, "time", time.time()))

            return {
                "timestamp": pkt_time,
                "src_ip":    src_ip,
                "dst_ip":    dst_ip,
                "src_port":  src_port,
                "dst_port":  dst_port,
                "protocol":  proto,
                "bytes":     pkt_len,
                "pkts":      1,
                "duration":  0.0,
            }
        except Exception:
            # Corrupted / truncated packet header
            return None

    # ------------------------------------------------------------------
    # Packet Handler Callback
    # ------------------------------------------------------------------
    def _on_packet(self, pkt):
        if not self.is_running:
            return

        try:
            meta = self.extract_packet_metadata(pkt)
            if not meta:
                self.corrupted_packets_count += 1
                return

            self.packets_captured += 1
            self.bytes_captured += meta.get("bytes", 0)

            # Ingest through callback or default EventProcessor
            res = None
            try:
                if self._ingest_callback:
                    res = self._ingest_callback(meta)
                else:
                    res = self._default_ingest(meta)
            except Exception as proc_exc:
                self.processing_errors_count += 1
                self.last_processing_error = str(proc_exc)
                return

            # Detect failure returned as error dictionary
            if isinstance(res, dict) and ("error" in res or res.get("ai_error")):
                self.processing_errors_count += 1
                self.last_processing_error = str(res.get("error") or res.get("ai_error"))
            else:
                self.events_ingested += 1

        except Exception as coll_exc:
            self.collector_errors_count += 1
            self.last_collector_error = str(coll_exc)

    # ------------------------------------------------------------------
    # Live Interface Sniffing & Operating Mode Management
    # ------------------------------------------------------------------
    def start_live_capture(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "ip",
        count: int = 0,
        simulate: bool = False,
        allow_fallback: bool = True
    ) -> Dict[str, Any]:
        """
        Starts live packet capture or simulation.
        Explicitly tracks and distinguishes operating modes:
          - "live": actual Scapy sniffer active on network interface
          - "simulation": simulated event generator active
          - "stopped": capture inactive or startup failed
        """
        if self.is_running:
            return {
                "status": "already_running",
                "mode": self.mode,
                "interface": self.active_interface,
                "packets_captured": self.packets_captured,
                "events_ingested": self.events_ingested
            }

        self.active_interface = interface or (conf.iface.name if SCAPY_AVAILABLE else "default")
        self.bpf_filter = bpf_filter
        self.packets_captured = 0
        self.bytes_captured = 0
        self.events_ingested = 0
        self.start_time = time.time()
        self._stop_event.clear()

        # 1. Explicit Simulation Mode Requested
        if simulate:
            try:
                self._start_simulated_live_worker("Simulation mode explicitly requested")
                self.is_running = True
                self.mode = "simulation"
                return {
                    "status": "started",
                    "mode": "simulation",
                    "interface": "simulated",
                    "filter": self.bpf_filter,
                    "scapy_live": False
                }
            except Exception as sim_exc:
                self.is_running = False
                self.mode = "stopped"
                self.collector_errors_count += 1
                self.last_collector_error = f"Failed to start simulation worker: {sim_exc}"
                return {
                    "status": "error",
                    "mode": "stopped",
                    "error": self.last_collector_error
                }

        # 2. Live Capture Requested
        if SCAPY_AVAILABLE:
            self._sniffer = None
            try:
                sniffer = AsyncSniffer(
                    iface=interface,
                    filter=bpf_filter,
                    prn=self._on_packet,
                    count=count,
                    store=False
                )
                sniffer.start()
                # Report live capture ONLY after successful start
                self._sniffer = sniffer
                self.is_running = True
                self.mode = "live"
                return {
                    "status": "started",
                    "mode": "live",
                    "interface": str(self.active_interface),
                    "filter": self.bpf_filter,
                    "scapy_live": True
                }
            except Exception as exc:
                # Clear stale sniffer reference and record error
                self._sniffer = None
                self.collector_errors_count += 1
                self.last_collector_error = f"Scapy startup failed: {str(exc)}"

                if allow_fallback:
                    try:
                        self._start_simulated_live_worker(f"Fallback after Scapy failure: {exc}")
                        self.is_running = True
                        self.mode = "simulation"
                        return {
                            "status": "started",
                            "mode": "simulation",
                            "interface": "simulated (fallback)",
                            "filter": self.bpf_filter,
                            "scapy_live": False,
                            "warning": f"Live capture failed ({exc}); running in simulation mode"
                        }
                    except Exception as fb_exc:
                        self.is_running = False
                        self.mode = "stopped"
                        self.last_collector_error = f"Live capture failed ({exc}) and fallback failed: {fb_exc}"
                        return {
                            "status": "error",
                            "mode": "stopped",
                            "error": self.last_collector_error
                        }
                else:
                    self.is_running = False
                    self.mode = "stopped"
                    return {
                        "status": "error",
                        "mode": "stopped",
                        "error": self.last_collector_error
                    }
        else:
            self.collector_errors_count += 1
            self.last_collector_error = "Scapy module unavailable on host"
            if allow_fallback:
                try:
                    self._start_simulated_live_worker("Scapy unavailable")
                    self.is_running = True
                    self.mode = "simulation"
                    return {
                        "status": "started",
                        "mode": "simulation",
                        "interface": "simulated (fallback)",
                        "filter": self.bpf_filter,
                        "scapy_live": False,
                        "warning": "Scapy unavailable; running in simulation mode"
                    }
                except Exception as fb_exc:
                    self.is_running = False
                    self.mode = "stopped"
                    return {
                        "status": "error",
                        "mode": "stopped",
                        "error": f"Fallback simulation failed: {fb_exc}"
                    }
            else:
                self.is_running = False
                self.mode = "stopped"
                return {
                    "status": "error",
                    "mode": "stopped",
                    "error": "Scapy module unavailable on host"
                }

    def _start_simulated_live_worker(self, reason: str):
        """
        Background live simulated event generator.
        Protected against callback exceptions so individual errors do not terminate the worker.
        """
        def _worker():
            import random
            while not self._stop_event.is_set():
                try:
                    meta = {
                        "timestamp": time.time(),
                        "src_ip": f"192.168.1.{random.choice([18, 45, 105, 77])}",
                        "dst_ip": random.choice(["142.250.190.46", "172.217.16.206", "45.33.32.156"]),
                        "src_port": random.randint(49152, 65535),
                        "dst_port": random.choice([443, 80, 53, 22]),
                        "protocol": "TCP",
                        "bytes": random.randint(120, 1500),
                        "duration": 0.05
                    }
                    self.packets_captured += 1
                    self.bytes_captured += meta["bytes"]

                    res = None
                    try:
                        if self._ingest_callback:
                            res = self._ingest_callback(meta)
                        else:
                            res = self._default_ingest(meta)
                    except Exception as cb_exc:
                        self.processing_errors_count += 1
                        self.last_processing_error = str(cb_exc)
                        if self._stop_event.wait(timeout=1.0):
                            break
                        continue

                    if isinstance(res, dict) and ("error" in res or res.get("ai_error")):
                        self.processing_errors_count += 1
                        self.last_processing_error = str(res.get("error") or res.get("ai_error"))
                    else:
                        self.events_ingested += 1

                except Exception as worker_exc:
                    self.collector_errors_count += 1
                    self.last_collector_error = str(worker_exc)

                # Stoppable sleep
                if self._stop_event.wait(timeout=1.0):
                    break

        self._capture_thread = threading.Thread(target=_worker, daemon=True)
        self._capture_thread.start()

    def stop_capture(self) -> Dict[str, Any]:
        """
        Stops live capture or simulation, halting active threads and clearing references.
        """
        if not self.is_running and self.mode == "stopped":
            return {"status": "not_running", "mode": "stopped"}

        self.is_running = False
        prev_mode = self.mode
        self.mode = "stopped"
        self._stop_event.set()

        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

        if self._capture_thread and self._capture_thread.is_alive():
            try:
                self._capture_thread.join(timeout=1.5)
            except Exception:
                pass
            self._capture_thread = None

        duration = round(time.time() - (self.start_time or time.time()), 2)
        return {
            "status": "stopped",
            "previous_mode": prev_mode,
            "packets_captured": self.packets_captured,
            "events_ingested": self.events_ingested,
            "bytes_captured": self.bytes_captured,
            "duration_s": duration
        }

    # ------------------------------------------------------------------
    # Offline PCAP File Processing
    # ------------------------------------------------------------------
    def process_pcap_file(
        self,
        pcap_path: str,
        max_packets: Optional[int] = None,
        auto_ingest: bool = True
    ) -> Dict[str, Any]:
        """
        Parses a raw PCAP / PCAPNG file, extracts metadata from each packet,
        and streams them through the detection pipeline.
        """
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for PCAP parsing.")

        extracted = []
        threats_found = 0
        ingested_count = 0

        def _pcap_callback(pkt):
            nonlocal threats_found, ingested_count
            try:
                meta = self.extract_packet_metadata(pkt)
                if meta:
                    extracted.append(meta)
                    if auto_ingest:
                        res = self._default_ingest(meta)
                        if isinstance(res, dict) and ("error" in res or res.get("ai_error")):
                            self.processing_errors_count += 1
                            self.last_processing_error = str(res.get("error") or res.get("ai_error"))
                        else:
                            ingested_count += 1
                            if res and res.get("alert"):
                                threats_found += 1
            except Exception as pcap_err:
                self.processing_errors_count += 1
                self.last_processing_error = str(pcap_err)

        try:
            sniff(
                offline=pcap_path,
                prn=_pcap_callback,
                count=max_packets or 0,
                store=False
            )
        except Exception as exc:
            return {
                "status": "error",
                "file": os.path.basename(pcap_path),
                "error": f"Failed to parse PCAP file: {str(exc)}",
                "total_packets": len(extracted),
                "events_ingested": ingested_count,
                "threats_detected": threats_found
            }

        return {
            "status": "completed",
            "file": os.path.basename(pcap_path),
            "total_packets": len(extracted),
            "events_ingested": ingested_count,
            "threats_detected": threats_found,
            "sample_metadata": extracted[:5]
        }

    # ------------------------------------------------------------------
    # Status and Interface Directory
    # ------------------------------------------------------------------
    def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive status distinguishing mode, counts, and errors."""
        uptime = round(time.time() - self.start_time, 2) if (self.is_running and self.start_time) else 0.0
        pps = round(self.packets_captured / max(uptime, 0.001), 1) if self.is_running else 0.0

        return {
            "is_running":              self.is_running,
            "is_capturing":            self.is_running,
            "mode":                    self.mode,  # "stopped", "live", "simulation"
            "is_live":                 self.mode == "live",
            "is_simulated":            self.mode == "simulation",
            "active_interface":        self.active_interface,
            "bpf_filter":              self.bpf_filter,
            "packets_captured":        self.packets_captured,
            "bytes_captured":          self.bytes_captured,
            "events_ingested":         self.events_ingested,
            "corrupted_packets":       self.corrupted_packets_count,
            "collector_errors":        self.collector_errors_count,
            "processing_errors":       self.processing_errors_count,
            "last_collector_error":    self.last_collector_error,
            "last_processing_error":   self.last_processing_error,
            "uptime_seconds":          uptime,
            "packets_per_sec":         pps,
            "throughput_pps":          pps,
            "scapy_available":         SCAPY_AVAILABLE,
        }

    def list_interfaces(self) -> List[Dict[str, Any]]:
        """Returns list of available network interfaces."""
        if not SCAPY_AVAILABLE:
            return [{"name": "default", "description": "Default System Interface"}]

        try:
            if_list = get_if_list()
            return [{"name": str(iface), "description": f"Interface {iface}"} for iface in if_list]
        except Exception:
            return [{"name": "default", "description": "Default System Interface"}]
