"""
Detector registry — returns one instance of every detector class.
"""
from services.detection.detectors.volume import LargeUpload, UploadHeavy, LongUpload, SlowLeak, BulkDownload
from services.detection.detectors.destination import UnknownDestination, UnusualCountry, TrustedSiteLeak, Beaconing, RemoteDesktopOut, EgressPolicy
from services.detection.detectors.temporal import UnusualTime, SpreadOutLeak, SuddenChange
from services.detection.detectors.traffic import AutomatedTransfer, ProtocolTunnel, ConnectionFailures, LateralMovement
from services.detection.detectors.identity import ConcurrentSessions, UnusualSource, TwoDevices, AuthAnomalies
from services.detection.detectors.dns_tls import DnsTunnel, HiddenTunnel, TlsFingerprintChange
from services.detection.detectors.chain_telemetry import MultiStage, DeviceSilent, TelemetryHealth


def all_detectors():
    """Return one instance of every registered detector, in evaluation order."""
    return [
        # D1–D7, D16: Volume / Exfiltration
        LargeUpload(),
        UploadHeavy(),
        LongUpload(),
        SlowLeak(),
        BulkDownload(),
        # D2, D3, D18, D19, D20, D23: Destination
        UnknownDestination(),
        UnusualCountry(),
        TrustedSiteLeak(),
        Beaconing(),
        RemoteDesktopOut(),
        EgressPolicy(),
        # D4, D9, D10: Temporal
        UnusualTime(),
        SpreadOutLeak(),
        SuddenChange(),
        # D8, D21, D22, D28: Traffic / Protocol
        AutomatedTransfer(),
        ProtocolTunnel(),
        ConnectionFailures(),
        LateralMovement(),
        # D13, D14, D15, D27: Identity
        ConcurrentSessions(),
        UnusualSource(),
        TwoDevices(),
        AuthAnomalies(),
        # D12, D17, D26: DNS/TLS/Tunnel
        DnsTunnel(),
        HiddenTunnel(),
        TlsFingerprintChange(),
        # D24, D11, D25: Chain / Telemetry (D24 multi-stage evaluates last)
        DeviceSilent(),
        TelemetryHealth(),
        MultiStage(),          # must be last — reads results of all others
    ]
