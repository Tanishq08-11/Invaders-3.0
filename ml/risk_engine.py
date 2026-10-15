"""
Alert and Risk Engine for Insider Data Exfiltration
Evaluates KitNET statistical anomaly scores alongside contextual network heuristics:
- Off-hours data egress
- Suspicious destination IP & egress ports (e.g., TLS 443, SSH 22, Tor 9001)
- Flow asymmetry (heavy outbound upload vs download)
- Host historical risk accumulation
"""
from typing import Dict, Any, Tuple
from datetime import datetime, timezone
import ipaddress
import numpy as np


class RiskEngine:
    """
    Translates raw KitNET anomaly scores into actionable cybersecurity risk metrics (0-100),
    severity tiers (NORMAL, LOW, MEDIUM, HIGH, CRITICAL), and alert triggers.
    """
    def __init__(
        self,
        z_low: float = 2.0,
        z_med: float = 3.5,
        z_high: float = 5.5,
        z_crit: float = 8.5
    ):
        self.z_low = z_low
        self.z_med = z_med
        self.z_high = z_high
        self.z_crit = z_crit

        self.suspicious_ports = {
            4444: "Metasploit / Command & Control Default",
            9001: "Tor / Encrypted Proxy",
            2222: "Non-standard SSH Tunnel",
            31337: "Back Orifice Trojan Port",
            6667: "IRC Exfiltration Channel",
            8088: "Custom HTTP Proxy Tunnel",
            8080: "HTTP/Proxy Tunnel",
            22:   "SSH/SFTP Secure Shell Transfer",
        }
        self.encrypted_channels = {
            443:  "TLS/HTTPS Encrypted Channel",
            8443: "Alternative HTTPS Port",
            53:   "DNS / Encrypted DoH Tunneling",
        }

    def is_private_ip(self, ip_str: str) -> bool:
        """Determines if an IP address is an internal corporate RFC 1918/loopback address."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback or ip.is_link_local:
                return True
            # RFC 1918 enterprise private subnets
            rfc1918 = (
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16")
            )
            return any(ip in net for net in rfc1918)
        except ValueError:
            return False

    def is_off_hours(self, dt: datetime) -> bool:
        """Determines if the timestamp falls on weekend or off-hours (20:00 - 06:00)."""
        if dt.weekday() >= 5:  # Saturday or Sunday
            return True
        hour = dt.hour
        return hour >= 20 or hour < 6

    def evaluate(
        self,
        anomaly_score: float,
        flow_meta: Dict[str, Any],
        baseline_mean: float,
        baseline_std: float,
        baseline_max: float
    ) -> Dict[str, Any]:
        """
        Evaluates the network flow event against learned normal baselines and domain rules.
        """
        # 1. Statistical Z-Score
        if baseline_std < 1e-5:
            baseline_std = 0.01
        z_score = max(0.0, (anomaly_score - baseline_mean) / baseline_std)

        # 2. Base Risk Calculation from Z-score (0 to 60)
        base_risk = 0.0
        if z_score < self.z_low:
            base_risk = (z_score / self.z_low) * 20.0
        elif z_score < self.z_med:
            base_risk = 20.0 + ((z_score - self.z_low) / (self.z_med - self.z_low)) * 20.0
        elif z_score < self.z_high:
            base_risk = 40.0 + ((z_score - self.z_med) / (self.z_high - self.z_med)) * 15.0
        else:
            base_risk = 55.0 + min(15.0, (z_score - self.z_high) * 3.0)

        # 3. Contextual Heuristic Risk Additions (0 to 40)
        heuristic_risk = 0.0
        risk_factors = []

        # Check External Destination
        dst_ip = flow_meta.get("dst_ip", "0.0.0.0")
        is_external = not self.is_private_ip(dst_ip)
        if is_external:
            heuristic_risk += 10.0
            risk_factors.append(f"Outbound transfer to external destination: {dst_ip}")

        # Check Egress Port (Known C2 / Tunnel ports or Encrypted channel under anomaly)
        dst_port = int(flow_meta.get("dst_port", 0))
        if dst_port in self.suspicious_ports:
            heuristic_risk += 12.0
            risk_factors.append(f"Suspicious destination port {dst_port} ({self.suspicious_ports[dst_port]})")
        elif dst_port in self.encrypted_channels and (z_score >= self.z_low or is_external):
            heuristic_risk += 6.0
            risk_factors.append(f"Encrypted channel {dst_port} ({self.encrypted_channels[dst_port]})")

        # Check Off-Hours Timing
        ts_val = flow_meta.get("timestamp")
        if isinstance(ts_val, (int, float)):
            dt = datetime.fromtimestamp(ts_val, tz=timezone.utc)
        elif isinstance(ts_val, datetime):
            dt = ts_val
        else:
            dt = datetime.now(timezone.utc)

        off_hours_flag = self.is_off_hours(dt)
        if off_hours_flag:
            heuristic_risk += 8.0
            risk_factors.append("Off-hours data transmission (evening/night or weekend)")

        # Check High Volume / Outbound Burst
        bytes_val = float(flow_meta.get("bytes") or flow_meta.get("sum") or 0.0)
        len_val = float(flow_meta.get("length") or 0.0)
        mean_val = float(flow_meta.get("mean") or 0.0)
        mean_pkt = mean_val if mean_val > 0 else (len_val if len_val <= 1514 else 0.0)
        if 1300 <= mean_pkt <= 1514:
            heuristic_risk += 6.0
            risk_factors.append(f"Near-MTU packet framing ({int(mean_pkt)} bytes/pkt) indicative of continuous data dumping")
        elif bytes_val > 5_000_000:
            heuristic_risk += 8.0
            risk_factors.append(f"Bulk data transfer volume ({bytes_val / (1024*1024):.1f} MB)")

        # Total Risk Score (capped at 100)
        total_risk = min(100.0, base_risk + heuristic_risk)

        # 4. Severity & Threat Categorization with Statistical Anomaly Gating
        if z_score < self.z_low:
            severity = "NORMAL" if total_risk < 30.0 else "LOW"
            is_threat = False
        elif z_score < self.z_med:
            if total_risk >= 65.0:
                severity = "MEDIUM"
                is_threat = True
            else:
                severity = "LOW"
                is_threat = False
        elif z_score < self.z_high:
            severity = "HIGH" if total_risk >= 70.0 else "MEDIUM"
            is_threat = True
        else:
            severity = "CRITICAL" if (total_risk >= 85.0 or z_score >= self.z_crit) else "HIGH"
            is_threat = True
        confidence = float(np.clip(0.65 + (z_score / 20.0) * 0.3, 0.65, 0.99))

        return {
            "anomaly_score": float(anomaly_score),
            "z_score": float(z_score),
            "risk_score": float(round(total_risk, 1)),
            "severity": severity,
            "is_threat": is_threat,
            "confidence": float(round(confidence, 2)),
            "is_external_dst": is_external,
            "off_hours": off_hours_flag,
            "risk_factors": risk_factors
        }


# ---------------------------------------------------------------------------------------
# Rule-signal combination policy (independent of the model path above)
# ---------------------------------------------------------------------------------------
RULE_GROUP_WEIGHTS = {
    # Weight applied to a group's score before noisy-OR combination.
    "exfiltration_volume": 1.0,
    "multi_stage": 1.0,
    "destination": 0.8,
    "protocol": 0.8,
    "identity": 0.8,
    "behaviour": 0.6,
}
EVIDENCE_ONLY_CAP = 15.0        # contextual signals (e.g. first-seen destination) never dominate
CORROBORATION_BONUS = 0.1       # within a group: +10% of each additional signal's score…
CORROBORATION_CAP = 10.0        # …capped, so correlated indicators are not double-counted


def combine_rule_signals(results):
    """
    Combine triggered *security* detector results into one rule score (0-100).

    1. Each signal contributes its rule score; evidence-only signals are capped at 15.
    2. Within a group (signals that measure related things, e.g. D1/D5/D6 volume), the
       group score is the maximum plus a small, capped corroboration bonus — correlated
       indicators are not summed.
    3. Groups are combined with a weighted noisy-OR: 1 - Π(1 - w_g·s_g/100).
    External destinations and HTTPS carry no risk by themselves: no detector scores them.
    The result is a rule weighting, not a probability and not an AI anomaly score.
    """
    groups = {}
    for r in results:
        score = float(r["score"] or 0.0)
        if r.get("evidence_only"):
            score = min(score, EVIDENCE_ONLY_CAP)
        groups.setdefault(r["group"], []).append(score)
    group_scores = {}
    for g, scores in groups.items():
        scores.sort(reverse=True)
        bonus = min(CORROBORATION_CAP, CORROBORATION_BONUS * sum(scores[1:]))
        group_scores[g] = min(100.0, scores[0] + bonus)
    remaining = 1.0
    for g, s in group_scores.items():
        remaining *= 1.0 - RULE_GROUP_WEIGHTS.get(g, 0.6) * s / 100.0
    combined = round(100.0 * (1.0 - remaining), 1)
    if combined >= 85:
        severity = "CRITICAL"
    elif combined >= 65:
        severity = "HIGH"
    elif combined >= 45:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    return {"rule_score": combined, "severity": severity, "group_scores": group_scores,
            "policy": "max-per-group + capped corroboration, weighted noisy-OR across groups"}


RiskEngine.combine_rule_signals = staticmethod(combine_rule_signals)
