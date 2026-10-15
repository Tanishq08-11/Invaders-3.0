"""
Explanation Engine (XAI) for Encrypted Traffic Insider Threat Detection
Translates KitNET per-feature reconstruction errors into human-readable SOC narratives,
radar chart data, and actionable incident response playbooks.
"""
from typing import List, Dict, Any
import numpy as np


class ExplanationEngine:
    """
    Decomposes Autoencoder reconstruction errors to explain WHY an encrypted network
    flow was flagged as data exfiltration without ever decrypting packet payloads.
    """
    def __init__(self, feature_names: List[str]):
        self.feature_names = feature_names
        self.feature_catalog = self._build_catalog()

    def _build_catalog(self) -> Dict[str, Dict[str, str]]:
        """Maps raw feature patterns to cybersecurity concepts."""
        return {
            "host_pkt_rate": {
                "display": "Host Outbound Packet Rate",
                "desc": "High burst of packets emitted by the internal host compared to normal workstation baseline."
            },
            "host_pkt_size_mean": {
                "display": "Average Packet Payload Size",
                "desc": "Abnormal shift towards full MTU packet sizes, characteristic of continuous data dumping."
            },
            "host_pkt_size_std": {
                "display": "Packet Size Variance / Uniformity",
                "desc": "Low variance indicates compressed/encrypted chunk streaming rather than human web browsing."
            },
            "channel_flow_rate": {
                "display": "Target Channel Flow Velocity",
                "desc": "Spike in packet frequency targeted at a specific external destination."
            },
            "channel_flow_mean": {
                "display": "Channel Throughput Volume",
                "desc": "Sustained high bandwidth channel established to external host."
            },
            "socket_burst_rate": {
                "display": "Socket Burst Frequency",
                "desc": "Single ephemeral socket pushing packets at anomalous machine speeds."
            },
            "conv_stream_rate": {
                "display": "Conversation Transfer Speed",
                "desc": "Intense bidirectional or unidirectional connection stream."
            },
            "burst_velocity": {
                "display": "Sub-Second Burst Velocity",
                "desc": "Extreme packet burst rate in 100ms window typical of automated exfiltration scripts."
            },
            "packet_size_entropy_proxy": {
                "display": "Encrypted Stream Entropy Proxy",
                "desc": "Statistical distribution aligns with encrypted/compressed archives (.zip, .tar, .7z) leaving the network."
            },
            "flow_asymmetry_metric": {
                "display": "Traffic Asymmetry (Upload Dominance)",
                "desc": "Severe disproportion between outbound data volume and inbound confirmations."
            },
            "channel_to_host_ratio": {
                "display": "Channel Traffic Dominance",
                "desc": "Single connection consuming a disproportionate share of total host network activity."
            },
            "jitter_size_corr": {
                "display": "Jitter-Size Correlation",
                "desc": "Consistent pacing and fixed size frames indicative of programmatic data egress."
            }
        }

    def _lookup_feature_info(self, raw_name: str) -> Dict[str, str]:
        for prefix, meta in self.feature_catalog.items():
            if raw_name.startswith(prefix):
                return meta
        return {
            "display": raw_name.replace("_", " ").title(),
            "desc": "Statistical anomaly detected in temporal decay window."
        }

    def explain(
        self,
        feature_errors: np.ndarray,
        flow_meta: Dict[str, Any],
        risk_evaluation: Dict[str, Any],
        top_k: int = 5
    ) -> Dict[str, Any]:
        """
        Generates full explainability payload for a detected event.
        """
        # Ensure errors are finite
        clean_errors = np.nan_to_num(feature_errors, nan=0.0)
        total_error = float(np.sum(clean_errors))

        if total_error <= 1e-7:
            # Fallback if no error
            clean_errors = np.ones_like(clean_errors)
            total_error = float(np.sum(clean_errors))

        # Rank features by reconstruction error
        sorted_indices = np.argsort(clean_errors)[::-1]
        top_indices = sorted_indices[:top_k]

        top_features = []
        for rank, idx in enumerate(top_indices, 1):
            if idx >= len(self.feature_names):
                continue
            name = self.feature_names[idx]
            info = self._lookup_feature_info(name)
            err_val = float(clean_errors[idx])
            pct = (err_val / total_error) * 100.0 if total_error > 0 else 0.0

            top_features.append({
                "rank": rank,
                "feature_name": name,
                "display_name": info["display"],
                "importance_score": round(err_val, 4),
                "contribution_pct": round(pct, 1),
                "description": info["desc"]
            })

        # Generate Contextual SOC Narrative
        src_ip = flow_meta.get("src_ip", flow_meta.get("saddr", "Internal Host"))
        dst_ip = flow_meta.get("dst_ip", flow_meta.get("daddr", "External Host"))
        dst_port = flow_meta.get("dst_port", flow_meta.get("dport", 443))
        protocol = str(flow_meta.get("protocol", flow_meta.get("proto", "TCP"))).upper()
        severity = risk_evaluation.get("severity", "MEDIUM")
        risk_score = risk_evaluation.get("risk_score", 50.0)
        bytes_transferred = flow_meta.get("length", flow_meta.get("bytes", 0))

        lead_feature_str = top_features[0]["display_name"] if top_features else "Encrypted Flow Dynamics"

        narrative = (
            f"Internal endpoint {src_ip} initiated anomalous encrypted traffic to {dst_ip}:{dst_port} ({protocol}). "
            f"Risk Engine classified this incident as {severity} (Risk Score: {risk_score}/100). "
            f"Primary deviation driver is '{lead_feature_str}' accounting for "
            f"{top_features[0]['contribution_pct'] if top_features else 0}% of the model's reconstruction error. "
        )

        if risk_evaluation.get("off_hours"):
            narrative += "Transfer occurred during non-business hours, raising high probability of intentional insider exfiltration. "
        if risk_evaluation.get("is_external_dst"):
            narrative += f"Traffic egressed the perimeter towards external IP {dst_ip}. "

        # Generate Recommended Playbook Actions
        mitigation = [
            f"Temporarily quarantine endpoint {src_ip} via EDR/NAC isolation.",
            f"Block outbound egress to IP {dst_ip} and destination port {dst_port} on firewall.",
            f"Investigate active user session and processes running on {src_ip} at time of transfer.",
            "Review host endpoint logs for unauthorized file staging (.zip, .tar, .7z) in /tmp or AppData.",
            "Inspect DLP and cloud storage access tokens associated with the logged-in user account."
        ]

        return {
            "top_features": top_features,
            "explanation_text": narrative,
            "mitigation_steps": mitigation,
            "radar_metrics": [
                {"metric": f["display_name"][:18], "value": min(100.0, f["contribution_pct"] * 2.5)}
                for f in top_features
            ]
        }
