"""
NTRO Unidirectional Cyber Threat Detection - Alert Schema Module
Standardized alert schema conforming to NTRO architectural specification (Constraint E).
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json
import uuid
from typing import Dict, Any, Optional

@dataclass
class FlowTuple:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # TCP, UDP, ICMP, etc.

@dataclass
class StandardizedAlert:
    alert_id: str = field(default_factory=lambda: f"ALT-{uuid.uuid4().hex[:12].upper()}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    threat_category_code: str = ""  # a, b, c, d, e, f
    threat_name: str = ""  # e.g., "Volumetric SYN Flood DDoS"
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW
    confidence_score: float = 0.0  # 0.0 to 1.0 (or percentage 0-100)
    flow_id: str = ""
    flow_tuple: Dict[str, Any] = field(default_factory=dict)
    supporting_evidence: Dict[str, Any] = field(default_factory=dict)
    ingress_interface: str = "diode_rx0"
    isolation_mode: str = "READ_ONLY_PASSIVE_ENCLAVE"
    recommended_advisory: str = ""  # Advisory note for enclave analysts (No return path action)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def create_threat_alert(
    threat_code: str,
    threat_name: str,
    severity: str,
    confidence: float,
    flow_tuple: FlowTuple,
    evidence: Dict[str, Any],
    advisory: str = ""
) -> StandardizedAlert:
    """Helper to construct standardized alert compliant with NTRO guidelines."""
    flow_id = f"{flow_tuple.src_ip}:{flow_tuple.src_port}->{flow_tuple.dst_ip}:{flow_tuple.dst_port}[{flow_tuple.protocol}]"
    
    return StandardizedAlert(
        threat_category_code=threat_code,
        threat_name=threat_name,
        severity=severity.upper(),
        confidence_score=round(confidence, 4),
        flow_id=flow_id,
        flow_tuple=asdict(flow_tuple),
        supporting_evidence=evidence,
        recommended_advisory=advisory or f"Isolate destination target {flow_tuple.dst_ip} at out-of-band firewall."
    )
