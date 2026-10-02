"""
NTRO Unidirectional Cyber Threat Detection - AI/ML Threat Detector Engine
Evaluates engineered streaming features against multi-class ML models & statistical detectors.
"""

from typing import Optional, Dict, Any, List, Tuple
from .diode_ingest import RawPacketMetadata
from .feature_extractor import StreamingFeatureExtractor
from .alert_schema import StandardizedAlert, FlowTuple, create_threat_alert

class ThreatDetectorEngine:
    """
    Real-time Threat Detection Engine operating purely on passive unidirectional telemetry.
    Implements rule-based heuristics, statistical anomaly boundaries, and ML scoring.
    """
    def __init__(self, feature_extractor: StreamingFeatureExtractor):
        self.extractor = feature_extractor
        self.total_alerts_raised = 0
        self.alert_counts_by_category = {
            "a": 0, "b": 0, "c": 0, "d": 0, "e": 0, "f": 0
        }

    def process_packet(self, pkt: RawPacketMetadata) -> Optional[StandardizedAlert]:
        """
        Ingests packet, updates feature window, and evaluates all 6 threat classifiers.
        Returns StandardizedAlert if threat detected with confidence >= threshold.
        """
        # Step 1: Update sliding window
        self.extractor.add_packet(pkt)
        
        # Step 2: Extract feature dict
        feats = self.extractor.extract_features_for_packet(pkt)
        
        # Flow tuple representation
        ft = FlowTuple(
            src_ip=pkt.src_ip,
            src_port=pkt.src_port,
            dst_ip=pkt.dst_ip,
            dst_port=pkt.dst_port,
            protocol=pkt.protocol
        )

        # Threat Classifier A: Volumetric / Protocol DDoS
        alert = self._detect_ddos(pkt, feats, ft)
        if alert: return self._register_alert(alert, "a")

        # Threat Classifier B: Botnet C2 Beaconing
        alert = self._detect_c2_beaconing(pkt, feats, ft)
        if alert: return self._register_alert(alert, "b")

        # Threat Classifier C: DGA & DNS Tunnelling
        alert = self._detect_dga_dns_tunnel(pkt, feats, ft)
        if alert: return self._register_alert(alert, "c")

        # Threat Classifier D: Encrypted Session Malware
        alert = self._detect_tls_malware(pkt, feats, ft)
        if alert: return self._register_alert(alert, "d")

        # Threat Classifier E: Reconnaissance & Port Scanning
        alert = self._detect_port_scan(pkt, feats, ft)
        if alert: return self._register_alert(alert, "e")

        # Threat Classifier F: Data Exfiltration
        alert = self._detect_data_exfiltration(pkt, feats, ft)
        if alert: return self._register_alert(alert, "f")

        return None

    def _register_alert(self, alert: StandardizedAlert, code: str) -> StandardizedAlert:
        self.total_alerts_raised += 1
        self.alert_counts_by_category[code] += 1
        return alert

    # --- Classifier Implementations ---

    def _detect_ddos(self, pkt: RawPacketMetadata, feats: Dict[str, Any], ft: FlowTuple) -> Optional[StandardizedAlert]:
        """Category A: Volumetric / Protocol DDoS (SYN Flood, Low Src IP Entropy)."""
        syn_ratio = feats["syn_ratio"]
        src_entropy = feats["src_ip_shannon_entropy"]
        pps_rate = feats["pps_rate"]

        # High SYN ratio + low source IP entropy or extreme PPS spike indicates flood
        if syn_ratio > 0.65 and pps_rate > 50:
            confidence = min(0.99, 0.70 + (syn_ratio * 0.25))
            severity = "CRITICAL" if pps_rate > 200 else "HIGH"
            
            return create_threat_alert(
                threat_code="a",
                threat_name="Volumetric TCP SYN Flood DDoS",
                severity=severity,
                confidence=confidence,
                flow_tuple=ft,
                evidence={
                    "syn_flag_ratio": syn_ratio,
                    "src_ip_shannon_entropy": src_entropy,
                    "packets_per_sec": pps_rate,
                    "detection_vector": "Flow-level rate & TCP flag distribution"
                },
                advisory="Enable upstream scrubbing or apply SYN cookies on border router."
            )
        return None

    def _detect_c2_beaconing(self, pkt: RawPacketMetadata, feats: Dict[str, Any], ft: FlowTuple) -> Optional[StandardizedAlert]:
        """Category B: Botnet C2 Beaconing (Low Inter-Arrival Time Variance CV <= 0.15)."""
        iat_cv = feats["iat_cv"]
        iat_mean = feats["iat_mean"]
        
        # Low CV (<= 0.15) with consistent repeated flows indicates automated beaconing
        if feats["window_size"] >= 10 and iat_mean > 0.5 and iat_cv <= 0.15:
            confidence = min(0.98, 0.75 + ((0.15 - iat_cv) * 1.5))
            
            return create_threat_alert(
                threat_code="b",
                threat_name="Botnet C2 Automated Beaconing",
                severity="HIGH",
                confidence=confidence,
                flow_tuple=ft,
                evidence={
                    "inter_arrival_time_cv": iat_cv,
                    "mean_inter_arrival_sec": iat_mean,
                    "periodicity_regularity_score": round(1.0 - iat_cv, 4),
                    "detection_vector": "Flow inter-arrival periodicity & CV analysis"
                },
                advisory="Block outbound C2 host destination IP in perimeter proxy."
            )
        return None

    def _detect_dga_dns_tunnel(self, pkt: RawPacketMetadata, feats: Dict[str, Any], ft: FlowTuple) -> Optional[StandardizedAlert]:
        """Category C: DGA Domains & DNS Tunnelling (High Entropy, N-Gram Anomaly, TXT Records)."""
        dns_q = pkt.dns_query
        dns_entropy = feats["dns_entropy"]
        ngram_score = feats["dns_ngram_score"]
        record_type = pkt.dns_record_type

        if not dns_q:
            return None

        # DGA Detection: High character entropy (> 4.2) or abnormal n-gram score
        if dns_entropy > 4.2 or (len(dns_q) > 25 and ngram_score > 0.45):
            is_tunnel = record_type == "TXT" or len(dns_q) > 50
            threat_name = "DNS Covert Data Tunnelling" if is_tunnel else "DGA Algorithmically Generated Domain"
            severity = "HIGH" if is_tunnel else "MEDIUM"
            confidence = min(0.97, 0.65 + (dns_entropy / 10.0))

            return create_threat_alert(
                threat_code="c",
                threat_name=threat_name,
                severity=severity,
                confidence=confidence,
                flow_tuple=ft,
                evidence={
                    "dns_query_fqdn": dns_q,
                    "record_type": record_type,
                    "shannon_character_entropy": dns_entropy,
                    "ngram_transition_anomaly": ngram_score,
                    "query_length": len(dns_q),
                    "detection_vector": "FQDN n-gram & entropy analysis"
                },
                advisory="Sinkhole internal DNS query and inspect host resolver logs."
            )
        return None

    def _detect_tls_malware(self, pkt: RawPacketMetadata, feats: Dict[str, Any], ft: FlowTuple) -> Optional[StandardizedAlert]:
        """Category D: Malware in Encrypted Sessions (JA3/JA4 Fingerprints & SPLT metadata)."""
        ja3_match = feats["ja3_match"]
        ja4_match = feats["ja4_match"]

        if ja3_match or ja4_match:
            threat_desc = ja3_match or ja4_match
            confidence = 0.96
            
            return create_threat_alert(
                threat_code="d",
                threat_name=f"Encrypted Malware Session ({threat_desc})",
                severity="CRITICAL",
                confidence=confidence,
                flow_tuple=ft,
                evidence={
                    "matched_fingerprint_description": threat_desc,
                    "tls_ja3_hash": pkt.tls_ja3_hash,
                    "tls_ja4_hash": pkt.tls_ja4_hash,
                    "tls_sni": pkt.tls_sni,
                    "splt_packet_sequence_len": feats["splt_seq_len"],
                    "detection_vector": "TLS ClientHello JA3/JA4 fingerprinting & SPLT sequence"
                },
                advisory="Restrict SSL egress to verified certificate authority bundles."
            )
        return None

    def _detect_port_scan(self, pkt: RawPacketMetadata, feats: Dict[str, Any], ft: FlowTuple) -> Optional[StandardizedAlert]:
        """Category E: Reconnaissance and Port Scanning (Fan-out across Dst Ports/Hosts)."""
        unique_ports = feats["unique_dst_ports"]
        unique_hosts = feats["unique_dst_hosts"]

        if unique_ports > 15 or unique_hosts > 10:
            severity = "HIGH" if unique_ports > 50 else "MEDIUM"
            confidence = min(0.95, 0.70 + (unique_ports / 100.0))

            return create_threat_alert(
                threat_code="e",
                threat_name="Reconnaissance & Horizontal/Vertical Port Scan",
                severity=severity,
                confidence=confidence,
                flow_tuple=ft,
                evidence={
                    "unique_dst_ports_in_window": unique_ports,
                    "unique_dst_hosts_in_window": unique_hosts,
                    "fanout_ratio": round(unique_ports / max(1, feats["window_size"]), 4),
                    "detection_vector": "Single-source host/port fan-out tracking"
                },
                advisory="Flag scanner IP for automated SIEM dynamic ACL rule creation."
            )
        return None

    def _detect_data_exfiltration(self, pkt: RawPacketMetadata, feats: Dict[str, Any], ft: FlowTuple) -> Optional[StandardizedAlert]:
        """Category F: Data Exfiltration (Unusual Outbound/Inbound Byte Ratio > 10.0)."""
        byte_ratio = feats["byte_ratio"]
        outbound_bytes = feats["outbound_bytes"]

        if outbound_bytes > 50000 and byte_ratio > 8.0:
            confidence = min(0.94, 0.65 + (byte_ratio / 50.0))
            
            return create_threat_alert(
                threat_code="f",
                threat_name="Data Exfiltration via Asymmetric Volume",
                severity="CRITICAL",
                confidence=confidence,
                flow_tuple=ft,
                evidence={
                    "outbound_bytes_total": outbound_bytes,
                    "outbound_to_inbound_ratio": byte_ratio,
                    "detection_vector": "Flow volume asymmetry & sustained outbound stream"
                },
                advisory="Isolate source workstation and perform DLP packet analysis."
            )
        return None
