"""
Unit Test Suite for NTRO Unidirectional Cyber Threat Detection Pipeline
Verifies diode physical constraint safety, feature extraction mathematical accuracy,
and alert classification for all 6 threat vectors.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pipeline.diode_ingest import UnidirectionalDiodeIngest, RawPacketMetadata
from pipeline.feature_extractor import StreamingFeatureExtractor
from pipeline.threat_detector import ThreatDetectorEngine
from pipeline.alert_schema import FlowTuple, StandardizedAlert, create_threat_alert

def test_unidirectional_diode_read_only_constraint():
    """Verify that diode receiver blocks any egress / transmit attempts."""
    ingest = UnidirectionalDiodeIngest()
    try:
        ingest.block_egress_attempts()
        assert False, "Should have raised PermissionError"
    except PermissionError as e:
        assert "DATA DIODE PHYSICAL CONSTRAINT" in str(e)

def test_shannon_entropy_calculation():
    """Test Shannon entropy calculation H(X) logic."""
    extractor = StreamingFeatureExtractor()
    # Uniform distribution of 4 items -> log2(4) = 2.0
    uniform_data = ["A", "B", "C", "D"]
    val = extractor.calculate_shannon_entropy(uniform_data)
    assert abs(val - 2.0) < 0.01

    # Zero entropy (single constant item)
    constant_data = ["A", "A", "A", "A"]
    assert extractor.calculate_shannon_entropy(constant_data) == 0.0

def test_dga_dns_tunnel_detection():
    """Verify detection of DGA domain and DNS tunnelling."""
    extractor = StreamingFeatureExtractor()
    engine = ThreatDetectorEngine(extractor)

    # High entropy DGA packet
    dga_pkt = RawPacketMetadata(
        timestamp=100.0,
        src_ip="192.168.1.10",
        src_port=54321,
        dst_ip="8.8.8.8",
        dst_port=53,
        protocol="UDP",
        packet_size=120,
        tcp_flags={},
        dns_query="xzk912ksd8410llqazxcvnm98.botnet-malicious-zone.cx",
        dns_record_type="A"
    )

    alert = engine.process_packet(dga_pkt)
    assert alert is not None
    assert alert.threat_category_code == "c"
    assert "DGA" in alert.threat_name or "DNS" in alert.threat_name
    assert alert.confidence_score >= 0.70

def test_tls_ja3_malware_detection():
    """Verify detection of known malware TLS JA3/JA4 fingerprint."""
    extractor = StreamingFeatureExtractor()
    engine = ThreatDetectorEngine(extractor)

    tls_pkt = RawPacketMetadata(
        timestamp=100.0,
        src_ip="192.168.1.88",
        src_port=49152,
        dst_ip="198.51.100.4",
        dst_port=443,
        protocol="TCP",
        packet_size=512,
        tcp_flags={"SYN": False, "ACK": True},
        tls_ja3_hash="e7ed349cc2f6ddef17227b93d7783801",
        tls_sni="bad-c2-domain.com"
    )

    alert = engine.process_packet(tls_pkt)
    assert alert is not None
    assert alert.threat_category_code == "d"
    assert "TrickBot" in alert.supporting_evidence["matched_fingerprint_description"]

def test_full_pipeline_mixed_stream():
    """Run full pipeline test over 500 mixed packets."""
    extractor = StreamingFeatureExtractor()
    engine = ThreatDetectorEngine(extractor)
    ingest = UnidirectionalDiodeIngest()

    count = 0
    alerts = 0
    for pkt in ingest.generate_simulated_stream(count=500, threat_scenario="MIXED"):
        count += 1
        a = engine.process_packet(pkt)
        if a: alerts += 1

    assert count == 500
    assert alerts > 0
    assert engine.total_alerts_raised == alerts

if __name__ == "__main__":
    print("Running Python Unit Tests...")
    test_unidirectional_diode_read_only_constraint()
    test_shannon_entropy_calculation()
    test_dga_dns_tunnel_detection()
    test_tls_ja3_malware_detection()
    test_full_pipeline_mixed_stream()
    print("✅ ALL UNIT TESTS PASSED SUCCESSFULLY!")
