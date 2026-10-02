"""
NTRO Unidirectional Cyber Threat Detection - Main Execution Entrypoint
Runs real-time AI/ML threat detection pipeline on passive unidirectional traffic stream.
"""

import sys
import time
import argparse
import json
from .diode_ingest import UnidirectionalDiodeIngest
from .feature_extractor import StreamingFeatureExtractor
from .threat_detector import ThreatDetectorEngine

def run_pipeline(
    packet_count: int = 2000, 
    scenario: str = "MIXED", 
    verbose: bool = True
):
    print("=" * 75)
    print(" NTRO UNIDIRECTIONAL IP TRAFFIC CYBER THREAT DETECTION PIPELINE")
    print(" Hardware Data Diode Enclave Mode: READ-ONLY PASSIVE INGEST")
    print(" Architectural Constraints: 0 Egress Sockets | No Decryption | Sub-5ms Latency")
    print("=" * 75)

    ingest = UnidirectionalDiodeIngest(interface_name="diode_rx0")
    extractor = StreamingFeatureExtractor(window_seconds=10.0)
    engine = ThreatDetectorEngine(feature_extractor=extractor)

    start_time = time.time()
    alerts_generated = []
    
    packet_stream = ingest.generate_simulated_stream(count=packet_count, threat_scenario=scenario)

    print(f"\n[+] Ingesting stream: {packet_count} packets | Scenario: {scenario} ...\n")

    for idx, pkt in enumerate(packet_stream):
        pkt_start = time.perf_counter()
        
        # Process packet through threat detector
        alert = engine.process_packet(pkt)
        
        pkt_latency_ms = (time.perf_counter() - pkt_start) * 1000.0

        if alert:
            alerts_generated.append(alert)
            if verbose and len(alerts_generated) <= 10:
                print(f"🚨 [ALERT #{len(alerts_generated)}] {alert.severity} | {alert.threat_name} | Confidence: {alert.confidence_score*100:.1f}% | Latency: {pkt_latency_ms:.2f}ms")
                print(f"   Flow: {alert.flow_id}")
                print(f"   Evidence: {json.dumps(alert.supporting_evidence)}")
                print("-" * 75)

    elapsed = time.time() - start_time
    flows_per_sec = packet_count / max(0.001, elapsed)
    mbps = (ingest.total_bytes_received * 8 / 1_000_000) / max(0.001, elapsed)

    print("\n" + "=" * 75)
    print(" PIPELINE RUN SUMMARY & PERFORMANCE BENCHMARK")
    print("=" * 75)
    print(f" Total Packets/Flows Processed : {ingest.total_packets_received:,}")
    print(f" Total Data Volume Ingested    : {ingest.total_bytes_received / (1024*1024):.2f} MB")
    print(f" Processing Runtime            : {elapsed:.3f} seconds")
    print(f" Sustained Throughput          : {flows_per_sec:,.2f} flows/sec ({mbps:.2f} Mbps)")
    print(f" Total Threats Detected        : {engine.total_alerts_raised}")
    print(" Alerts by Category Breakdown  :")
    print(f"   [a] Volumetric / DDoS       : {engine.alert_counts_by_category['a']}")
    print(f"   [b] Botnet C2 Beaconing     : {engine.alert_counts_by_category['b']}")
    print(f"   [c] DGA / DNS Tunnelling    : {engine.alert_counts_by_category['c']}")
    print(f"   [d] TLS Encrypted Malware   : {engine.alert_counts_by_category['d']}")
    print(f"   [e] Recon / Port Scan       : {engine.alert_counts_by_category['e']}")
    print(f"   [f] Data Exfiltration       : {engine.alert_counts_by_category['f']}")
    print("=" * 75)

    return {
        "packets": ingest.total_packets_received,
        "runtime_sec": round(elapsed, 3),
        "throughput_fps": round(flows_per_sec, 2),
        "total_alerts": engine.total_alerts_raised,
        "alerts": [a.to_dict() for a in alerts_generated]
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NTRO Unidirectional Threat Detection Pipeline")
    parser.add_argument("--count", type=int, default=2500, help="Number of packets/flows to process")
    parser.add_argument("--scenario", type=str, default="MIXED", choices=["MIXED", "DDOS_SYN_FLOOD", "BOTNET_BEACON", "DGA_DNS_TUNNEL", "TLS_MALWARE", "SCANNING", "EXFILTRATION", "NORMAL"])
    parser.add_argument("--quiet", action="store_true", help="Suppress individual alert printing")

    args = parser.parse_args()
    run_pipeline(packet_count=args.count, scenario=args.scenario, verbose=not args.quiet)
