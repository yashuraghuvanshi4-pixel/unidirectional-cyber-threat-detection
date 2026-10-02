"""
NTRO Unidirectional Cyber Threat Detection - Feature Extraction Module
Engineers real-time streaming features over sliding windows for the 6 target threat categories.
Uses standard library math & statistics for zero-dependency execution.
"""

import math
import statistics
from collections import defaultdict, Counter
from typing import Dict, List, Any, Tuple
from .diode_ingest import RawPacketMetadata

# Known Malicious JA3 / JA4 Fingerprint Threat Intelligence Database
MALICIOUS_JA3_SIGNATURES = {
    "e7ed349cc2f6ddef17227b93d7783801": "TrickBot Malware TLS Fingerprint",
    "51c858f91870a6129ccb64041511516e": "Cobalt Strike Beacon Default TLS",
    "a0e42d1599c3082a41e1def92a2d5120": "AsyncRAT C2 Client Fingerprint",
    "cd58300061b78297b5e408d6d5392095": "Metasploit Meterpreter Reverse HTTPS"
}

MALICIOUS_JA4_SIGNATURES = {
    "t13d151600_8daaf6152771_b123456789ab": "Cobalt Strike Beacon JA4",
    "t13d151600_8daaf6152771_e3b0c44298fc": "AsyncRAT / Remcos RAT JA4"
}

class StreamingFeatureExtractor:
    """
    Stateful sliding-window feature extractor operating on passive read-only stream.
    Window size: 10.0 seconds / 1000 packets sliding buffer.
    """
    def __init__(self, window_seconds: float = 10.0):
        self.window_seconds = window_seconds
        self.packet_buffer: List[RawPacketMetadata] = []
        
        # State tracking for per-pair flow stats
        self.src_ip_counter: Counter = Counter()
        self.dst_ip_counter: Counter = Counter()
        self.src_fanout_ports: Dict[str, set] = defaultdict(set)
        self.src_fanout_hosts: Dict[str, set] = defaultdict(set)
        
        # Flow timing history for beaconing analysis: (src_ip, dst_ip) -> List[timestamps]
        self.flow_timestamps: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        
        # Flow byte statistics: (src_ip, dst_ip) -> {'out': int, 'in': int}
        self.flow_bytes: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(lambda: {'out': 0, 'in': 0})
        
        # TLS packet size sequence (SPLT) first 15 packets
        self.tls_splt_sequences: Dict[Tuple[str, str], List[int]] = defaultdict(list)

    def add_packet(self, pkt: RawPacketMetadata):
        """Pushes packet into sliding window buffer and updates state counters."""
        self.packet_buffer.append(pkt)
        
        # Trim stale packets outside sliding window
        cutoff = pkt.timestamp - self.window_seconds
        while self.packet_buffer and self.packet_buffer[0].timestamp < cutoff:
            stale = self.packet_buffer.pop(0)
            self.src_ip_counter[stale.src_ip] -= 1
            if self.src_ip_counter[stale.src_ip] <= 0:
                del self.src_ip_counter[stale.src_ip]

        # Update fanout stats
        self.src_ip_counter[pkt.src_ip] += 1
        self.dst_ip_counter[pkt.dst_ip] += 1
        self.src_fanout_ports[pkt.src_ip].add(pkt.dst_port)
        self.src_fanout_hosts[pkt.src_ip].add(pkt.dst_ip)
        
        # Update flow timing
        pair_key = (pkt.src_ip, pkt.dst_ip)
        self.flow_timestamps[pair_key].append(pkt.timestamp)
        if len(self.flow_timestamps[pair_key]) > 100:
            self.flow_timestamps[pair_key].pop(0)
            
        # Update flow volume
        self.flow_bytes[pair_key]['out'] += pkt.packet_size
        
        # TLS SPLT sequence (first 15 packets)
        if pkt.dst_port == 443 and len(self.tls_splt_sequences[pair_key]) < 15:
            self.tls_splt_sequences[pair_key].append(pkt.packet_size)

    @staticmethod
    def calculate_shannon_entropy(data_list: List[Any]) -> float:
        """Computes Shannon Entropy H(X) = -sum(p_i * log2(p_i))."""
        if not data_list:
            return 0.0
        total = len(data_list)
        counts = Counter(data_list)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def calculate_string_entropy(text: str) -> float:
        """Computes character-level Shannon entropy of string (e.g. FQDN query name)."""
        if not text:
            return 0.0
        return StreamingFeatureExtractor.calculate_shannon_entropy(list(text))

    @staticmethod
    def calculate_ngram_score(text: str) -> float:
        """Calculates bigram/trigram transition anomaly score for FQDNs."""
        if len(text) < 4:
            return 0.0
        consonants = set("bcdfghjklmnpqrstvwxyz")
        consecutive_consonants = 0
        max_consecutive_consonants = 0
        digits_or_special = 0

        for char in text.lower():
            if char in consonants:
                consecutive_consonants += 1
                max_consecutive_consonants = max(max_consecutive_consonants, consecutive_consonants)
            else:
                consecutive_consonants = 0
            if char.isdigit() or char in "-_":
                digits_or_special += 1

        score = (max_consecutive_consonants / len(text)) + (digits_or_special / len(text))
        return round(score, 4)

    def extract_features_for_packet(self, pkt: RawPacketMetadata) -> Dict[str, Any]:
        """Extracts complete feature vector for model inference on given packet."""
        window_size = len(self.packet_buffer)
        
        # 1. Volumetric & Entropy Features
        src_ips_in_window = [p.src_ip for p in self.packet_buffer]
        src_ip_shannon_entropy = self.calculate_shannon_entropy(src_ips_in_window)
        syn_count = sum(1 for p in self.packet_buffer if p.tcp_flags.get("SYN") and not p.tcp_flags.get("ACK"))
        syn_ratio = syn_count / max(1, window_size)
        pps_rate = window_size / max(0.1, self.window_seconds)

        # 2. Beaconing & Periodicity Features
        pair_key = (pkt.src_ip, pkt.dst_ip)
        ts_list = self.flow_timestamps.get(pair_key, [])
        iat_mean = 0.0
        iat_std = 0.0
        iat_cv = 1.0  # Coefficient of variation (sigma / mu)
        if len(ts_list) >= 4:
            iats = [ts_list[i] - ts_list[i-1] for i in range(1, len(ts_list))]
            iat_mean = float(statistics.mean(iats))
            iat_std = float(statistics.stdev(iats)) if len(iats) > 1 else 0.0
            if iat_mean > 0:
                iat_cv = iat_std / iat_mean

        # 3. DNS / DGA Features
        dns_entropy = self.calculate_string_entropy(pkt.dns_query)
        dns_ngram_score = self.calculate_ngram_score(pkt.dns_query)
        dns_len = len(pkt.dns_query)

        # 4. TLS Fingerprints & SPLT
        ja3_match = MALICIOUS_JA3_SIGNATURES.get(pkt.tls_ja3_hash, "")
        ja4_match = MALICIOUS_JA4_SIGNATURES.get(pkt.tls_ja4_hash, "")
        splt_seq = self.tls_splt_sequences.get(pair_key, [])
        splt_var = float(statistics.variance(splt_seq)) if len(splt_seq) >= 2 else 0.0

        # 5. Reconnaissance Fan-Out
        unique_dst_ports = len(self.src_fanout_ports[pkt.src_ip])
        unique_dst_hosts = len(self.src_fanout_hosts[pkt.src_ip])

        # 6. Exfiltration Volume Asymmetry
        flow_stat = self.flow_bytes[pair_key]
        outbound_bytes = flow_stat['out']
        inbound_bytes = max(1, flow_stat['in'])
        byte_ratio = outbound_bytes / inbound_bytes

        return {
            "window_size": window_size,
            "pps_rate": round(pps_rate, 2),
            "src_ip_shannon_entropy": round(src_ip_shannon_entropy, 4),
            "syn_ratio": round(syn_ratio, 4),
            "iat_mean": round(iat_mean, 4),
            "iat_std": round(iat_std, 4),
            "iat_cv": round(iat_cv, 4),
            "dns_query_len": dns_len,
            "dns_entropy": round(dns_entropy, 4),
            "dns_ngram_score": dns_ngram_score,
            "ja3_match": ja3_match,
            "ja4_match": ja4_match,
            "splt_seq_len": len(splt_seq),
            "splt_var": round(splt_var, 2),
            "unique_dst_ports": unique_dst_ports,
            "unique_dst_hosts": unique_dst_hosts,
            "outbound_bytes": outbound_bytes,
            "byte_ratio": round(byte_ratio, 2)
        }
