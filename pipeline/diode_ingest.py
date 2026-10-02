"""
NTRO Unidirectional Cyber Threat Detection - Read-Only Diode Ingest Module
Simulates a hardware data diode (TX -> RX enclave) passive network stream ingest.
Guarantees NO return path, NO socket binding to egress, and strictly read-only parsing.
"""

from dataclasses import dataclass
import time
import random
import math
from typing import Generator, Dict, Any, List

@dataclass
class RawPacketMetadata:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packet_size: int
    tcp_flags: Dict[str, bool]
    dns_query: str = ""
    dns_record_type: str = ""
    tls_ja3_hash: str = ""
    tls_ja4_hash: str = ""
    tls_sni: str = ""
    payload_len: int = 0


class UnidirectionalDiodeIngest:
    """
    Passive Ingest Receiver sitting inside the Monitoring Enclave.
    Enforces Strict Read-Only Semantics:
    1. Socket write methods are disabled or absent.
    2. Stream is processed in real-time order with bounded buffer size.
    """
    def __init__(self, interface_name: str = "diode_rx0"):
        self.interface_name = interface_name
        self.total_packets_received = 0
        self.total_bytes_received = 0
        self.start_time = time.time()
        self.is_active = True

    def block_egress_attempts(self):
        """Proof of unidirectional enforcement: Raises PermissionError on any transmit attempt."""
        raise PermissionError("DATA DIODE PHYSICAL CONSTRAINT: Transmit capability is hardware disabled (TX fiber disconnected).")

    def generate_simulated_stream(
        self, 
        count: int = 1000, 
        threat_scenario: str = "NORMAL",
        flows_per_sec: int = 5000
    ) -> Generator[RawPacketMetadata, None, None]:
        """
        Generates simulated passive NetFlow/PCAP stream passing through data diode.
        Supports scenarios: NORMAL, DDOS_SYN_FLOOD, BOTNET_BEACON, DGA_DNS_TUNNEL, TLS_MALWARE, SCANNING, EXFILTRATION.
        """
        normal_srcs = [f"192.168.1.{i}" for i in range(10, 250)]
        normal_dsts = ["10.0.0.5", "10.0.0.10", "140.82.112.4", "172.217.16.206"]
        c2_ip = "185.220.101.5"
        exfil_ip = "45.33.32.156"

        beacon_timer = 0.0

        for i in range(count):
            if not self.is_active:
                break

            now = time.time()
            proto = "TCP"
            s_ip = random.choice(normal_srcs)
            d_ip = random.choice(normal_dsts)
            s_port = random.randint(1024, 65535)
            d_port = random.choice([80, 443, 53, 22, 8080])
            pkt_size = random.randint(64, 1500)
            flags = {"SYN": False, "ACK": True, "FIN": False, "RST": False, "UDP": False}
            dns_q = ""
            dns_type = ""
            ja3 = ""
            ja4 = ""
            sni = ""

            # Inject threat vectors based on scenario or probability
            curr_scenario = threat_scenario
            if threat_scenario == "MIXED":
                r = random.random()
                if r < 0.15: curr_scenario = "DDOS_SYN_FLOOD"
                elif r < 0.25: curr_scenario = "BOTNET_BEACON"
                elif r < 0.35: curr_scenario = "DGA_DNS_TUNNEL"
                elif r < 0.45: curr_scenario = "TLS_MALWARE"
                elif r < 0.55: curr_scenario = "SCANNING"
                elif r < 0.65: curr_scenario = "EXFILTRATION"
                else: curr_scenario = "NORMAL"

            if curr_scenario == "DDOS_SYN_FLOOD":
                # Spoofed random src IPs sending high volume SYN packets to single victim port
                s_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                d_ip = "10.0.0.5"
                d_port = 80
                flags = {"SYN": True, "ACK": False, "FIN": False, "RST": False, "UDP": False}
                pkt_size = 64

            elif curr_scenario == "BOTNET_BEACON":
                # Fixed low-variance inter-arrival time to C2 IP
                s_ip = "192.168.1.105"
                d_ip = c2_ip
                d_port = 8443
                pkt_size = 256
                ja4 = "t13d151600_8daaf6152771_b123456789ab"
                # Simulated fixed 10.0s interval tick

            elif curr_scenario == "DGA_DNS_TUNNEL":
                proto = "UDP"
                flags["UDP"] = True
                d_port = 53
                if random.random() < 0.5:
                    # DGA domain
                    random_sub = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=28))
                    dns_q = f"{random_sub}.botnet-malicious-zone.cx"
                    dns_type = "A"
                else:
                    # DNS Tunnelling (High entropy payload encoded in TXT record query)
                    b64_payload = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=64))
                    dns_q = f"{b64_payload}.exfil-stego-channel.org"
                    dns_type = "TXT"

            elif curr_scenario == "TLS_MALWARE":
                d_port = 443
                s_ip = "192.168.1.188"
                ja3 = "e7ed349cc2f6ddef17227b93d7783801"  # Known malware JA3 fingerprint (e.g., TrickBot / AsyncRAT)
                ja4 = "t13d151600_8daaf6152771_e3b0c44298fc"
                sni = "update-service-cdn-check.biz"
                pkt_size = random.choice([512, 1024, 1460])

            elif curr_scenario == "SCANNING":
                # Single source sweeping multiple dest ports / hosts rapidly
                s_ip = "192.168.1.99"
                d_port = random.randint(1, 1024)
                d_ip = f"10.0.0.{random.randint(1, 254)}"
                flags = {"SYN": True, "ACK": False, "FIN": False, "RST": False, "UDP": False}

            elif curr_scenario == "EXFILTRATION":
                s_ip = "192.168.1.50"  # Internal sensitive server
                d_ip = exfil_ip
                d_port = 443
                pkt_size = 1460  # Large outbound packet burst
                flags = {"SYN": False, "ACK": True, "FIN": False, "RST": False, "UDP": False}

            self.total_packets_received += 1
            self.total_bytes_received += pkt_size

            yield RawPacketMetadata(
                timestamp=now,
                src_ip=s_ip,
                src_port=s_port,
                dst_ip=d_ip,
                dst_port=d_port,
                protocol=proto,
                packet_size=pkt_size,
                tcp_flags=flags,
                dns_query=dns_q,
                dns_record_type=dns_type,
                tls_ja3_hash=ja3,
                tls_ja4_hash=ja4,
                tls_sni=sni,
                payload_len=max(0, pkt_size - 40)
            )
