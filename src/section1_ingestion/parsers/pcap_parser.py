"""
PCAP Parser for network packet capture files.

Extracts security-relevant events from network traffic,
including suspicious connections, potential attacks, and anomalies.
"""

from pathlib import Path
from typing import Optional
from datetime import datetime
from collections import defaultdict

from ..schemas import Finding, Severity, AffectedAsset, SourceType
from .base_parser import BaseParser


class PCAPParser(BaseParser):
    """
    Parser for PCAP network capture files.
    
    Uses Scapy to analyze packet captures and identify:
    - Suspicious port scanning activity
    - Unusual protocol usage
    - High-volume traffic sources
    - Potential data exfiltration
    - Malformed packets
    """
    
    PARSER_NAME = "pcap_parser"
    PARSER_VERSION = "1.0.0"
    SUPPORTED_EXTENSIONS = [".pcap", ".pcapng"]
    SOURCE_TYPE = SourceType.PCAP
    
    # Suspicious ports often associated with attacks
    SUSPICIOUS_PORTS = {
        22: "SSH",
        23: "Telnet", 
        445: "SMB",
        3389: "RDP",
        4444: "Metasploit default",
        5900: "VNC",
        6667: "IRC (often used by botnets)",
        31337: "Back Orifice",
    }
    
    # Thresholds for anomaly detection
    PORT_SCAN_THRESHOLD = 20  # Unique ports from single source
    CONNECTION_FLOOD_THRESHOLD = 100  # Connections to single dest
    
    def __init__(self, file_path: str | Path, max_packets: int = 10000):
        super().__init__(file_path)
        self.max_packets = max_packets
        self.packets = []
        self.packet_count = 0
        
        # Statistics for analysis
        self.src_dst_pairs: dict[tuple, int] = defaultdict(int)
        self.src_ports: dict[str, set] = defaultdict(set)  # src_ip -> set of dst_ports
        self.protocol_counts: dict[str, int] = defaultdict(int)
        self.suspicious_events: list[dict] = []
    
    def _analyze_packets(self) -> None:
        """
        Analyze packets for security-relevant patterns.
        
        This is called after packets are loaded to build statistics.
        """
        try:
            # Import scapy here to avoid import errors if not installed
            from scapy.all import IP, TCP, UDP, ICMP
            
            for pkt in self.packets:
                try:
                    if IP in pkt:
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        
                        # Track source-destination pairs
                        self.src_dst_pairs[(src_ip, dst_ip)] += 1
                        
                        # Track protocols
                        if TCP in pkt:
                            self.protocol_counts['TCP'] += 1
                            dst_port = pkt[TCP].dport
                            self.src_ports[src_ip].add(dst_port)
                            
                            # Check for suspicious ports
                            if dst_port in self.SUSPICIOUS_PORTS:
                                self.suspicious_events.append({
                                    'type': 'suspicious_port',
                                    'src_ip': src_ip,
                                    'dst_ip': dst_ip,
                                    'port': dst_port,
                                    'service': self.SUSPICIOUS_PORTS[dst_port],
                                    'timestamp': float(pkt.time) if hasattr(pkt, 'time') else None,
                                })
                        
                        elif UDP in pkt:
                            self.protocol_counts['UDP'] += 1
                            dst_port = pkt[UDP].dport
                            self.src_ports[src_ip].add(dst_port)
                            
                            # DNS exfiltration check (large DNS queries)
                            if dst_port == 53 and len(pkt) > 512:
                                self.suspicious_events.append({
                                    'type': 'large_dns_query',
                                    'src_ip': src_ip,
                                    'dst_ip': dst_ip,
                                    'size': len(pkt),
                                })
                        
                        elif ICMP in pkt:
                            self.protocol_counts['ICMP'] += 1
                        
                        else:
                            self.protocol_counts['Other'] += 1
                
                except Exception as e:
                    self.add_warning(f"Error analyzing packet: {e}")
            
            # Detect port scanning
            for src_ip, ports in self.src_ports.items():
                if len(ports) >= self.PORT_SCAN_THRESHOLD:
                    self.suspicious_events.append({
                        'type': 'port_scan',
                        'src_ip': src_ip,
                        'unique_ports': len(ports),
                        'sample_ports': list(ports)[:10],
                    })
            
            # Detect connection flooding
            for (src_ip, dst_ip), count in self.src_dst_pairs.items():
                if count >= self.CONNECTION_FLOOD_THRESHOLD:
                    self.suspicious_events.append({
                        'type': 'connection_flood',
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'connection_count': count,
                    })
        
        except ImportError:
            self.add_error("Scapy is not installed. Run: pip install scapy")
    
    def parse(self) -> list[Finding]:
        """Parse the PCAP file and extract security findings."""
        findings = []
        
        try:
            # Import scapy
            from scapy.all import rdpcap, PcapReader
            
            # Use PcapReader for memory efficiency with large files
            try:
                with PcapReader(str(self.file_path)) as pcap_reader:
                    for i, pkt in enumerate(pcap_reader):
                        if i >= self.max_packets:
                            self.add_warning(f"Stopped at {self.max_packets} packets (limit reached)")
                            break
                        self.packets.append(pkt)
                        self.packet_count += 1
            except Exception:
                # Fallback to rdpcap for problematic files
                self.packets = rdpcap(str(self.file_path), count=self.max_packets)
                self.packet_count = len(self.packets)
            
            if not self.packets:
                self.add_warning("No packets found in PCAP file")
                return findings
            
            # Analyze packets for suspicious activity
            self._analyze_packets()
            
            # Convert suspicious events to findings
            for event in self.suspicious_events:
                if event['type'] == 'port_scan':
                    finding = Finding(
                        severity=Severity.HIGH,
                        title=f"Potential Port Scan from {event['src_ip']}",
                        description=(
                            f"Host {event['src_ip']} connected to {event['unique_ports']} unique ports, "
                            f"which may indicate port scanning activity. "
                            f"Sample ports: {event['sample_ports']}"
                        ),
                        affected_assets=[AffectedAsset(identifier=event['src_ip'], asset_type="source_host")],
                        raw_excerpt=str(event),
                        source_ip=event['src_ip'],
                        protocol="TCP/UDP",
                    )
                    findings.append(finding)
                
                elif event['type'] == 'connection_flood':
                    finding = Finding(
                        severity=Severity.MEDIUM,
                        title=f"High Connection Volume: {event['src_ip']} → {event['dst_ip']}",
                        description=(
                            f"Detected {event['connection_count']} connections from {event['src_ip']} "
                            f"to {event['dst_ip']}. This could indicate a DoS attempt, "
                            f"data exfiltration, or legitimate high-traffic application."
                        ),
                        affected_assets=[
                            AffectedAsset(identifier=event['src_ip'], asset_type="source_host"),
                            AffectedAsset(identifier=event['dst_ip'], asset_type="destination_host"),
                        ],
                        raw_excerpt=str(event),
                        source_ip=event['src_ip'],
                        destination_ip=event['dst_ip'],
                    )
                    findings.append(finding)
                
                elif event['type'] == 'suspicious_port':
                    finding = Finding(
                        severity=Severity.MEDIUM,
                        title=f"Connection to Suspicious Port: {event['service']} ({event['port']})",
                        description=(
                            f"Connection from {event['src_ip']} to {event['dst_ip']} on port {event['port']} "
                            f"({event['service']}). This port is commonly associated with attacks or "
                            f"services that should be monitored."
                        ),
                        affected_assets=[
                            AffectedAsset(identifier=event['src_ip'], asset_type="source_host"),
                            AffectedAsset(identifier=event['dst_ip'], asset_type="destination_host"),
                        ],
                        raw_excerpt=str(event),
                        source_ip=event['src_ip'],
                        destination_ip=event['dst_ip'],
                        protocol="TCP",
                    )
                    findings.append(finding)
                
                elif event['type'] == 'large_dns_query':
                    finding = Finding(
                        severity=Severity.LOW,
                        title=f"Large DNS Query from {event['src_ip']}",
                        description=(
                            f"Unusually large DNS query ({event['size']} bytes) from {event['src_ip']} "
                            f"to {event['dst_ip']}. Large DNS queries can be used for data exfiltration "
                            f"via DNS tunneling."
                        ),
                        affected_assets=[AffectedAsset(identifier=event['src_ip'], asset_type="host")],
                        raw_excerpt=str(event),
                        source_ip=event['src_ip'],
                        destination_ip=event['dst_ip'],
                        protocol="DNS",
                    )
                    findings.append(finding)
            
            # If no suspicious events but we have packets, create a summary finding
            if not findings and self.packet_count > 0:
                protocol_summary = ", ".join(f"{proto}: {count}" for proto, count in self.protocol_counts.items())
                finding = Finding(
                    severity=Severity.INFO,
                    title=f"Network Traffic Summary ({self.packet_count} packets)",
                    description=(
                        f"Analyzed {self.packet_count} packets. "
                        f"Protocol distribution: {protocol_summary}. "
                        f"No obviously suspicious activity detected, but manual review recommended."
                    ),
                    raw_excerpt=f"Packets: {self.packet_count}, Protocols: {dict(self.protocol_counts)}",
                )
                findings.append(finding)
        
        except ImportError:
            self.add_error("Scapy is not installed. Install with: pip install scapy")
        except Exception as e:
            self.add_error(f"Error reading PCAP file: {e}")
        
        return findings
    
    def extract_document_summary(self) -> Optional[str]:
        """Generate summary from parsed data."""
        if self.packet_count == 0:
            return None
        
        protocol_summary = ", ".join(f"{proto}: {count}" for proto, count in self.protocol_counts.items())
        unique_sources = len(set(src for src, dst in self.src_dst_pairs.keys()))
        unique_dests = len(set(dst for src, dst in self.src_dst_pairs.keys()))
        
        return (
            f"PCAP with {self.packet_count} packets. "
            f"Protocols: {protocol_summary}. "
            f"Unique sources: {unique_sources}, Unique destinations: {unique_dests}. "
            f"Suspicious events detected: {len(self.suspicious_events)}."
        )
