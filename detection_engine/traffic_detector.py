"""
Network traffic detection engine.

Input formats:
  - Zeek (conn.log, dns.log, http.log, ssl.log, files.log) as dicts
  - Suricata EVE JSON
  - NetFlow v9/IPFIX records (normalized)
  - Raw PCAP (via scapy - optional)

Key technique coverage:
  T1041   - Exfiltration Over C2 Channel (large outbound, beaconing)
  T1043   - Commonly Used Port (non-standard protocols on standard ports)
  T1048   - Exfiltration Over Alternative Protocol (DNS tunneling, ICMP)
  T1071   - Application Layer Protocol (HTTP/S C2, DNS C2)
  T1090   - Proxy (onion routing patterns, multi-hop)
  T1095   - Non-Application Layer Protocol
  T1102   - Web Service (GitHub/Pastebin as C2)
  T1205   - Traffic Signaling (port knocking)
  T1219   - Remote Access Software (RDP, VNC, TeamViewer beacon patterns)
  T1498   - Network DoS
  T1571   - Non-Standard Port
  T1572   - Protocol Tunneling (DNS-over-HTTPS, ICMP)
  T1590   - Gather Victim Network Information (scanning patterns)
  ... implement all network-observable techniques

Detection signatures:
  - Beacon detection: coefficient of variation < 0.3 over >= 10 intervals
  - DNS tunneling: query length > 50 chars OR entropy > 3.5
  - Exfil: outbound bytes > 3x baseline AND destination = new
  - Port scan: > 15 unique dst_ports to same dst_ip within 60s window
"""

import math
import statistics
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional

from .base import BaseDetector, DetectionFinding


class TrafficDetector(BaseDetector):
    def __init__(self, index):
        super().__init__(index)
        self._conn_history = defaultdict(deque)
        self._dns_history = defaultdict(deque)
        self._scan_tracker = defaultdict(deque)
        self._baseline_bytes = defaultdict(lambda: 1024 * 1024)

    def detect(self, data: List[Dict[str, Any]]) -> List[DetectionFinding]:
        findings = []
        for record in data:
            record_type = record.get("record_type", "").lower()
            if record_type in ("conn", "zeek_conn", "connection"):
                findings.extend(self._analyze_connection(record))
            elif record_type in ("dns", "zeek_dns"):
                findings.extend(self._analyze_dns(record))
            elif record_type in ("http", "zeek_http"):
                findings.extend(self._analyze_http(record))
            elif record_type in ("netflow", "flow"):
                findings.extend(self._analyze_netflow(record))
            elif record_type in ("suricata", "eve"):
                findings.extend(self._analyze_suricata(record))
        return findings

    def _analyze_connection(self, record: Dict) -> List[DetectionFinding]:
        findings = []
        src_ip = record.get("src_ip", "")
        dst_ip = record.get("dst_ip", "")
        record.get("src_port", 0)
        dst_port = record.get("dst_port", 0)
        record.get("proto", "").upper()
        bytes_out = record.get("bytes_out", 0) or record.get("orig_bytes", 0)
        bytes_in = record.get("bytes_in", 0) or record.get("resp_bytes", 0)
        duration = record.get("duration", 0)
        timestamp = record.get("timestamp", "")

        key = f"{src_ip}->{dst_ip}:{dst_port}"
        self._conn_history[key].append(
            {
                "timestamp": timestamp,
                "bytes_out": bytes_out,
                "bytes_in": bytes_in,
                "duration": duration,
            }
        )

        if len(self._conn_history[key]) >= 10:
            if self._is_beaconing(self._conn_history[key]):
                findings.append(
                    self._make_finding(
                        "T1071.001",
                        "HTTP Beaconing Detected",
                        "HIGH",
                        0.85,
                        record,
                        f"Regular interval connections to {dst_ip}:{dst_port}",
                    )
                )

        if bytes_out > self._baseline_bytes[src_ip] * 3:
            if dst_ip not in self._get_known_destinations(src_ip):
                findings.append(
                    self._make_finding(
                        "T1041",
                        "Large Outbound Data Transfer to New Destination",
                        "HIGH",
                        0.8,
                        record,
                        f"{bytes_out} bytes to {dst_ip}:{dst_port} (baseline: {self._baseline_bytes[src_ip]})",
                    )
                )
            self._baseline_bytes[src_ip] = max(self._baseline_bytes[src_ip], bytes_out)

        self._track_port_scan(src_ip, dst_ip, dst_port, timestamp)

        return findings

    def _is_beaconing(self, history: deque) -> bool:
        intervals = []
        for i in range(1, len(history)):
            try:
                t1 = float(history[i - 1].get("timestamp", 0))
                t2 = float(history[i].get("timestamp", 0))
                intervals.append(t2 - t1)
            except (ValueError, TypeError):
                return False
        if len(intervals) < 5:
            return False
        mean = statistics.mean(intervals)
        if mean == 0:
            return False
        stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
        cv = stdev / mean
        return cv < 0.3

    def _get_known_destinations(self, src_ip: str) -> set:
        return set()

    def _track_port_scan(self, src_ip: str, dst_ip: str, dst_port: int, timestamp: str):
        key = f"{src_ip}->{dst_ip}"
        try:
            ts = float(timestamp)
            self._scan_tracker[key].append((ts, dst_port))
            cutoff = ts - 60
            self._scan_tracker[key] = deque(
                [(t, p) for t, p in self._scan_tracker[key] if t > cutoff]
            )
            unique_ports = set(p for t, p in self._scan_tracker[key])
            if len(unique_ports) > 15:
                return True
        except (ValueError, TypeError):
            pass
        return False

    def _analyze_dns(self, record: Dict) -> List[DetectionFinding]:
        findings = []
        query = record.get("query", "").lower()
        qtype = record.get("qtype", "").upper()
        record.get("src_ip", "")
        answers = record.get("answers", [])

        if len(query) > 50:
            entropy = self._shannon_entropy(query)
            if entropy > 3.5:
                findings.append(
                    self._make_finding(
                        "T1048.003",
                        "DNS Tunneling - High Entropy Query",
                        "HIGH",
                        0.9,
                        record,
                        f"Query: {query[:100]} (entropy={entropy:.2f})",
                    )
                )

        if qtype == "TXT" and len(query) > 30:
            findings.append(
                self._make_finding(
                    "T1048.003",
                    "DNS Tunneling - TXT Record Query",
                    "MEDIUM",
                    0.75,
                    record,
                    f"TXT query: {query[:100]}",
                )
            )

        if qtype in ("A", "AAAA") and answers:
            for ans in answers:
                if ans.get("type") in ("A", "AAAA"):
                    ip = ans.get("data", "")
                    if self._is_suspicious_ip(ip):
                        findings.append(
                            self._make_finding(
                                "T1071.004",
                                "DNS C2 - Fast Flux / Suspicious IP",
                                "MEDIUM",
                                0.7,
                                record,
                                f"Domain {query} resolved to {ip}",
                            )
                        )

        return findings

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0
        freq = defaultdict(int)
        for c in data:
            freq[c] += 1
        entropy = 0
        n = len(data)
        for count in freq.values():
            p = count / n
            entropy -= p * math.log2(p)
        return entropy

    def _is_suspicious_ip(self, ip: str) -> bool:
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                return int(parts[0]) >= 224 or int(parts[0]) == 0
        except (ValueError, IndexError):
            pass
        return False

    def _analyze_http(self, record: Dict) -> List[DetectionFinding]:
        findings = []
        method = record.get("method", "").upper()
        uri = record.get("uri", "")
        host = record.get("host", "")
        user_agent = record.get("user_agent", "")
        record.get("src_ip", "")
        record.get("status_code", 0)

        suspicious_ua = [
            "python",
            "curl",
            "wget",
            "go-http",
            "java/",
            "apache-httpclient",
            "powershell",
            "winhttp",
            "msie",
            "mozilla/4.0",
            "bot",
            "scanner",
        ]
        if any(s in user_agent.lower() for s in suspicious_ua):
            findings.append(
                self._make_finding(
                    "T1071.001",
                    "Suspicious HTTP User Agent",
                    "MEDIUM",
                    0.7,
                    record,
                    f"UA: {user_agent[:100]}",
                )
            )

        if "github.com" in host or "raw.githubusercontent.com" in host:
            if "pastebin" in uri or "gist" in uri or "/raw/" in uri:
                findings.append(
                    self._make_finding(
                        "T1102",
                        "Web Service C2 - GitHub/Pastebin",
                        "MEDIUM",
                        0.75,
                        record,
                        f"Request to {host}{uri}",
                    )
                )

        if method == "POST" and len(uri) > 100:
            findings.append(
                self._make_finding(
                    "T1071.001",
                    "Long URI POST - Potential C2",
                    "LOW",
                    0.5,
                    record,
                    f"POST {uri[:200]}",
                )
            )

        return findings

    def _analyze_netflow(self, record: Dict) -> List[DetectionFinding]:
        return self._analyze_connection(record)

    def _analyze_suricata(self, record: Dict) -> List[DetectionFinding]:
        findings = []
        event_type = record.get("event_type", "")
        if event_type == "alert":
            alert = record.get("alert", {})
            signature = alert.get("signature", "")
            severity = alert.get("severity", 3)
            sev_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
            findings.append(
                self._make_finding(
                    "T1190",
                    f"Suricata Alert: {signature}",
                    sev_map.get(severity, "MEDIUM"),
                    0.8,
                    record,
                    f"Suricata signature: {signature}",
                )
            )
        return findings

    def _make_finding(
        self,
        tech_id: str,
        rule_name: str,
        severity: str,
        confidence: float,
        evidence: Dict,
        description: str,
    ) -> Optional[DetectionFinding]:
        mapping = self._build_mapping(tech_id, confidence)
        if mapping is None:
            return None
        return DetectionFinding(
            rule_id=f"NET-{tech_id.replace('.', '-')}",
            rule_name=rule_name,
            severity=severity,
            confidence=confidence,
            source_type="traffic",
            raw_evidence=evidence,
            mappings=[mapping],
            timestamp=str(evidence.get("timestamp", "")),
            host=evidence.get("src_ip", ""),
            description=description,
        )
