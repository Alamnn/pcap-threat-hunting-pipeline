# pcap-threat-hunting-pipeline: Containerized Zeek & Suricata Threat Hunting Pipeline

**Problem:** DFIR analysts and threat hunters need an automated pipeline that ingests raw packet captures (`.pcap`), generates structured **Zeek** (`conn.log`, `dns.log`, `http.log`) and **Suricata** (`eve.json`) telemetry without heavy VMs, detects periodic C2 DNS beaconing and malicious HTTP User-Agents, and produces a **NIST SP 800-61** incident response report.

## Architecture & Workflow

```text
input_pcaps/sample.pcap  (Generated via scripts/generate_test_pcap.py using Scapy)
        |
        +---> Zeek Network Monitor  ---> logs/zeek/{conn.log, dns.log, http.log}
        |
        +---> Suricata IDS Engine   ---> logs/suricata/eve.json
        |
        v
   hunt.py  ---> IOC Extraction (Top Talkers, 60.0s C2 Beacon Jitter, HTTP UAs, SIDs)
        |
        v
   reports/sample_incident_report.md  (NIST SP 800-61 Incident Report)
```

## Quick Start & Usage

```bash
# 1. Generate synthetic test PCAP (TCP port scan + 60s DNS C2 beacon + CobaltStrike/sqlmap HTTP)
python3 scripts/generate_test_pcap.py

# 2. Run the threat hunting pipeline and generate NIST SP 800-61 incident report
python3 hunt.py --pcap input_pcaps/sample.pcap --out reports/sample_incident_report.md

# 3. Run unit tests
pytest -q tests
```

## Visual Proof

![hunt](docs/screenshots/01_pcap_hunt.png)

Sample generated report: [reports/sample_incident_report.md](reports/sample_incident_report.md)
