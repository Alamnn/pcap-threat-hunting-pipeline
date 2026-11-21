from pathlib import Path
from scripts.generate_test_pcap import generate_pcap
from hunt import run_hunt


def test_pcap_hunt_extracts_iocs_and_generates_nist_report(tmp_path):
    pcap = tmp_path / "test.pcap"
    report = tmp_path / "incident_report.md"
    generate_pcap(pcap)
    analysis = run_hunt(pcap, report)

    assert len(analysis["beacons"]) == 1
    assert analysis["beacons"][0]["domain"] == "c2-beacon.darkops-sync.example"
    assert analysis["beacons"][0]["avg_interval_sec"] == 60.0
    assert len(analysis["suricata_alerts"]) >= 4
    text = report.read_text()
    assert "NIST SP 800-61" in text
    assert "CobaltStrike" in text
    assert "198.51.100.77" in text
