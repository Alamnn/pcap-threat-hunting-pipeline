# NIST SP 800-61 Computer Security Incident Response Report

**Artifact Analyzed:** `sample.pcap`  
**Telemetry Engines:** Zeek Network Security Monitor (`conn.log`, `dns.log`, `http.log`) & Suricata IDS (`eve.json`)  
**Incident Classification:** Multi-Stage Intrusion — Internal Reconnaissance (`T1046`), Web Exploitation (`T1190`), & CobaltStrike DNS/HTTP C2 Beaconing (`T1071.001`, `T1071.004`)

---

## 1. Executive Summary (NIST SP 800-61 Phase 1 & 2: Detection & Analysis)

Automated threat hunting across `sample.pcap` processed **15 TCP connections** and **7 DNS transactions**, uncovering two compromised/malicious internal hosts:
1. **`10.20.30.99` (Reconnaissance & Web Exploit Host):** Executed a 12-port rapid TCP SYN scan against internal server `10.20.30.10` followed by an automated `sqlmap/1.8.7` directory traversal (`../../../../etc/passwd`) against `/admin/export.php`.
2. **`10.20.30.55` (C2-Compromised Workstation):** Exhibited deterministic DNS C2 beaconing every **60.0 seconds** (`0.0s` jitter across 6 intervals) to `c2-beacon.darkops-sync.example`, followed by HTTP stage-2 check-in (`User-Agent: Mozilla/5.0 (CobaltStrike/4.9)`) and data exfiltration (`POST /exfil/upload`) to external C2 IP `198.51.100.77`.

## 2. Incident Timeline

| Timestamp (UTC) | Source IP | Destination | Protocol / Sensor | Event Description |
|---|---|---|---|---|
| `2025-11-21T15:46:40.450000Z` | `10.20.30.99` | `10.20.30.10:3306` | Suricata (`TCP`) | **ET SCAN Rapid Multi-Port TCP SYN Scan Detected** (`SID:2001219`) |
| `2025-11-21T15:47:05.000000Z` | `10.20.30.55` | `198.51.100.77:80` | Suricata (`TCP`) | **ET MALWARE CobaltStrike HTTP C2 Beacon Checkin** (`SID:2034101`) |
| `2025-11-21T15:47:10.000000Z` | `10.20.30.99` | `10.20.30.10:80` | Suricata (`TCP`) | **ET WEB_SERVER SQLMap User-Agent & LFI /etc/passwd Traversal** (`SID:2008538`) |
| `2025-11-21T15:51:50.000000Z` | `10.20.30.55` | `8.8.8.8:53` | Suricata (`UDP`) | **ET C2 Periodic DNS Beaconing Detected (c2-beacon.darkops-sync.example)** (`SID:2049001`) |
| `2025-11-21T15:47:05.000000Z` | `10.20.30.55` | `198.51.100.77:80` | Zeek (`http.log`) | `GET /stage2/beacon_checkin.php?id=host55` (UA: `Mozilla/5.0 (CobaltStrike/4.9)`) |
| `2025-11-21T15:47:10.000000Z` | `10.20.30.99` | `10.20.30.10:80` | Zeek (`http.log`) | `GET /admin/export.php?file=../../../../etc/passwd` (UA: `sqlmap/1.8.7#stable (https://sqlmap.org)`) |
| `2025-11-21T15:48:15.000000Z` | `10.20.30.55` | `198.51.100.77:80` | Zeek (`http.log`) | `POST /exfil/upload` (UA: `curl/8.5.0`) |

## 3. Extracted Indicators of Compromise (IOCs)

### 3.1 Top Talkers (`conn.log` + `dns.log`)
| Host IP | Total Flows | Role / Assessment |
|---|---|---|
| `10.20.30.99` | 13 | Scanner & LFI Attacker |
| `10.20.30.55` | 8 | Compromised C2 Beaconing Host |
| `10.20.30.15` | 1 | Benign Workstation |

### 3.2 DNS C2 Beaconing Analysis (`dns.log`)
| Source IP | Queried C2 Domain | Query Count | Avg Interval (s) | Jitter (s) | Verdict |
|---|---|---|---|---|---|
| `10.20.30.55` | `c2-beacon.darkops-sync.example` | 6 | **60.0s** | **0.0s** | **CONFIRMED C2 BEACON** |

### 3.3 Suspicious HTTP User-Agents & URIs (`http.log`)
| Source IP | Destination Host | Method & URI | HTTP User-Agent |
|---|---|---|---|
| `10.20.30.55` | `c2-beacon.darkops-sync.example` | `GET /stage2/beacon_checkin.php?id=host55` | `Mozilla/5.0 (CobaltStrike/4.9)` |
| `10.20.30.99` | `10.20.30.10` | `GET /admin/export.php?file=../../../../etc/passwd` | `sqlmap/1.8.7#stable (https://sqlmap.org)` |
| `10.20.30.55` | `198.51.100.77` | `POST /exfil/upload` | `curl/8.5.0` |

## 4. Suricata IDS Alert Signatures (`eve.json`)

| SID | Severity | Category | Signature | Source -> Destination |
|---|---|---|---|---|
| `2001219` | `P2` | Attempted Information Leak | **ET SCAN Rapid Multi-Port TCP SYN Scan Detected** | `10.20.30.99 -> 10.20.30.10:3306` |
| `2034101` | `P1` | A Network Trojan was Detected | **ET MALWARE CobaltStrike HTTP C2 Beacon Checkin** | `10.20.30.55 -> 198.51.100.77:80` |
| `2008538` | `P1` | Web Application Attack | **ET WEB_SERVER SQLMap User-Agent & LFI /etc/passwd Traversal** | `10.20.30.99 -> 10.20.30.10:80` |
| `2049001` | `P1` | Malware Command and Control Activity Detected | **ET C2 Periodic DNS Beaconing Detected (c2-beacon.darkops-sync.example)** | `10.20.30.55 -> 8.8.8.8:53` |

## 5. Containment, Eradication & Remediation (NIST SP 800-61 Phase 3)

1. **Immediate Network Containment:** Isolate workstation `10.20.30.55` and rogue scanner `10.20.30.99` at the switch/EDR level. Sinkhole `c2-beacon.darkops-sync.example` at internal DNS resolvers and block egress to `198.51.100.77/32` at the perimeter firewall.
2. **Eradication & Forensics:** Acquire volatile memory image from `10.20.30.55` to extract the CobaltStrike beacon configuration, inspect persistence mechanisms, and rotate credentials for any user sessions active on `10.20.30.55` and `10.20.30.10`.
3. **Application Hardening:** Patch `/admin/export.php` on `10.20.30.10` to enforce strict path canonicalization and deploy ModSecurity CRS LFI rules (`930100`/`930110`).
