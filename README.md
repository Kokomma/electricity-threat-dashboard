# 🛡️ Electricity Infrastructure Threat Dashboard — SEC-001

> **Cybersecurity monitoring dashboard for Nigerian power sector ICS/OT systems — simulated SCADA attack logs, MITRE ATT&CK for ICS tagging, ELK Stack, and automated detection rules.**

![ELK](https://img.shields.io/badge/ELK_Stack-8.13-005571?logo=elastic)
![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-ICS-red)

---

## 🎯 Problem Statement

Nigeria's electricity infrastructure is **critical national infrastructure** — yet most DisCos operate SCADA systems with zero security monitoring. ICS-specific threats (DNP3 replay, GOOSE spoofing, Modbus manipulation) are entirely unknown to IT security teams, and NERC has no standardised framework for DisCo cybersecurity reporting.

**This project builds a proof-of-concept ICS threat monitoring dashboard:**
- 10 realistic attack scenarios targeting Nigerian grid assets
- Every event tagged to MITRE ATT&CK for ICS (T0800–T0891)
- Full ELK Stack via Docker Compose (Elasticsearch + Logstash + Kibana)
- 5 Kibana SIEM detection rules with automated severity alerting
- GeoIP enrichment and ICS protocol-aware escalation

---

## 🏗️ Architecture

┌──────────────────────────────────────────────────────────────┐
│              ATTACK SIMULATION (log_generator.py)            │
│  10 scenarios: Brute Force | Modbus Scan | IEC 61850 Trip    │
│  DNP3 Replay | Data Exfil | Ransomware | Phishing | PLC Manip│
│  Output: logs/ics_security_events.jsonl                      │
└─────────────────────┬────────────────────────────────────────┘
│ Filebeat ships logs
▼
┌─────────────────────────────────────────────────────────────┐
│                    LOGSTASH                                   │
│  JSON parse → GeoIP enrichment → Severity scoring           │
│  ICS protocol tagging → MITRE ID extraction                 │
└─────────────────────┬───────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│                 ELASTICSEARCH                                 │
│  Index: nserc-ics-threats-YYYY.MM.DD                        │
└─────────────────────┬───────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────┐
│                    KIBANA                                     │
│  Threat Overview · MITRE Heatmap · Geo Attack Map           │
│  5 Detection Rules · Alert Timeline · DisCo Breakdown       │
└─────────────────────────────────────────────────────────────┘
---

## 🚀 Quick Start

### Step 1 — Generate Attack Logs
```bash
git clone https://github.com/Kokomma/electricity-threat-dashboard
cd electricity-threat-dashboard
pip install -r requirements.txt
python log_generator/log_generator.py
```

### Step 2 — Start ELK Stack
```bash
docker-compose up -d
# Wait ~2 minutes for all services to start
```

### Step 3 — Verify Elasticsearch received data
```bash
curl http://localhost:9200/nserc-ics-threats-*/_count
```

### Step 4 — Setup Kibana detection rules
```bash
python detection/setup_kibana.py
```

### Step 5 — Open Kibana
http://localhost:5601
Analytics → Discover → select "NSERC ICS Threat Logs"
Security → Rules → enable NSERC detection rules

---

## ⚔️ Attack Scenarios

| Scenario | MITRE Technique | Severity | Protocol |
|---------|----------------|----------|---------|
| SCADA Brute Force | T0866 — Exploitation of Remote Services | HIGH | RDP |
| Modbus Reconnaissance | T0846 — Remote System Discovery | MEDIUM | Modbus/TCP |
| IEC 61850 Trip Command | T0855 — Unauthorized Command | CRITICAL | IEC 61850 |
| Historian Exfiltration | T0852 — Data Collection | HIGH | SMB |
| Ransomware Lateral Movement | T0812 — Default Credentials | CRITICAL | SMB |
| DNP3 Replay Attack | T0830 — Adversary-in-the-Middle | CRITICAL | DNP3 |
| VPN Phishing | T0865 — Spearphishing Attachment | MEDIUM | HTTPS |
| PLC Process Manipulation | T0800 — Firmware Manipulation | CRITICAL | Modbus/TCP |
| OT Network Port Scan | T0840 — Network Enumeration | LOW | ICMP |
| Engineering WS Compromise | T0871 — Execution through API | HIGH | WinRM |

---

## 💼 Business Impact

> *"Demonstrates a production-ready ICS security monitoring capability for Nigerian DisCos — a near-zero-competition niche in Nigerian cybersecurity consulting. Maps directly to NERC CIP compliance requirements being introduced for licensed DisCos, positioning this as a consulting offering worth ₦15–50M per engagement."*

---

## 🛠️ Tools Used

| Tool | Purpose |
|------|---------|
| Python 3.11 | Log generation, Kibana setup |
| Elasticsearch 8.13 | Search and analytics engine |
| Logstash 8.13 | Log ingestion and enrichment |
| Kibana 8.13 | Visualisation and SIEM |
| Filebeat 8.13 | Log shipping |
| Docker Compose | Full stack orchestration |
| MITRE ATT&CK for ICS | Threat classification framework |

---

*Built by Ella — Portfolio | [LinkedIn](https://linkedin.com/in/emmanuella-samuel/) | [GitHub](https://github.com/Kokomma)*
