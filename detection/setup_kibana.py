"""
setup_kibana.py
===============
Automates Kibana setup for the NSERC Threat Dashboard:
  1. Waits for Kibana to be ready
  2. Creates index pattern for nserc-ics-threats-*
  3. Installs 5 SIEM detection rules
  4. Verifies data is indexed in Elasticsearch

Run after: docker-compose up -d && python log_generator/log_generator.py

Author: Ella | NSERC Portfolio SEC-001
"""

import json
import time
import requests

KIBANA_URL = "http://localhost:5601"
ES_URL     = "http://localhost:9200"
HEADERS    = {"Content-Type": "application/json", "kbn-xsrf": "true"}


def wait_for_kibana(max_wait=120):
    print("Waiting for Kibana...")
    for i in range(max_wait // 5):
        try:
            r = requests.get(f"{KIBANA_URL}/api/status", timeout=5)
            if r.status_code == 200:
                level = r.json().get("status", {}).get("overall", {}).get("level", "")
                if level in ("available", "degraded"):
                    print(f"Kibana ready (status: {level})")
                    return True
        except Exception:
            pass
        time.sleep(5)
        print(f"  Still waiting... ({(i+1)*5}s elapsed)")
    raise TimeoutError("Kibana did not become ready in time. Check: docker-compose ps")


def create_index_pattern():
    payload = {
        "data_view": {
            "title": "nserc-ics-threats-*",
            "name": "NSERC ICS Threat Logs",
            "timeFieldName": "@timestamp",
        }
    }
    r = requests.post(
        f"{KIBANA_URL}/api/data_views/data_view",
        headers=HEADERS, json=payload
    )
    if r.status_code in (200, 409):
        print("Index pattern created: nserc-ics-threats-*")
    else:
        print(f"Index pattern warning ({r.status_code}): {r.text[:150]}")


def install_detection_rules():
    rules = [
        {
            "name": "NSERC: Critical ICS Protocol Attack",
            "description": "CRITICAL event using ICS protocol (Modbus, DNP3, IEC 61850). Immediate response required.",
            "risk_score": 95, "severity": "critical", "type": "query",
            "query": 'severity: "CRITICAL" AND is_ics_protocol: true',
            "language": "lucene", "index": ["nserc-ics-threats-*"],
            "interval": "1m", "from": "now-2m", "enabled": True,
            "tags": ["NSERC", "ICS", "Critical-Infrastructure"],
        },
        {
            "name": "NSERC: SCADA Brute Force Detected",
            "description": "High-volume failed authentication attempts on SCADA/HMI assets.",
            "risk_score": 75, "severity": "high", "type": "query",
            "query": 'scenario_name: *Brute* AND event_count: >100',
            "language": "lucene", "index": ["nserc-ics-threats-*"],
            "interval": "5m", "from": "now-10m", "enabled": True,
            "tags": ["NSERC", "BruteForce", "Authentication"],
        },
        {
            "name": "NSERC: Large Data Exfiltration from Historian",
            "description": "Bulk data transfer >50MB from historian or SCADA servers.",
            "risk_score": 85, "severity": "high", "type": "query",
            "query": 'mitre_tactic: "Collection" AND bytes_transferred_mb: >50',
            "language": "lucene", "index": ["nserc-ics-threats-*"],
            "interval": "5m", "from": "now-15m", "enabled": True,
            "tags": ["NSERC", "Exfiltration", "Historian"],
        },
        {
            "name": "NSERC: Unauthorized IEC 61850 or DNP3 Command",
            "description": "Control command on protection relay or RTU from unauthorized source.",
            "risk_score": 99, "severity": "critical", "type": "query",
            "query": 'protocol: ("IEC 61850" OR "DNP3") AND action: "CONTROL_COMMAND"',
            "language": "lucene", "index": ["nserc-ics-threats-*"],
            "interval": "1m", "from": "now-2m", "enabled": True,
            "tags": ["NSERC", "GridSabotage", "ProtectionRelay"],
        },
        {
            "name": "NSERC: OT Network Reconnaissance",
            "description": "Port scan or discovery targeting OT network segments.",
            "risk_score": 50, "severity": "medium", "type": "query",
            "query": 'mitre_tactic: "Discovery" AND destination_ip: 192.168.*',
            "language": "lucene", "index": ["nserc-ics-threats-*"],
            "interval": "10m", "from": "now-15m", "enabled": True,
            "tags": ["NSERC", "Reconnaissance", "OT-Network"],
        },
    ]

    created = 0
    for rule in rules:
        r = requests.post(
            f"{KIBANA_URL}/api/detection_engine/rules",
            headers=HEADERS, json=rule
        )
        if r.status_code == 200:
            print(f"  Rule created: {rule['name']}")
            created += 1
        elif r.status_code == 409:
            print(f"  Rule already exists: {rule['name']}")
        else:
            print(f"  Rule warning ({r.status_code}): {rule['name']}")

    print(f"Detection rules: {created}/{len(rules)} created")


def verify_data():
    try:
        r = requests.get(f"{ES_URL}/nserc-ics-threats-*/_count", timeout=10)
        if r.status_code == 200:
            count = r.json().get("count", 0)
            print(f"Elasticsearch: {count:,} events indexed")
            if count == 0:
                print("  No data yet. Run: python log_generator/log_generator.py")
                print("  Then wait ~30 seconds for Logstash to ingest.")
            return count
    except Exception as e:
        print(f"Could not reach Elasticsearch: {e}")
    return 0


if __name__ == "__main__":
    print("=" * 55)
    print("NSERC Threat Dashboard — Kibana Setup")
    print("=" * 55)

    try:
        wait_for_kibana()
        create_index_pattern()
        install_detection_rules()
        verify_data()

        print("\n" + "=" * 55)
        print("Setup complete!")
        print("  Kibana:          http://localhost:5601")
        print("  Discover:        Analytics → Discover")
        print("  Data view:       NSERC ICS Threat Logs")
        print("  Detection rules: Security → Rules")
        print("=" * 55)

    except Exception as e:
        print(f"\nSetup failed: {e}")
        print("Make sure Docker is running: docker-compose up -d")
