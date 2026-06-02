"""
log_generator.py
================
Generates realistic cybersecurity attack logs targeting Nigerian
electricity infrastructure (SCADA, ICS/OT, substation automation).
Tagged to MITRE ATT&CK for ICS (T0800-T0891).

Author: Ella | NSERC Portfolio SEC-001
"""

import json
import random
import time
import os
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict, field
from typing import Optional

random.seed()

# ── Nigerian ICS Network Assets ─────────────────────────────────
ICS_ASSETS = [
    {"ip": "192.168.10.10", "name": "SCADA-Server-01",     "type": "SCADA_Server",      "disco": "Abuja DisCo"},
    {"ip": "192.168.10.11", "name": "HMI-Station-01",      "type": "HMI",               "disco": "Abuja DisCo"},
    {"ip": "192.168.10.20", "name": "RTU-Feeder-F01",      "type": "RTU",               "disco": "Abuja DisCo"},
    {"ip": "192.168.10.21", "name": "RTU-Feeder-F02",      "type": "RTU",               "disco": "Abuja DisCo"},
    {"ip": "192.168.20.10", "name": "DMS-Server-IKJ",      "type": "DMS",               "disco": "Ikeja DisCo"},
    {"ip": "192.168.20.11", "name": "EMS-Server-IKJ",      "type": "EMS",               "disco": "Ikeja DisCo"},
    {"ip": "10.10.1.5",     "name": "Historian-DB-01",     "type": "Historian",         "disco": "Eko DisCo"},
    {"ip": "10.10.1.6",     "name": "Engineering-WS-01",   "type": "Engineering_WS",    "disco": "Eko DisCo"},
    {"ip": "10.10.2.10",    "name": "PLC-Substation-001",  "type": "PLC",               "disco": "Kano DisCo"},
    {"ip": "10.10.2.11",    "name": "Relay-Protection-01", "type": "Protection_Relay",  "disco": "Kano DisCo"},
    {"ip": "172.16.5.5",    "name": "FW-OT-Perimeter",     "type": "Firewall",          "disco": "Ikeja DisCo"},
    {"ip": "172.16.5.6",    "name": "Jump-Server-01",      "type": "Jump_Server",       "disco": "Abuja DisCo"},
]

ATTACK_SCENARIOS = [
    {
        "name": "SCADA Brute Force Login",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T0866 — Exploitation of Remote Services",
        "severity": "HIGH",
        "protocol": "RDP",
        "target_types": ["SCADA_Server", "HMI", "Jump_Server"],
        "description": "Multiple failed authentication attempts targeting SCADA remote access",
    },
    {
        "name": "Modbus Reconnaissance Scan",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T0846 — Remote System Discovery",
        "severity": "MEDIUM",
        "protocol": "Modbus/TCP",
        "target_types": ["RTU", "PLC", "SCADA_Server"],
        "description": "Systematic Modbus function code enumeration on ICS subnet",
    },
    {
        "name": "Unauthorized IEC 61850 Command",
        "mitre_tactic": "Impair Process Control",
        "mitre_technique": "T0855 — Unauthorized Command Message",
        "severity": "CRITICAL",
        "protocol": "IEC 61850",
        "target_types": ["Protection_Relay", "RTU", "PLC"],
        "description": "Unauthorized GOOSE message to protection relay — potential trip command",
    },
    {
        "name": "Historian Data Exfiltration",
        "mitre_tactic": "Collection",
        "mitre_technique": "T0852 — Data from Information Repositories",
        "severity": "HIGH",
        "protocol": "SMB",
        "target_types": ["Historian", "SCADA_Server"],
        "description": "Bulk data transfer from historian DB to external endpoint",
    },
    {
        "name": "Ransomware Lateral Movement",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T0812 — Default Credentials",
        "severity": "CRITICAL",
        "protocol": "SMB",
        "target_types": ["Engineering_WS", "DMS", "EMS"],
        "description": "Pass-the-Hash lateral movement through OT network",
    },
    {
        "name": "DNP3 Replay Attack",
        "mitre_tactic": "Impair Process Control",
        "mitre_technique": "T0830 — Adversary-in-the-Middle",
        "severity": "CRITICAL",
        "protocol": "DNP3",
        "target_types": ["RTU", "SCADA_Server"],
        "description": "Captured and replayed DNP3 control messages to substation RTU",
    },
    {
        "name": "VPN Phishing Campaign",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T0865 — Spearphishing Attachment",
        "severity": "MEDIUM",
        "protocol": "HTTPS",
        "target_types": ["Engineering_WS", "Jump_Server"],
        "description": "Spearphishing emails targeting DisCo control room engineers",
    },
    {
        "name": "PLC Process Manipulation",
        "mitre_tactic": "Inhibit Response Function",
        "mitre_technique": "T0800 — Activate Firmware Update Mode",
        "severity": "CRITICAL",
        "protocol": "Modbus/TCP",
        "target_types": ["PLC", "RTU"],
        "description": "Modification of PLC setpoints — could cause feeder trip",
    },
    {
        "name": "OT Network Port Scan",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T0840 — Network Connection Enumeration",
        "severity": "LOW",
        "protocol": "ICMP",
        "target_types": ["Firewall", "SCADA_Server"],
        "description": "Network reconnaissance sweep of ICS subnet from DMZ",
    },
    {
        "name": "Engineering Station Compromise",
        "mitre_tactic": "Execution",
        "mitre_technique": "T0871 — Execution through API",
        "severity": "HIGH",
        "protocol": "WinRM",
        "target_types": ["Engineering_WS"],
        "description": "Suspicious process execution on engineering workstation",
    },
]

ICS_PROTOCOLS = {"Modbus/TCP", "DNP3", "IEC 61850", "IEC 104", "OPC-DA", "PROFINET"}

PORT_MAP = {
    "RDP": 3389, "SSH": 22, "SMB": 445, "HTTP": 80, "HTTPS": 443,
    "FTP": 21, "Telnet": 23, "WinRM": 5985,
    "Modbus/TCP": 502, "DNP3": 20000, "IEC 61850": 102,
    "IEC 104": 2404, "ICMP": 0,
}

COUNTRY_PREFIXES = {
    "41.": "Nigeria", "196.": "Nigeria", "197.": "South Africa",
    "185.": "Russia", "91.": "Russia", "194.": "United Kingdom",
    "45.": "United States", "62.": "Netherlands",
}


def rand_external_ip():
    prefix = random.choice(list(COUNTRY_PREFIXES.keys()))
    dots_needed = 3 - prefix.count(".")
    suffix = ".".join(str(random.randint(1, 254)) for _ in range(dots_needed))
    return prefix + suffix


def get_country(ip):
    for prefix, country in COUNTRY_PREFIXES.items():
        if ip.startswith(prefix):
            return country
    return "Unknown"


def pick_target(scenario):
    candidates = [a for a in ICS_ASSETS if a["type"] in scenario["target_types"]]
    return random.choice(candidates) if candidates else random.choice(ICS_ASSETS)


def make_event(scenario, base_time):
    target = pick_target(scenario)
    src_ip = rand_external_ip()
    ts = base_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    protocol = scenario["protocol"]
    port = PORT_MAP.get(protocol, random.randint(1024, 65535))
    is_ics = protocol in ICS_PROTOCOLS
    event_count = random.randint(1, 2000) if "Brute" in scenario["name"] else random.randint(1, 50)

    raw_log = (
        f"{ts} IDS-ALERT [{scenario['severity']}] {scenario['name']} "
        f"SRC={src_ip} DST={target['ip']} PROTO={protocol} DPT={port} "
        f"TECHNIQUE={scenario['mitre_technique'].split(' — ')[0]}"
    )

    return {
        "event_id":          f"SEC-{int(time.time())}-{random.randint(1000,9999)}",
        "timestamp":         ts,
        "scenario_name":     scenario["name"],
        "mitre_tactic":      scenario["mitre_tactic"],
        "mitre_technique":   scenario["mitre_technique"],
        "mitre_technique_id":scenario["mitre_technique"].split(" — ")[0],
        "severity":          scenario["severity"],
        "severity_score":    {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(scenario["severity"], 1),
        "source_ip":         src_ip,
        "source_country":    get_country(src_ip),
        "destination_ip":    target["ip"],
        "destination_asset": target["name"],
        "destination_type":  target["type"],
        "disco":             target["disco"],
        "protocol":          protocol,
        "port":              port,
        "is_ics_protocol":   is_ics,
        "action":            "CONTROL_COMMAND" if "Command" in scenario["name"] else "SUSPICIOUS_ACTIVITY",
        "outcome":           random.choice(["DETECTED", "BLOCKED_BY_IDS", "ALERTED"]),
        "bytes_transferred": random.randint(60, 500_000_000),
        "bytes_transferred_mb": round(random.randint(60, 500_000_000) / 1_048_576, 3),
        "packet_count":      random.randint(1, 50000),
        "event_count":       event_count,
        "description":       scenario["description"],
        "raw_log":           raw_log,
        "tags":              ["ICS", "NSERC", scenario["mitre_tactic"].lower().replace(" ", "-")],
        "requires_immediate_action": scenario["severity"] == "CRITICAL" and is_ics,
    }


def generate_attack_logs(n_events=300, days_back=30):
    now = datetime.now(timezone.utc)
    events = []
    for _ in range(n_events):
        scenario = random.choice(ATTACK_SCENARIOS)
        base_time = now - timedelta(
            days=random.uniform(0, days_back),
            hours=random.uniform(0, 24),
            minutes=random.uniform(0, 60),
        )
        events.append(make_event(scenario, base_time))
    events.sort(key=lambda e: e["timestamp"])
    return events


if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)

    print("Generating ICS attack logs for Nigerian electricity infrastructure...")
    events = generate_attack_logs(n_events=300, days_back=30)

    with open("logs/ics_security_events.jsonl", "w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")

    with open("logs/ics_syslog.log", "w") as f:
        for ev in events:
            f.write(ev["raw_log"] + "\n")

    severity_counts = {}
    for ev in events:
        severity_counts[ev["severity"]] = severity_counts.get(ev["severity"], 0) + 1

    print(f"\nGenerated {len(events)} security events:")
    print(f"  CRITICAL: {severity_counts.get('CRITICAL', 0)}")
    print(f"  HIGH:     {severity_counts.get('HIGH', 0)}")
    print(f"  MEDIUM:   {severity_counts.get('MEDIUM', 0)}")
    print(f"  LOW:      {severity_counts.get('LOW', 0)}")
    print("\nOutput: logs/ics_security_events.jsonl")
    print("Output: logs/ics_syslog.log")
    print("\nNext: docker-compose up -d")
    print("Then: python detection/setup_kibana.py")
