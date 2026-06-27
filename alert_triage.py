import csv
import ipaddress
from collections import Counter
from pathlib import Path


ALERTS_FILE = Path("sample_alerts.csv")
NETWORKS_FILE = Path("data/internal_networks.csv")
MITRE_FILE = Path("data/mitre_mapping.csv")

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

INCIDENT_REPORT_CSV = REPORTS_DIR / "incident_report.csv"
INCIDENT_SUMMARY_MD = REPORTS_DIR / "incident_summary.md"


SEVERITY_POINTS = {
    "Low": 10,
    "Medium": 30,
    "High": 50,
    "Critical": 70,
}

ASSET_CRITICALITY_POINTS = {
    "Low": 0,
    "Medium": 5,
    "High": 10,
    "Critical": 15,
}

HOST_EXPOSURE_POINTS = {
    "Internal": 0,
    "Internet-Facing": 15,
}


def load_csv(path):
    with path.open("r", encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


def load_internal_networks():
    rows = load_csv(NETWORKS_FILE)
    networks = []

    for row in rows:
        try:
            networks.append(ipaddress.ip_network(row["network"]))
        except ValueError:
            continue

    return networks


def is_internal_ip(ip_value, internal_networks):
    try:
        ip = ipaddress.ip_address(ip_value)
    except ValueError:
        return "Unknown"

    for network in internal_networks:
        if ip in network:
            return "Internal"

    return "External"


def load_mitre_mapping():
    rows = load_csv(MITRE_FILE)
    mapping = {}

    for row in rows:
        mapping[row["alert_type"]] = row

    return mapping


def calculate_priority_score(alert, mitre_data, source_classification):
    base_severity = mitre_data.get("base_severity", "Low")
    score = SEVERITY_POINTS.get(base_severity, 10)

    score += ASSET_CRITICALITY_POINTS.get(alert.get("asset_criticality", "Low"), 0)
    score += HOST_EXPOSURE_POINTS.get(alert.get("host_exposure", "Internal"), 0)

    if source_classification == "External":
        score += 10

    if alert["alert_type"] in ["Known Malicious IP", "Malware Alert", "Privilege Escalation"]:
        score += 15

    if alert["alert_type"] in ["Suspicious PowerShell", "New Windows Service"]:
        score += 10

    return min(score, 100)


def priority_label(score):
    if score >= 85:
        return "P1"
    if score >= 70:
        return "P2"
    if score >= 50:
        return "P3"
    return "P4"


def incident_severity(score):
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"


def containment_recommendation(alert_type):
    recommendations = {
        "Failed SSH Login": "Block source IP if repeated, review authentication logs, confirm no successful login followed.",
        "Suspicious PowerShell": "Collect PowerShell and Sysmon logs, review command line, isolate host if malicious intent is suspected.",
        "New Windows Service": "Validate service name, binary path, and creator. Disable service if unauthorized.",
        "File Integrity Change": "Review modified file, validate change approval, restore from backup if unauthorized.",
        "Known Malicious IP": "Block IP at firewall, search logs for related connections, review affected destination host.",
        "High Risk CVE": "Patch affected asset or apply compensating controls. Prioritize based on exposure and asset criticality.",
        "Impossible Travel Login": "Force password reset, revoke sessions, review MFA and identity logs.",
        "Privilege Escalation": "Remove unauthorized privileges, review account activity, isolate affected host if needed.",
        "Malware Alert": "Isolate endpoint, collect evidence, run malware scan, begin incident response process.",
        "Nmap Scan Detected": "Validate whether scan was authorized. Review source host and firewall logs.",
    }

    return recommendations.get(alert_type, "Review alert context and investigate according to incident response procedures.")


def enrich_alerts(alerts, mitre_mapping, internal_networks):
    enriched_alerts = []

    for alert in alerts:
        alert_type = alert["alert_type"]
        mitre_data = mitre_mapping.get(alert_type, {})

        source_classification = is_internal_ip(alert["source_ip"], internal_networks)
        score = calculate_priority_score(alert, mitre_data, source_classification)

        enriched = {
            "alert_id": alert["alert_id"],
            "timestamp": alert["timestamp"],
            "alert_type": alert_type,
            "source_ip": alert["source_ip"],
            "source_classification": source_classification,
            "destination_host": alert["destination_host"],
            "user": alert["user"],
            "event_source": alert["event_source"],
            "description": alert["description"],
            "asset_criticality": alert["asset_criticality"],
            "host_exposure": alert["host_exposure"],
            "mitre_tactic": mitre_data.get("tactic", "Unknown"),
            "mitre_technique_id": mitre_data.get("technique_id", "Unknown"),
            "mitre_technique_name": mitre_data.get("technique_name", "Unknown"),
            "base_severity": mitre_data.get("base_severity", "Low"),
            "incident_score": score,
            "incident_severity": incident_severity(score),
            "priority": priority_label(score),
            "recommended_response": containment_recommendation(alert_type),
        }

        enriched_alerts.append(enriched)

    return sorted(enriched_alerts, key=lambda item: item["incident_score"], reverse=True)


def write_incident_report(enriched_alerts):
    fieldnames = [
        "alert_id",
        "timestamp",
        "alert_type",
        "source_ip",
        "source_classification",
        "destination_host",
        "user",
        "event_source",
        "description",
        "asset_criticality",
        "host_exposure",
        "mitre_tactic",
        "mitre_technique_id",
        "mitre_technique_name",
        "base_severity",
        "incident_score",
        "incident_severity",
        "priority",
        "recommended_response",
    ]

    with INCIDENT_REPORT_CSV.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(enriched_alerts)


def write_summary(enriched_alerts):
    priority_counts = Counter(alert["priority"] for alert in enriched_alerts)
    tactic_counts = Counter(alert["mitre_tactic"] for alert in enriched_alerts)
    severity_counts = Counter(alert["incident_severity"] for alert in enriched_alerts)

    top_alerts = enriched_alerts[:5]

    lines = [
        "# Incident Triage Summary",
        "",
        "## Executive Summary",
        "",
        f"This report analyzed {len(enriched_alerts)} security alerts and prioritized them based on severity, source context, asset criticality, host exposure, and alert type.",
        "",
        "## Priority Summary",
        "",
    ]

    for priority, count in sorted(priority_counts.items()):
        lines.append(f"- {priority}: {count}")

    lines.extend([
        "",
        "## Severity Summary",
        "",
    ])

    for severity, count in severity_counts.items():
        lines.append(f"- {severity}: {count}")

    lines.extend([
        "",
        "## MITRE ATT&CK Tactic Summary",
        "",
    ])

    for tactic, count in tactic_counts.items():
        lines.append(f"- {tactic}: {count}")

    lines.extend([
        "",
        "## Top 5 Highest Priority Alerts",
        "",
    ])

    for alert in top_alerts:
        lines.extend([
            f"### {alert['alert_id']} - {alert['alert_type']}",
            "",
            f"- Priority: {alert['priority']}",
            f"- Incident Severity: {alert['incident_severity']}",
            f"- Incident Score: {alert['incident_score']}",
            f"- Source IP: {alert['source_ip']} ({alert['source_classification']})",
            f"- Destination Host: {alert['destination_host']}",
            f"- User: {alert['user']}",
            f"- MITRE Mapping: {alert['mitre_tactic']} / {alert['mitre_technique_id']} / {alert['mitre_technique_name']}",
            f"- Recommended Response: {alert['recommended_response']}",
            "",
        ])

    lines.extend([
        "## Recommended Next Steps",
        "",
        "- Review P1 and P2 alerts first.",
        "- Validate whether activity was authorized or expected.",
        "- Isolate hosts where malware, privilege escalation, or suspicious PowerShell activity is confirmed.",
        "- Block malicious external IPs where appropriate.",
        "- Document containment, eradication, and recovery actions.",
    ])

    INCIDENT_SUMMARY_MD.write_text("\n".join(lines), encoding="utf-8")


def print_console_summary(enriched_alerts):
    print("\n=== Security Alert Triage Summary ===\n")

    for alert in enriched_alerts:
        print(
            f"{alert['priority']} | {alert['incident_severity']} | "
            f"Score: {alert['incident_score']} | "
            f"{alert['alert_type']} | "
            f"{alert['destination_host']} | "
            f"{alert['mitre_technique_id']}"
        )

    print("\nReports created:")
    print(f"- {INCIDENT_REPORT_CSV}")
    print(f"- {INCIDENT_SUMMARY_MD}")


def main():
    alerts = load_csv(ALERTS_FILE)
    internal_networks = load_internal_networks()
    mitre_mapping = load_mitre_mapping()

    enriched_alerts = enrich_alerts(alerts, mitre_mapping, internal_networks)

    write_incident_report(enriched_alerts)
    write_summary(enriched_alerts)
    print_console_summary(enriched_alerts)


if __name__ == "__main__":
    main()