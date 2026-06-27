# Incident Triage Summary

## Executive Summary

This report analyzed 10 security alerts and prioritized them based on severity, source context, asset criticality, host exposure, and alert type.

## Priority Summary

- P1: 4
- P2: 2
- P3: 2
- P4: 2

## Severity Summary

- Critical: 4
- High: 2
- Medium: 2
- Low: 2

## MITRE ATT&CK Tactic Summary

- Command and Control: 1
- Privilege Escalation: 1
- Execution: 2
- Initial Access: 2
- Persistence: 1
- Credential Access: 1
- Defense Evasion: 1
- Discovery: 1

## Top 5 Highest Priority Alerts

### A005 - Known Malicious IP

- Priority: P1
- Incident Severity: Critical
- Incident Score: 100
- Source IP: 198.51.100.25 (External)
- Destination Host: web-server-01
- User: unknown
- MITRE Mapping: Command and Control / T1071 / Application Layer Protocol
- Recommended Response: Block IP at firewall, search logs for related connections, review affected destination host.

### A008 - Privilege Escalation

- Priority: P1
- Incident Severity: Critical
- Incident Score: 100
- Source IP: 172.30.80.1 (Internal)
- Destination Host: windows-endpoint
- User: jdoe
- MITRE Mapping: Privilege Escalation / T1068 / Exploitation for Privilege Escalation
- Recommended Response: Remove unauthorized privileges, review account activity, isolate affected host if needed.

### A009 - Malware Alert

- Priority: P1
- Incident Severity: Critical
- Incident Score: 100
- Source IP: 172.30.80.1 (Internal)
- Destination Host: windows-endpoint
- User: jdoe
- MITRE Mapping: Execution / T1204 / User Execution
- Recommended Response: Isolate endpoint, collect evidence, run malware scan, begin incident response process.

### A007 - Impossible Travel Login

- Priority: P1
- Incident Severity: Critical
- Incident Score: 85
- Source IP: 192.0.2.77 (External)
- Destination Host: cloud-admin-portal
- User: asmith
- MITRE Mapping: Initial Access / T1078 / Valid Accounts
- Recommended Response: Force password reset, revoke sessions, review MFA and identity logs.

### A002 - Suspicious PowerShell

- Priority: P2
- Incident Severity: High
- Incident Score: 75
- Source IP: 172.30.80.1 (Internal)
- Destination Host: windows-endpoint
- User: jdoe
- MITRE Mapping: Execution / T1059.001 / PowerShell
- Recommended Response: Collect PowerShell and Sysmon logs, review command line, isolate host if malicious intent is suspected.

## Recommended Next Steps

- Review P1 and P2 alerts first.
- Validate whether activity was authorized or expected.
- Isolate hosts where malware, privilege escalation, or suspicious PowerShell activity is confirmed.
- Block malicious external IPs where appropriate.
- Document containment, eradication, and recovery actions.