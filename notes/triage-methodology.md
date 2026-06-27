\# Alert Triage Methodology



\## Overview



This project demonstrates a repeatable alert triage process using Python automation.



The script ingests raw security alerts, enriches them with MITRE ATT\&CK context, classifies source IPs as internal or external, calculates an incident score, assigns a priority, and recommends response actions.



\## Risk Factors Used



| Factor | Purpose |

|---|---|

| Base Severity | Starting severity based on alert type |

| Source Classification | External sources add additional risk |

| Asset Criticality | Critical assets receive higher priority |

| Host Exposure | Internet-facing systems receive higher priority |

| Alert Type | Malware, privilege escalation, and known malicious IPs receive additional weight |



\## Priority Model



| Score | Priority |

|---|---|

| 85-100 | P1 |

| 70-84 | P2 |

| 50-69 | P3 |

| 0-49 | P4 |



\## Security Relevance



Security teams often receive high volumes of alerts. A repeatable triage method helps prioritize the most urgent events, reduce noise, and guide response actions.

