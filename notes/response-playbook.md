\# Incident Response Playbook



\## Failed SSH Login



Recommended actions:



\- Review authentication logs

\- Identify repeated source IPs

\- Check for successful login after failures

\- Block source IP if malicious

\- Enforce MFA or SSH key-based authentication where possible





\## Suspicious PowerShell



Recommended actions:



\- Collect PowerShell logs

\- Review Sysmon Event ID 1 process creation

\- Inspect command line arguments

\- Identify parent process

\- Isolate host if malicious activity is confirmed





\## New Windows Service



Recommended actions:



\- Review service name and binary path

\- Validate service creator

\- Check for persistence behavior

\- Disable unauthorized service

\- Collect endpoint evidence





\## File Integrity Change



Recommended actions:



\- Identify modified file

\- Validate change approval

\- Review user activity

\- Restore file if unauthorized

\- Investigate for persistence or tampering





\## Known Malicious IP



Recommended actions:



\- Block IP at firewall

\- Search proxy, DNS, and endpoint logs

\- Identify contacted hosts

\- Review for command-and-control behavior





\## Malware Alert



Recommended actions:



\- Isolate endpoint

\- Collect evidence

\- Run endpoint scan

\- Review process and network activity

\- Begin containment and eradication process

