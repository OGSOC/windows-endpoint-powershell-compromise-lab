Incident Report: PowerShell Encoded Command Compromise

Summary

A suspicious PowerShell process executed with an encoded command and execution policy bypass. Investigation confirmed external payload download and persistence via registry Run key.

Timeline

14:22:31 – PowerShell executed with encoded command
14:22:33 – Outbound HTTP connection initiated
14:23:01 – Registry Run key created
14:23:05 – php.exe executed from Public directory

Impact

Single host confirmed compromised.
Persistence established.
Potential credential exposure.

Risk Level

Critical

MITRE ATT&CK

T1059.001 – PowerShell
T1105 – Ingress Tool Transfer
T1547.001 – Registry Run Key

Recommendations

Isolate host immediately.
Remove persistence artifact.
Block malicious domain.
Reset user credentials.
Conduct enterprise-wide threat hunt.

Analyst Conclusion

Behavior chain strongly indicates malicious compromise rather than administrative activity. Escalation and containment required.
