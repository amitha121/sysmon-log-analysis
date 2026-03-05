# sysmon-log-analysis
Basic Windows Sysmon log analysis for security monitoring and threat detection
Title : A hands-on Endpoint Log Analysis Project
Sysmon-Based Endpoint Monitoring and Threat Detection Lab
Project Overview

This project demonstrates how Windows endpoint activity can be monitored and analyzed using Sysmon. The objective was to simulate basic attacker techniques and investigate the generated telemetry through Windows Event Viewer.

The lab focuses on identifying suspicious behaviors including encoded PowerShell execution, outbound network connections initiated by PowerShell, and file creation in user directories.

The purpose of this exercise was to gain practical experience in endpoint visibility and foundational security investigation techniques commonly used in SOC environments.

Lab Environment

Operating System: Windows 10
Monitoring Tool: Sysmon (System Monitor)
Log Analysis Tool: Windows Event Viewer
Command Execution Tool: PowerShell

Sysmon was installed and configured to log process creation events, network connections, and file creation activities. Logs were reviewed under:

Applications and Services Logs → Microsoft → Windows → Sysmon → Operational

Attack Simulation

The following controlled actions were performed to generate detectable activity.

Encoded PowerShell Execution

Command Executed:

powershell.exe -enc UABvAHcAZQByAFMAaABlAGwAbAAgAGQAZQBtAG8=

This command launches PowerShell with a Base64-encoded argument.

Log Evidence:

Event ID: 1 (Process Creation)
Image: powershell.exe
CommandLine: contains the "-enc" parameter

Analysis:

The -enc parameter allows PowerShell commands to be encoded in Base64 format. This technique is frequently used by attackers to obfuscate malicious commands and bypass simple detection mechanisms. Monitoring encoded command-line execution is a common detection strategy in endpoint security.

Outbound Network Connection via PowerShell

Command Executed:

Invoke-WebRequest http://example.com -UseBasicParsing

This command forces PowerShell to initiate an HTTP request to an external domain.

Log Evidence:

Event ID: 3 (Network Connection)
Image: powershell.exe
DestinationHostname: example.com
DestinationPort: 80

Analysis:

PowerShell is a legitimate administrative tool but is often abused to download payloads, establish command-and-control communication, or exfiltrate data. Detecting network connections initiated by PowerShell is important during endpoint investigations.

File Creation in AppData Directory

Command Executed:

New-Item -Path "$env:APPDATA\dummy_malware.txt" -ItemType File

This creates a file within the user’s AppData directory.

Log Evidence:

Event ID: 11 (File Creation)
TargetFilename: dummy_malware.txt
Directory: AppData\Roaming

Analysis:

The AppData directory is frequently used by malware to drop payloads, store configuration files, and maintain persistence. Monitoring file creation in user-specific directories can help identify suspicious activity.

Log Investigation Methodology

The investigation was conducted using Windows Event Viewer by filtering Sysmon logs based on relevant Event IDs:

Event ID 1 – Process Creation
Event ID 3 – Network Connection
Event ID 11 – File Creation

The following fields were examined during analysis:

Image
CommandLine
ParentImage
DestinationHostname
TargetFilename
File Hashes

Special attention was given to identifying unusual command-line arguments, encoded execution patterns, and network connections originating from PowerShell.

Key Findings

Encoded PowerShell execution was successfully logged and identified.
PowerShell-initiated outbound network traffic was captured through Sysmon network connection events.
File creation activity in user directories was recorded and reviewed.
Normal background system processes were distinguished from intentionally simulated suspicious activity.

Lessons Learned

How to install and configure Sysmon for endpoint monitoring
How process creation events reveal command-line activity
How to identify encoded execution techniques
How to correlate process and network activity
How to conduct endpoint log analysis using native Windows tools

This lab provided practical experience in analyzing endpoint telemetry and understanding how common attacker behaviors appear in system logs.

Future Improvements

Custom Sysmon configuration tuning
Integration with a SIEM platform
Creation of detection rules for encoded PowerShell
Simulation of more advanced attack techniques
Automation of log analysis using Python or PowerShell scripts

Conclusion

This project demonstrates how Sysmon provides valuable visibility into endpoint activity. Even basic logging configurations allow detection of techniques such as encoded PowerShell execution and suspicious outbound network connections.

With proper monitoring and analysis, Windows endpoints can generate meaningful telemetry for threat detection and investigation.
