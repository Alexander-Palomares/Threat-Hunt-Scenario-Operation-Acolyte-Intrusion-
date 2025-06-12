# 🕵️‍♂️ Threat Hunt Report: Operation Acolyte Intrusion

## 🎯 Scenario

For weeks, multiple partner organizations across Southeast Asia and Eastern Europe detected odd outbound activity to obscure cloud endpoints. Initially dismissed as harmless automation, the anomalies began aligning.

Across sectors — telecom, defense, manufacturing — analysts observed the same patterns: irregular PowerShell bursts, unexplained registry changes, and credential traces mimicking known red-team tools.

Then came a break. A tech firm flagged sensitive project files leaked days before a bid was undercut. An energy provider found zipped payloads posing as sync utilities in public directories.

Whispers grew — not one actor, but a coordinated effort. Code fragments matched across unrelated environments. The beaconing continued: quiet, rhythmic pings to endpoints no business could explain.

Some suspect Starlance — an old, disbanded joint op revived. Others say mercenary crews using supply chain access and familiar tooling.

What’s clear: this wasn’t smash-and-grab. It was long game.

> **Your mission**: Trace the access, map the spread, and uncover what was touched — or taken. Two machines hold the truth, scattered and shrouded.

**Starting Point**  
Begin your hunt with newly created virtual machines that were only active for a few hours around **May 24th, 2025** before being deleted — a sign of ephemeral attack infrastructure with limited logging footprint.

---

## 🖥️ Environment Details

- **Initial Host**: `acolyte756`
- **Secondary Host**: `victor-disa-vm`
- **Telemetry Platform**: Microsoft Defender for Endpoint
- **Threat Category**: Fileless Malware, Registry + WMI Persistence, Lateral Movement, Exfiltration

---

## Flags:

### 🔹 Flag 1 – Initial PowerShell Execution Detection
**Objective**: Pinpoint the earliest suspicious PowerShell activity that marks the intruder's possible entry.

**KQL Query**:

```kql
let Vm = "acolyte756";
DeviceProcessEvents
| where DeviceName == Vm
| where Timestamp >= datetime(2025-05-24)
| where ProcessCommandLine contains "powershell"
| order by Timestamp asc 
| project Timestamp, ActionType, FileName, FolderPath, ProcessCommandLine, AccountName, InitiatingProcessFileName
```

**Results:**
![flag 1](https://github.com/user-attachments/assets/b019b71a-e464-4ee9-9a27-b37711827676)

**Finding**: 
- Suspicious PowerShell activity observed on `acolyte756`  
- **Timestamp**: `2025-05-25T09:14:02.3908261Z`

---

### 🔹 Flag 2 – Outbound Communication  
**Objective**: Confirm an unusual outbound communication attempt from a potentially compromised host.

**KQL Query**:

```kql
DeviceNetworkEvents
| where DeviceName == "acolyte756"
| where Timestamp >= datetime(2025-05-25 09:14:02)
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Results:**
![flag 2](https://github.com/user-attachments/assets/e85acdb8-49cb-412e-aaeb-7380d20654e5)

**Finding**: 
- **C2 Domain**: `eoqsu1hq6e9ulga.m.pipedream.net`  

---

### 🔹 Flag 3 – Registry Persistence  
**Objective**: Detect whether the adversary used registry-based mechanisms to gain persistence.

**KQL Query**:

```kql
DeviceRegistryEvents
| where DeviceName == "acolyte756"
| where ActionType == "RegistryValueSet"
| where InitiatingProcessRemoteSessionDeviceName == @"GRINLOK"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Results:**
![flag 3](https://github.com/user-attachments/assets/7739702b-98f3-4c97-8722-5dbe76e68c09)

```powershell
powershell.exe -WindowStyle Hidden -Exec Bypass -File C:\Users\Public\C2.ps1
```

**Finding**:
- **Registry Value**: `simulatedbackdoor`
- New file created `C2.ps1`

---

### 🔹 Flag 4 – Scheduled Task Persistence 
**Objective**: Investigate the presence of alternate autorun methods used by the intruder.

**KQL Query**:

```kql
DeviceRegistryEvents
| where DeviceName == "acolyte756"
| where ActionType == "RegistryValueSet" or ActionType == "RegistryKeyCreated"
| where RegistryKey has "\\Schedule\\" 
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Results:** ![flag 4](https://github.com/user-attachments/assets/ceeb8f08-46e8-4616-a789-06734a228d97)

**Finding**: 
- **Registry Key**: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\SimC2Task`

---

### 🔹 Flag 5 – Obfuscated PowerShell Execution  
**Objective**: Uncover signs of script concealment or encoding in command-line activity.

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc", "-bypass", "-nop", "FromBase64String")
| where FileName == "powershell.exe" or FileName == "pwsh.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp asc
```

**Results**: ![flag 5](https://github.com/user-attachments/assets/466f4f61-7453-4bf9-b1ab-0b284d721639)

**Finding**: 
- **Encoded Command**:  `powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAaQBtAHUAbABhAHQAZQBkACAAbwBiAGYAdQBzAGMAYQB0AGUAZAAgAGUAeABlAGMAdQB0AGkAbwBuACIA`  

---

### 🔹 Flag 6 – PowerShell Downgrade Evasion  
**Objective**: Detect usage of outdated script configurations likely intended to bypass modern controls.

**KQL Query**:

```kql
DeviceProcessEvents
| where DeviceName == "acolyte756"
| where (
    ProcessCommandLine has_any ("-Version 2", "-v 2", "cscript.exe", "wscript.exe") 
    or (FileName == "powershell.exe" and ProcessCommandLine has_any ("-ExecutionPolicy Bypass", "-NoProfile"))
)
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

**Results:** ![flag 6](https://github.com/user-attachments/assets/54267b63-e218-4e2a-a4a1-882f6234aca5)

**Finding**: 
- **Command**:  `powershell.exe -Version 2 -NoProfile -ExecutionPolicy Bypass -NoExit`  

---

### 🔹 Flag 7 – Lateral Movement  
**Objective**: Reveal the intruder's next target beyond the initial breach point.

**KQL Query**:

```kql
let ip = "3.215.219.189";
search in (DeviceNetworkEvents,DeviceFileEvents,DeviceLogonEvents,DeviceEvents)
Timestamp between (ago(30d) .. now())
and (// Events initiated by this IP
LocalIP == ip
or FileOriginIP == ip
or RequestSourceIP == ip
// Events affecting this IP
or RemoteIP == ip
)
```

**Results:** ![flag 7](https://github.com/user-attachments/assets/59b8c0fa-0e8d-42dc-aac5-d6796cc4b79a)

**Finding**: 
- **Target Machine**: `victor-disa-vm`

---

### 🔹 Flag 8 – Entry Indicator on Second Host  
**Objective**: Identify the subtle digital footprints left during a pivot.


**KQL Query**:

```kql
DeviceFileEvents
| where DeviceName == "victor-disa-vm"
| where Timestamp between (datetime(2025-05-25T00:00:00Z) .. datetime(2025-05-26T02:29:56.2210422Z))
| where FileName contains_cs "point" or FileName contains_cs "stage" or FileName contains_cs "sync" or FileName contains_cs "checkpoint"
| project Timestamp, FileName, FolderPath
| order by Timestamp asc
```

**Results:**
![flag 8](https://github.com/user-attachments/assets/cd52fbfb-6e33-4376-b93d-55cc0b366e00)

**Finding**: 
- **Dropped File**: `savepoint_sync.lnk`  

### 🔹 Flag 8.1 – Registry Persistence on Second Host  
**Objective**: Detect attempts to embed control mechanisms within system configuration.

**KQL Query**:

```kql
DeviceRegistryEvents
| where DeviceName == "victor-disa-vm"
| where RegistryValueData contains "point"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp asc
```

**Results:** ![flag 8 1](https://github.com/user-attachments/assets/ace65c6b-99b4-433b-a8a9-e64b1bd586c7)

**Finding**: 
- **Execution**: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\savepoint_sync.ps1"`  

---

### 🔹 Flag 9 – New C2 Domain on Second Host  
**Objective**: Verify if outbound signals continued from the newly touched system.

**KQL Query**:

```kql
DeviceNetworkEvents
| where DeviceName == "victor-disa-vm"
| where Timestamp >= datetime(2025-05-26T02:29:56.2210422Z)
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Results:** ![flag 9](https://github.com/user-attachments/assets/b985dedd-f40c-473f-a7dc-a25de04e5893)

**Finding**: 
- **suspicious outbound connection**: `eo1v1texxlrdq3v.m.pipedream.net`  

---

### 🔹 Flag 10 – WMI-Based Persistence  
**Objective**: Uncover non-traditional persistence mechanisms leveraging system instrumentation.

**KQL Query**:

```kql
DeviceProcessEvents
| where InitiatingProcessCommandLine contains_cs "beacon" or ProcessCommandLine contains_cs "beacon"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```

**Results:** ![flag 10](https://github.com/user-attachments/assets/f90bed20-25e0-4539-8a96-53aa49afd078)

**Finding**: 
- **Trigger Time**: `2025-05-26T02:48:07.2900744Z`

---

### 🔹 Flag 11 – Credential Dump Simulation  
**Objective**: Detect test-like access patterns mimicking sensitive credential theft.

**KQL Query**:

```kql
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where ProcessCommandLine has_any ("mimikatz", "sekurlsa", "lsass", "dump", "password", "hash", "creds", "sekurlsa::logonpasswords")
   or FileName has_any ("mimikatz.exe", "dump.exe", "creddump", "pwdump", "beacon.exe", "lsa_dump")
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

**Results:** ![flag 11](https://github.com/user-attachments/assets/46d2bac9-353a-46e3-ba54-10189b197147)

**Finding**: 
- **Artifact**: `mimidump_sim.txt`  

---

### 🔹 Flag 12 – Outbound Data Transfer  
**Objective**: Investigate signs of potential data transfer to untrusted locations.

**Results:** ![flag 12](https://github.com/user-attachments/assets/59144762-3246-4d89-9476-4fa9a10e30d9)

**Finding**: 
- **SHA256**: `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`

---

### 🔹 Flag 13 – Sensitive Asset Accessed  
**Objective**: Reveal whether any internal document of significance was involved.

**KQL Query**:

```kql
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where ProcessCommandLine contains "2025"
| order by Timestamp asc
```

**Results:** ![flag 13](https://github.com/user-attachments/assets/e8d64fdb-8c40-4b4f-865c-28fe2bb25936)

**Finding**: 
- **File**: `RolloutPlan_v8_477.docx`

---

### 🔹 Flag 14 – Tool Packaging Activity  
**Objective**: Spot behaviors related to preparing code or scripts for movement.

**KQL Query**:

```kql
DeviceProcessEvents
| where DeviceName == "victor-disa-vm"
| where ProcessCommandLine has_any ("Compress-Archive", "-DestinationPath", ".zip", ".7z", ".tar", "zip.exe", "7z.exe", "-Path")
| project Timestamp, DeviceName, ProcessCommandLine,  InitiatingProcessCommandLine, FileName, FolderPath, InitiatingProcessFileName
| order by Timestamp asc
```

**Results:** ![flag 14](https://github.com/user-attachments/assets/1842f937-7de5-430d-870c-2f9f9a72c69f)

**Finding**: 
- **Command**: `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Compress-Archive -Path "C:\Users\Public\dropzone_spicy" -DestinationPath "C:\Users\Public\spicycore_loader_flag8.zip" -Force`  

---

### 🔹 Flag 15 – Payload Planted  
**Objective**: Verify whether staged payloads were saved to disk.

**Finding**: 
- **Archive**: `spicycore_loader_flag8.zip`  


### 🔹 Flag 16 – Final Scheduled Task Execution  
**Objective**: Identify automation set to invoke recently dropped content.

**Finding**: 
- **Timestamp**: `2025-05-26T07:01:01.6652736Z`  

---
## 🧠 Analyst Reasoning Flow

1 → 2: Suspicious PowerShell → possible beaconing  
2 → 3: Beaconing → persistence check → registry  
3 → 4: Registry persistence → redundant method → scheduled task  
4 → 5: Task leads to encoded PowerShell (obfuscation)  
5 → 6: Obfuscation → check for evasion → PowerShell downgrade  
6 → 7: Downgrade implies stealth → lateral movement  
7 → 8: New host → dropped artifacts  
8 → 9: Second beacon confirms active threat  
9 → 10: Persistence on new host → WMI-based  
10 → 11: Privilege escalation → credential dumping  
11 → 12: Data staging and exfil attempt  
12 → 13: Sensitive file access confirmed  
13 → 14: File packaged for exfiltration  
14 → 15: ZIP planted for extraction  
15 → 16: Scheduled task confirms execution  

---

## 🛠️ Tools Used

- Microsoft Defender for Endpoint (MDE)  
- Kusto Query Language (KQL)  


📅 **Date**: June 10 2025

