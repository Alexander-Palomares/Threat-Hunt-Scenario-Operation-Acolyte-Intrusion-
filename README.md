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

## 🧩 Flags

### 🔹 Flag 1 – Initial PowerShell Execution
**Finding**: Suspicious PowerShell activity observed on `acolyte756`  
**Timestamp**: `2025-05-25T09:14:02.3908261Z`

**KQL Query**:

**Screenshot:**

---

### 🔹 Flag 2 – Outbound Communication  
**C2 Domain**: `eoqsu1hq6e9ulga.m.pipedream.net`  

**KQL Query**:

**Screenshot:**

---

### 🔹 Flag 3 – Registry Persistence  
**Registry Value**: `simulatedbackdoor`  

**KQL Query**:

```powershell
powershell.exe -WindowStyle Hidden -Exec Bypass -File C:\Users\Public\C2.ps1
```

**Screenshot:**

---

### 🔹 Flag 4 – Scheduled Task Persistence  
**Registry Key**: `HKLM\...\Tree\SimC2Task`  

**KQL Query**:

**Screenshot:**

---

### 🔹 Flag 5 – Obfuscated PowerShell Execution  
**Encoded Command**:  
`powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAaQBtAHUAbABhAHQAZQBkACAAbwBiAGYAdQBzAGMAYQB0AGUAZAAgAGUAeABlAGMAdQB0AGkAbwBuACIA`  

**KQL Query**:

**Screenshot:**

---

### 🔹 Flag 6 – PowerShell Downgrade Evasion  
**Command**:  
`powershell.exe -Version 2 -NoProfile -ExecutionPolicy Bypass -NoExit`  

**KQL Query**:

**Screenshot:**

---

### 🔹 Flag 7 – Lateral Movement  
**Target Machine**: `victor-disa-vm`  

**KQL Query**:

**Screenshot:**

---

### 🔹 Flag 8 – Entry Indicator on Second Host  
**Dropped File**: `savepoint_sync.lnk`  

**KQL Query**:

**Screenshot:**


### 🔹 Flag 8.1 – Registry Persistence on Second Host  
**Execution**:  
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\savepoint_sync.ps1"`  

**KQL Query**:

**Screenshot:**

---

### 🔹 Flag 9 – New C2 Domain on Second Host  
**Domain**: `eo1v1texxlrdq3v.m.pipedream.net`  

**KQL Query**:

**Screenshot:**

---

### 🔹 Flag 10 – WMI-Based Persistence  
**Trigger Time**: `2025-05-26T02:48:07.2900744Z`  

**KQL Query**:

**Screenshot:**

---

### 🔹 Flag 11 – Credential Dump Simulation  
**Artifact**: `mimidump_sim.txt`  

**KQL Query**:

**Screenshot:**

---

### 🔹 Flag 12 – Outbound Data Transfer  
**SHA256**:  
`9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`  

**KQL Query**:

**Screenshot:**

---

### 🔹 Flag 13 – Sensitive Asset Accessed  
**File**: `RolloutPlan_v8_477.docx`  

**KQL Query**:

**Screenshot:**

---

### 🔹 Flag 14 – Tool Packaging Activity  
**Command**:  
`powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Compress-Archive -Path "C:\Users\Public\dropzone_spicy" -DestinationPath "C:\Users\Public\spicycore_loader_flag8.zip" -Force`  

**KQL Query**:

**Screenshot:**

---

### 🔹 Flag 15 – Payload Planted  
**Archive**: `spicycore_loader_flag8.zip`  

**KQL Query**:

**Screenshot:**

---

### 🔹 Flag 16 – Final Scheduled Task Execution  
**Timestamp**: `2025-05-26T07:01:01.6652736Z`  

**KQL Query**:

**Screenshot:**

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

---

## ✍️ Author

**Alexander Palomares**  
Cybersecurity Threat Hunter  
[LinkedIn: YourLinkedIn]  
[GitHub: YourGitHub]  

📅 **Date**: June 2025

