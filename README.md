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

**Results:**
![flag 1](https://github.com/user-attachments/assets/b019b71a-e464-4ee9-9a27-b37711827676)


---

### 🔹 Flag 2 – Outbound Communication  
**C2 Domain**: `eoqsu1hq6e9ulga.m.pipedream.net`  

**KQL Query**:

**Results:**
![flag 2](https://github.com/user-attachments/assets/e85acdb8-49cb-412e-aaeb-7380d20654e5)

---

### 🔹 Flag 3 – Registry Persistence  
**Registry Value**: `simulatedbackdoor`  

**KQL Query**:

```powershell
powershell.exe -WindowStyle Hidden -Exec Bypass -File C:\Users\Public\C2.ps1
```

**Results:**
![flag 3](https://github.com/user-attachments/assets/7739702b-98f3-4c97-8722-5dbe76e68c09)

---

### 🔹 Flag 4 – Scheduled Task Persistence  
**Registry Key**: `HKLM\...\Tree\SimC2Task`  

**KQL Query**:

**Results:**
![flag 4](https://github.com/user-attachments/assets/ceeb8f08-46e8-4616-a789-06734a228d97)

---

### 🔹 Flag 5 – Obfuscated PowerShell Execution  
**Encoded Command**:  
`powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMAaQBtAHUAbABhAHQAZQBkACAAbwBiAGYAdQBzAGMAYQB0AGUAZAAgAGUAeABlAGMAdQB0AGkAbwBuACIA`  

**KQL Query**:

**Results:**
![flag 5](https://github.com/user-attachments/assets/466f4f61-7453-4bf9-b1ab-0b284d721639)

---

### 🔹 Flag 6 – PowerShell Downgrade Evasion  
**Command**:  
`powershell.exe -Version 2 -NoProfile -ExecutionPolicy Bypass -NoExit`  

**KQL Query**:

**Results:**
![flag 6](https://github.com/user-attachments/assets/54267b63-e218-4e2a-a4a1-882f6234aca5)

---

### 🔹 Flag 7 – Lateral Movement  
**Target Machine**: `victor-disa-vm`  

**KQL Query**:

**Results:**
![flag 7](https://github.com/user-attachments/assets/59b8c0fa-0e8d-42dc-aac5-d6796cc4b79a)

---

### 🔹 Flag 8 – Entry Indicator on Second Host  
**Dropped File**: `savepoint_sync.lnk`  

**KQL Query**:

**Results:**
![flag 8](https://github.com/user-attachments/assets/cd52fbfb-6e33-4376-b93d-55cc0b366e00)


### 🔹 Flag 8.1 – Registry Persistence on Second Host  
**Execution**:  
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\savepoint_sync.ps1"`  

**KQL Query**:

**Results:**
![flag 8 1](https://github.com/user-attachments/assets/ace65c6b-99b4-433b-a8a9-e64b1bd586c7)

---

### 🔹 Flag 9 – New C2 Domain on Second Host  
**Domain**: `eo1v1texxlrdq3v.m.pipedream.net`  

**KQL Query**:

**Results:**
![flag 9](https://github.com/user-attachments/assets/b985dedd-f40c-473f-a7dc-a25de04e5893)


---

### 🔹 Flag 10 – WMI-Based Persistence  
**Trigger Time**: `2025-05-26T02:48:07.2900744Z`  

**KQL Query**:

**Results:**
![flag 10](https://github.com/user-attachments/assets/f90bed20-25e0-4539-8a96-53aa49afd078)

---

### 🔹 Flag 11 – Credential Dump Simulation  
**Artifact**: `mimidump_sim.txt`  

**KQL Query**:

**Results:**
![flag 11](https://github.com/user-attachments/assets/46d2bac9-353a-46e3-ba54-10189b197147)

---

### 🔹 Flag 12 – Outbound Data Transfer  
**SHA256**:  
`9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`  

**KQL Query**:

**Results:**
![flag 12](https://github.com/user-attachments/assets/59144762-3246-4d89-9476-4fa9a10e30d9)

---

### 🔹 Flag 13 – Sensitive Asset Accessed  
**File**: `RolloutPlan_v8_477.docx`  

**KQL Query**:

**Results:**
![flag 13](https://github.com/user-attachments/assets/e8d64fdb-8c40-4b4f-865c-28fe2bb25936)

---

### 🔹 Flag 14 – Tool Packaging Activity  
**Command**:  
`powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Compress-Archive -Path "C:\Users\Public\dropzone_spicy" -DestinationPath "C:\Users\Public\spicycore_loader_flag8.zip" -Force`  

**KQL Query**:

**Results:**
![flag 14](https://github.com/user-attachments/assets/1842f937-7de5-430d-870c-2f9f9a72c69f)

---

### 🔹 Flag 15 – Payload Planted  
**Archive**: `spicycore_loader_flag8.zip`  

**KQL Query**:

**Results:**

---

### 🔹 Flag 16 – Final Scheduled Task Execution  
**Timestamp**: `2025-05-26T07:01:01.6652736Z`  

**KQL Query**:

**Results:**

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

