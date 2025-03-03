# Australian Signals Directorate Live Fire Exchange Programme

![ASD Programme Logo](https://github.com/simon-im-security/ASD-Live-Fire-Exchange-Program/blob/main/Australian_Signals_Directorate_program_logo.png)

These are my personal notes from the **ASD Live Fire Cyberbitrange** event. This document is not provided by or affiliated with the **Australian Signals Directorate (ASD)** or **CyberbitRange**.

---

## <span style="color:navy; font-weight:bold;">Lifefire Bangalore - Malicious Detection</span>

### **Scenario:** Command and Control (C2) detection via Splunk and McAfee, leveraging event logs for forensic analysis. The goal is to:
- **Gather logs** using Event Viewer to track system activity and intrusion attempts.
- **Identify malware** by cross-referencing process activity with known Indicators of Compromise (IOCs).
- **Remove malware** by terminating its process and deleting the source file.
- **Investigate network activity** to pinpoint Command and Control (C2) communication.
- **Block the malicious actor** by implementing firewall rules, host-based security policies, or blacklisting the source.
- **Mitigate persistence mechanisms** by analysing scheduled tasks, registry entries, and startup programmes.

---

### Tools Available
| Tool Name              | Functionality |
|------------------------|--------------|
| CyberChef v10.5.2     | Data analysis, encoding/decoding, and encryption/decryption tasks. |
| DnSpy                 | .NET debugger and decompiler for analysing malicious .NET applications. |
| Eric Zimmerman Tools  | Forensic tools for investigating Windows artifacts. |
| Ghidra                | Reverse engineering tool for analysing compiled binaries. |
| ILSpy                 | .NET decompiler to inspect and reverse engineer .NET assemblies. |
| oletools-0.60.1       | Analysis tools for inspecting malicious Microsoft Office files. |
| Pestudio              | Static malware analysis tool for inspecting PE files. |
| Python Tools          | Various Python-based security and forensic utilities. |
| SysinternalsSuite     | Collection of Windows system utilities for advanced monitoring and analysis. |
| WinSCP               | Secure file transfer tool using SCP, SFTP, and FTP. |
| Ay Base 64 Decoder.exe | Decodes Base64-encoded data, often used in malware obfuscation. |
| IL Disassembler.exe   | Disassembles .NET IL (Intermediate Language) code for analysis. |
| mTail.exe             | Real-time log file monitoring utility. |
| newsid.exe            | Generates new SID (Security Identifier) for system forensic analysis. |
| rktools.exe           | Windows Resource Kit tools for system administration and troubleshooting. |
| Scriptomatic2.exe     | Automates Windows Management Instrumentation (WMI) scripting. |

---

### Step 1: Process Monitoring
#### Open Process Explorer by Sysinternals (preferred) or Task Manager
```powershell
taskmgr
```

#### Find Suspicious Processes
```powershell
tasklist | findstr /i "powershell cmd python wscript cscript mshta wmic rundll32 regsvr32 schtasks bitsadmin"
```

#### Kill Suspicious Processes
```powershell
taskkill /F /PID <PID>
```

#### Open Event Viewer (Security Logs)
```powershell
eventvwr
```

---

### Step 2: Scheduled Tasks
#### Open Task Scheduler (GUI)
```powershell
taskschd
```

#### Detect Suspicious Scheduled Tasks (One-Liner)
```powershell
Get-ScheduledTask | ? { $_.TaskPath -notmatch "^\\Microsoft\\Windows" -and ($_.Actions | % Execute | Out-String) -match "cmd|powershell|python|wscript|cscript|\.bat|\.vbs|\.js|\.py|mshta|rundll32|schtasks|bitsadmin" }
```

#### Remove a Suspicious Scheduled Task
```powershell
Unregister-ScheduledTask -TaskName "<SuspiciousTaskName>" -Confirm:$false
```

---

### Step 3: Registry Startup
#### Open Registry Editor (GUI)
```powershell
regedit
```

#### Check Startup Programmes (System & User Level)
```powershell
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

---

### Step 4: Network Communications
#### List Active Network Connections
```powershell
netstat -bano
```

---

### Step 5: File Investigation
#### Find Specific File Types (Excel, DOCX, PDF)
```powershell
Get-ChildItem -Path C:\Users -Include *.xlsx,*.docx,*.pdf -File -Recurse -ErrorAction SilentlyContinue
