# Australian Signals Directorate Live Fire Exchange Program
These are my personal notes from the **ASD Live Fire Cyberbitrange** event. This document is not provided by or affiliated with the **Australian Signals Directorate (ASD)** or **CyberbitRange**.

---

## Malware Investigation

### Step 1: Process Monitoring
#### Open Process Explorer by Sysinternals (preferred) or Task Manager
```powershell
taskmgr
```
*Opens Task Manager to review processes.*

#### Find Suspicious Processes
```powershell
tasklist | findstr /i "powershell cmd python wscript cscript mshta wmic rundll32 regsvr32 schtasks bitsadmin"
```
*Lists running processes and filters for common suspicious executables.*

#### Kill Suspicious Processes
```powershell
taskkill /F /PID <PID>
```
*Forcefully terminates a process by its PID.*

#### Open Event Viewer (Security Logs)
```powershell
eventvwr
```
*Opens Event Viewer to review system and security logs.*

---

### Step 2: Scheduled Tasks
#### Open Task Scheduler (GUI)
```powershell
taskschd
```
*Opens the Task Scheduler GUI to review scheduled tasks.*

#### Detect Suspicious Scheduled Tasks (One-Liner)
```powershell
Get-ScheduledTask | ? { $_.TaskPath -notmatch "^\\Microsoft\\Windows" -and ($_.Actions | % Execute | Out-String) -match "cmd|powershell|python|wscript|cscript|\.bat|\.vbs|\.js|\.py|mshta|rundll32|schtasks|bitsadmin" }
```
*Finds scheduled tasks that execute potentially malicious scripts or binaries, excluding system tasks.*

#### Remove a Suspicious Scheduled Task
```powershell
Unregister-ScheduledTask -TaskName "<SuspiciousTaskName>" -Confirm:$false
```
*Deletes a scheduled task without requiring confirmation.*

---

### Step 3: Registry Startup
#### Open Registry Editor (GUI)
```powershell
regedit
```
*Opens the Windows Registry Editor to inspect startup entries.*

#### Check Startup Programs (System & User Level)
```powershell
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```
*Lists programs set to run at startup for both system-wide and user-specific configurations.*

---

### Step 4: Network Communications
#### List Active Network Connections
```powershell
netstat -bano
```
*Displays active network connections, including the owning process ID (PID).*

---

### Step 5: File Investigation
#### Find Specific File Types (Excel, DOCX, PDF)
```powershell
Get-ChildItem -Path C:\Users -Include *.xlsx,*.docx,*.pdf -File -Recurse -ErrorAction SilentlyContinue
```
*Searches for specified file types recursively in user directories, ignoring errors from inaccessible folders.*
