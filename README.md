<!-- ASD Programme Logo -->
<p align="center">
  <img src="https://github.com/simon-im-security/ASD-Live-Fire-Exchange-Program/blob/main/Australian_Signals_Directorate_program_logo.png" alt="ASD Programme Logo" width="300">
</p>

<p><strong>These are my personal notes from the <em>ASD Live Fire Cyberbitrange</em> event. This document is not provided by or affiliated with the <em>Australian Signals Directorate (ASD)</em> or <em>CyberbitRange</em>.</strong></p>

<details>
<summary><strong>🔍 Lifefire Bangalore - Malicious Detection</strong></summary>

<h3>Scenario: Command and Control (C2) Detection</h3>

<ul>
  <li>Gather logs using Event Viewer</li>
  <li>Identify malware via IOCs</li>
  <li>Remove malware and kill process</li>
  <li>Investigate network activity (C2)</li>
  <li>Block source and set firewall rules</li>
  <li>Remove persistence (startup/registry/scheduled tasks)</li>
</ul>

<h3>🔧 Tools Available</h3>

<table>
  <thead>
    <tr><th>Tool Name</th><th>Functionality</th></tr>
  </thead>
  <tbody>
    <tr><td>CyberChef</td><td>Data analysis and decoding</td></tr>
    <tr><td>DnSpy</td><td>.NET debugging/decompiling</td></tr>
    <tr><td>Eric Zimmerman Tools</td><td>Windows forensics</td></tr>
    <tr><td>Ghidra</td><td>Reverse engineering</td></tr>
    <tr><td>oletools</td><td>Office macro analysis</td></tr>
    <tr><td>Pestudio</td><td>Static malware analysis</td></tr>
    <tr><td>Sysinternals</td><td>Advanced monitoring</td></tr>
    <tr><td>WinSCP</td><td>Secure file transfers</td></tr>
  </tbody>
</table>

<h3>🧱 Step 1: Process Monitoring</h3>
<pre><code>taskmgr

tasklist | findstr /i "powershell cmd python wscript cscript mshta wmic rundll32 regsvr32 schtasks bitsadmin"

taskkill /F /PID &lt;PID&gt;

eventvwr
</code></pre>

<h3>🗓 Step 2: Scheduled Tasks</h3>
<pre><code>taskschd

Get-ScheduledTask | ? {
  $_.TaskPath -notmatch "^\\Microsoft\\Windows" -and 
  ($_.Actions | % Execute | Out-String) -match "cmd|powershell|python|wscript|cscript|.bat|.vbs|.js|.py|mshta|rundll32|schtasks|bitsadmin"
}

Unregister-ScheduledTask -TaskName "&lt;SuspiciousTaskName&gt;" -Confirm:$false
</code></pre>

<h3>🧬 Step 3: Registry Startup</h3>
<pre><code>regedit

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
</code></pre>

<h3>🌐 Step 4: Network Communications</h3>
<pre><code>netstat -bano
</code></pre>

<h3>📁 Step 5: File Investigation</h3>
<pre><code>Get-ChildItem -Path C:\Users -Include *.xlsx,*.docx,*.pdf -File -Recurse -ErrorAction SilentlyContinue
</code></pre>

</details>
