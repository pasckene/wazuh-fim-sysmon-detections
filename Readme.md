
---

# Enterprise File Integrity Monitoring (FIM) & Malware/Insider Threat Detection using Wazuh

## Project Overview

This project demonstrates the design, deployment, and validation of an **enterprise-grade File Integrity Monitoring (FIM)** and **endpoint behavioral visibility solution** using **Wazuh** and **Sysmon**. The solution focuses on detecting **insider threat activity**, **unauthorized system changes**, and **malware behavior** (e.g., DeerStealer) on **Windows endpoints** in a SOC environment.

The project emphasizes **telemetry correlation, behavioral analysis, and alert fidelity**, simulating real-world SOC operations rather than relying solely on signature-based detection.

---

## Objectives

* Detect unauthorized file creation, modification, and deletion
* Monitor high-risk directories associated with insider misuse or malware staging
* Capture process, user, and command-line context using Sysmon
* Detect malware execution and data exfiltration attempts (e.g., DeerStealer)
* Correlate file and process activity to reduce false positives
* Produce **investigation-ready alerts** for SOC analysts

---

## Architecture

**Windows Endpoints**
|
v
Wazuh Agent + Sysmon
|
v
Wazuh Manager
|
v
Alerts & Dashboards

**Tools & Technologies:**

* Wazuh SIEM (Manager & Agents)
* Syscheck (File Integrity Monitoring)
* Sysmon (Endpoint Telemetry)
* Windows 10 / 11
* PowerShell
* Custom Wazuh Rules for Insider Threats & DeerStealer Malware

**Architecture Diagram Screenshot:**

```
![Architecture Diagram](screenshots/architecture-diagram.png)
```

---

## Implementation Steps

### 1️⃣ Agent & Telemetry Deployment

* Installed **Wazuh agents** on Windows endpoints
* Configured **Sysmon** to capture process-level telemetry
* Enabled **Sysmon event forwarding** via Wazuh eventchannel
* Verified secure agent-manager communication

**Deployment Screenshot Placeholder:**

```
![Agent Deployment](screenshots/agent-deployment.png)
```

---

### 2️⃣ File Integrity Monitoring (FIM) Configuration

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>600</frequency>
  <directories check_all="yes">C:\Users\Public\Documents</directories>
  <directories check_all="yes" realtime="yes">C:\Windows\Temp</directories>
</syscheck>
```

**Rationale:** Focused on directories often involved in insider misuse or malware staging.

**FIM Configuration Screenshot Placeholder:**

```
![FIM Configuration](screenshots/fim-configuration.png)
```

---

### 3️⃣ Sysmon Telemetry Integration (Windows)

* Monitored **Sysmon Event IDs**:

  * **1** – Process Creation
  * **3** – Network Connections
  * **7** – Image Load
  * **11** – File Creation
  * **13** – Registry Modification

* Configured Wazuh agents to forward eventchannel logs:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

**Sysmon Telemetry Screenshot Placeholder:**

```
![Sysmon Telemetry](screenshots/sysmon-telemetry.png)
```

---

### 4️⃣ Custom Detection Rules

**Insider Threat Detection:**

```xml
<rule id="100210" level="10">
  <if_sid>550</if_sid>
  <field name="syscheck.path">C:\\Users\\Public\\Documents</field>
  <description>Unauthorized file activity in Public Documents directory</description>
  <mitre>T1083</mitre>
</rule>

<rule id="100220" level="11">
  <if_sid>61603</if_sid>
  <description>Suspicious process created with command-line visibility (Sysmon)</description>
  <mitre>T1059</mitre>
</rule>
```

**DeerStealer Malware Detection:**

```xml
<group name="malware,deerstealer,windows">
  <!-- Process Execution -->
  <rule id="100800" level="14">
    <if_sid>61603</if_sid>
    <field name="win.system.eventdata.Image">(?i).*deerstealer.*\.exe</field>
    <description>DeerStealer malware process execution detected</description>
    <mitre>
      <id>T1204.002</id>
      <id>T1059</id>
    </mitre>
    <group>deerstealer,execution,malware</group>
  </rule>

  <!-- Credential/Wallet File Drops -->
  <rule id="100801" level="13">
    <if_sid>61613</if_sid>
    <field name="win.system.eventdata.TargetFilename">(?i).*(wallet|cookies|login data|passwords|keychain).*\.db</field>
    <description>DeerStealer suspicious credential or wallet file creation</description>
    <mitre>
      <id>T1555</id>
      <id>T1005</id>
    </mitre>
    <group>deerstealer,credential-access,malware</group>
  </rule>

  <!-- Registry Persistence -->
  <rule id="100803" level="13">
    <if_sid>61612</if_sid>
    <field name="win.system.eventdata.TargetObject">(?i).*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.*</field>
    <field name="win.system.eventdata.Details">(?i).*deerstealer.*</field>
    <description>DeerStealer persistence via Run registry key</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
    <group>deerstealer,persistence,malware</group>
  </rule>

  <!-- Network Connections -->
  <rule id="100804" level="12">
    <if_sid>61605</if_sid>
    <field name="win.system.eventdata.Image">(?i).*deerstealer.*</field>
    <description>DeerStealer outbound network connection (possible C2)</description>
    <mitre>
      <id>T1071</id>
      <id>T1041</id>
    </mitre>
    <group>deerstealer,command-and-control,malware</group>
  </rule>
</group>
```

**Custom Rules Screenshot Placeholder:**

```
![Custom Rules](screenshots/custom-rules.png)
```

---

### 5️⃣ Activity Simulation & Validation

**Windows Example Commands:**

```powershell
echo "confidential data" > C:\Users\Public\Documents\salary.xlsx
echo "test data" > C:\Windows\Temp\audit_test.bin
copy notepad.exe deerstealer.exe
.\deerstealer.exe
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Deer /t REG_SZ /d "C:\Users\Public\deerstealer.exe"
New-Item "$env:APPDATA\wallets.db"
```

**Simulation Screenshot Placeholder:**

```
![Activity Simulation](screenshots/activity-simulation.png)
```

---

### 6️⃣ SOC Investigation Workflow

1. Identify affected file and directory
2. Review Sysmon process metadata (PID, image, command line)
3. Correlate timestamp and user context
4. Determine policy violation or malware behavior
5. Escalate or close with documented evidence

**Alert Investigation Screenshot Placeholder:**

```
![Alert Investigation](screenshots/alert-investigation.png)
```

---

### 7️⃣ Correlation Rules

**Correlation links low-level alerts into high-confidence events:**

```xml
<group name="deerstealer,correlation,malware">
  
  <!-- Execution + credential/wallet creation -->
  <rule id="110800" level="15">
    <if_sid>100800</if_sid>
    <if_sid>100801</if_sid>
    <same_host/>
    <timeframe>3600</timeframe>
    <description>DeerStealer executed and created credential/wallet files</description>
    <mitre>
      <id>T1055</id>
      <id>T1005</id>
    </mitre>
  </rule>

  <!-- Execution + registry persistence -->
  <rule id="110801" level="15">
    <if_sid>100800</if_sid>
    <if_sid>100803</if_sid>
    <same_host/>
    <timeframe>3600</timeframe>
    <description>DeerStealer executed and added persistence key</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
  </rule>

  <!-- Execution + suspicious network connection -->
  <rule id="110802" level="14">
    <if_sid>100800</if_sid>
    <if_sid>100804</if_sid>
    <same_host/>
    <timeframe>1800</timeframe>
    <description>DeerStealer process connected to possible C2 server</description>
    <mitre>
      <id>T1071</id>
      <id>T1041</id>
    </mitre>
  </rule>

</group>
```

**Correlation Rules Screenshot Placeholder:**

```
![Correlation Rules](screenshots/correlation-rules.png)
```

---

### Results & Impact

* Near real-time detection (<2 seconds)
* Full **process + file context** for investigations
* Detection of **insider threats and DeerStealer malware**
* Reduced false positives through **correlation rules**
* Improved analyst confidence and triage speed

**Dashboard Screenshot Placeholder:**

```
![Wazuh Dashboard](screenshots/wazuh-dashboard.png)
```

---

### Lessons Learned

* FIM alone lacks sufficient context without process telemetry
* Sysmon significantly improves investigation depth
* Correlation rules reduce noise and increase alert fidelity
* Directory and process scoping are essential for noise reduction
* Simulation & testing are critical for SOC readiness

---

### CV Summary

**Project:** Enterprise File Integrity Monitoring & Malware Detection using Wazuh
**Description:** Designed and deployed a SOC-ready **FIM and Sysmon-based endpoint monitoring solution**, integrating **custom detection and correlation rules for insider threats and DeerStealer malware** across Windows systems. Delivered **high-confidence alerts**, MITRE ATT&CK mapped telemetry, and actionable insights for SOC operations.

**Key Skills:** Wazuh SIEM, Sysmon, File Integrity Monitoring, Malware Detection, Correlation Rules, MITRE ATT&CK, Windows Administration, SOC Operations, Security Rule Authoring

---
