# Enterprise File Integrity Monitoring (FIM) & Sysmon-Based Insider Threat Detection using Wazuh

## 📌 Project Overview

This project demonstrates the design, deployment, and validation of an **enterprise-grade File Integrity Monitoring (FIM)** and **endpoint behavioral visibility** solution using **Wazuh and Sysmon**. The focus is on **detecting insider threat activity, unauthorized system changes, and suspicious user/process behavior** across **Windows and Linux endpoints** in a SOC environment.

Rather than signature-based malware detection, the project emphasizes **telemetry correlation, behavior analysis, and alert fidelity**, aligning with real-world SOC operations.

---

## 🎯 Objectives

* Detect unauthorized file creation, modification, and deletion
* Monitor high-risk directories associated with insider misuse
* Capture process, user, and command-line context using Sysmon
* Correlate file activity with originating processes
* Reduce false positives through tuning and validation
* Produce investigation-ready alerts for SOC analysts

---

## 🏗️ Architecture

> 📸 **Screenshot Placeholder – Architecture Diagram**
> `screenshots/architecture-diagram.png`
>
> *(Include a diagram showing Windows & Linux endpoints, Wazuh Agents, Manager, and Dashboard flow)*

```
Windows Endpoints        Linux Servers
       |                       |
       v                       v
          Wazuh Agent + Sysmon
                     |
                     v
                Wazuh Manager
                     |
                     v
              Alerts & Dashboards
```

---

## 🧰 Tools & Technologies

* **Wazuh SIEM** (Manager & Agents)
* **Syscheck (File Integrity Monitoring)**
* **Sysmon (Endpoint Telemetry)**
* Windows 10 / 11
* Ubuntu Server
* PowerShell & Bash

---

## 🔧 Implementation Steps

### 1️⃣ Agent & Telemetry Deployment

* Installed Wazuh agents on Windows and Linux endpoints
* Installed and configured **Sysmon** on Windows endpoints
* Enabled Sysmon event forwarding via Wazuh `eventchannel`
* Verified agent-manager communication and secure log ingestion

---

### 2️⃣ File Integrity Monitoring Configuration

#### Windows Agent Configuration

```xml
<syscheck>
    <disabled>no</disabled>
    <frequency>600</frequency>

    <!-- Insider-risk directory -->
    <directories check_all="yes">C:\Users\Public\Documents</directories>

    <!-- Temporary execution & staging area -->
    <directories check_all="yes" realtime="yes">C:\Windows\Temp</directories>
</syscheck>
```

**Rationale:**

* `Public\Documents` → unauthorized data manipulation or staging
* `Windows\Temp` → short-lived files tied to user or process activity

---

#### Linux Agent Configuration

```xml
<syscheck>
    <disabled>no</disabled>
    <frequency>600</frequency>

    <directories check_all="yes">/etc</directories>
    <directories check_all="yes" realtime="yes">/var/www</directories>
</syscheck>
```

**Rationale:**

* `/etc` → configuration tampering and privilege misuse
* `/var/www` → unauthorized file changes by users or services

---

### 3️⃣ Sysmon Telemetry Integration (Windows)

Sysmon was configured to provide **process-level context** for file activity and user actions.

Monitored Sysmon Events:

* **Event ID 1** – Process Creation
* **Event ID 11** – File Creation
* **Event ID 3** – Network Connections
* **Event ID 7** – Image Load

Wazuh agent configuration:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

This enabled correlation between **file integrity events and originating processes**, including command-line arguments and user context.

---

## 🧪 Activity Simulation & Validation

> 📸 **Screenshot Placeholder – Activity Simulation Commands**
> `screenshots/activity-simulation-commands.png`
![Lab Architecture](images/Screenshot%202025-12-15%20101829.png)
![Lab Architecture](images/Screenshot%202025-12-15%20113742.png)
>
> *(Include terminal screenshots showing PowerShell and Bash commands used to generate file and process activity)*

### Insider Activity Simulation (Windows)

```powershell
echo "confidential data" > C:\Users\Public\Documents\salary.xlsx
```

### Suspicious File Staging (Windows)

```powershell
echo "test data" > C:\Windows\Temp\audit_test.bin
```

### Linux Configuration Change

```bash
sudo echo "audit_test" >> /etc/hosts
```

Sysmon captured the **process responsible**, while FIM captured the **file change**, allowing cross-validation.

---

## 🚨 Detection & Alert Validation

> 📸 **Screenshot Placeholder – Wazuh Alerts View**
> `screenshots/wazuh-alerts-view.png`
![Lab Architecture](images/img/Screenshot%202025-12-13%20145427.png)
![Lab Architecture](images/img/Screenshot%202025-12-13%20145533.png)
![Lab Architecture](images/img/Screenshot%202025-12-13%20150550.png)
>
> *(Include Wazuh dashboard alerts showing correlated FIM and Sysmon events)*

Observed alerts included:

* File added / modified
* Hash and permission changes
* Process name and command-line context (Sysmon)
* User context and timestamp correlation

This enabled analysts to determine **who did what, how, and when**.

---

## 🧠 Custom Detection Rules

> 📸 **Screenshot Placeholder – Custom Rules Configuration**
> `screenshots/custom-wazuh-rules.png`
>
> *(Include custom rules file or Wazuh manager rules UI showing rule IDs and logic)*

Custom Wazuh rules were written to prioritize insider-risk behavior rather than generic file changes.

```xml
<rule id="100210" level="10">
  <if_sid>550</if_sid>
  <field name="syscheck.path">C:\\Users\\Public\\Documents</field>
  <description>Unauthorized file activity in Public Documents directory</description>
  <mitre>T1083</mitre>
</rule>
```

```xml
<rule id="100220" level="11">
  <if_sid>61603</if_sid>
  <description>Suspicious process created with command-line visibility (Sysmon)</description>
  <mitre>T1059</mitre>
</rule>
```

**Enhancements:**

* Directory-aware severity
* Process-aware alerting
* MITRE ATT&CK mapping
* SOC escalation prioritization

---

## 🔍 SOC Investigation Workflow

> 📸 **Screenshot Placeholder – Alert Investigation Drill-down**
> `screenshots/alert-investigation-drilldown.png`
>
> *(Include alert detail view showing file path, process name, PID, user, and timestamp)*

1. Identify affected file and directory
2. Review Sysmon process metadata (PID, image, command line)
3. Correlate timestamp and user context
4. Determine policy violation or authorized action
5. Escalate or close with documented evidence

---

## 📊 Results & Impact

> 📸 **Screenshot Placeholder – Wazuh Dashboard Overview**
> `screenshots/wazuh-dashboard-overview.png`
>
> *(Include dashboards summarizing FIM and Sysmon activity trends)*

* ⚡ Near real-time detection (<2 seconds)
* 🔍 Full process and file context for investigations
* 🎯 Reduced false positives through tuning
* 🧠 Improved analyst confidence and triage speed

---

## 🧪 Lessons Learned

* FIM alone lacks sufficient context without process telemetry
* Sysmon significantly improves investigation depth
* Directory and process scoping are essential for noise reduction
* Validation through simulation is critical for SOC readiness

---

## 📄 CV Summary

> Designed and deployed a SOC-ready File Integrity Monitoring and Sysmon-based endpoint visibility solution using Wazuh, enabling detailed detection and investigation of insider threat activity across Windows and Linux systems.

---

## 📎 Future Enhancements

* Automated response actions for high-confidence alerts
* Advanced correlation between Sysmon and FIM events
* Dedicated insider threat dashboards
* User behavior baselining

---

## ✅ Status

✔ Project Completed
✔ Validated through controlled activity simulation
✔ SOC-ready and investigation-focused
