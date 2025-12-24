# Enterprise File Integrity Monitoring (FIM) & Behavioral Ransomware Detection using Wazuh

## 🛡️ Executive Summary

This project demonstrates the design and deployment of an **Enterprise-Grade File Integrity Monitoring (FIM) and Behavioral Detection system**. Moving beyond traditional signature-based security, this solution identifies the **Tactics, Techniques, and Procedures (TTPs)** used in modern ransomware and insider threat campaigns.

By integrating **Wazuh FIM**, **Sysmon telemetry**, and **Complex Correlation Logic**, the system provides real-time visibility into mass encryption, shadow copy deletion, and unauthorized data staging. This proactive approach bridges the gap between passive logging and active threat mitigation, significantly reducing the Mean Time to Detect (MTTD) in a SOC environment.

---

## 🎯 Objectives

* **Detect Behavioral Anomalies:** Identify mass file renaming and encryption patterns using frequency analysis.
* **Identify Recovery Inhibition:** Detect the deletion of Volume Shadow Copies (backups) via command-line monitoring.
* **Monitor High-Risk Directories:** Secure sensitive paths using real-time File Integrity Monitoring (FIM).
* **Correlate Multi-Source Telemetry:** Link FIM events with Sysmon process metadata for "high-fidelity" alerts.
* **Map to MITRE ATT&CK:** Align all detections with industry-standard adversary frameworks.

---

## 🏗️ Architecture

**Tools & Technologies:**

* **Wazuh SIEM:** Centralized Manager, Ruleset Engine, and Dashboard.
* **Sysmon:** Advanced endpoint telemetry for process and file-system visibility.
* **Syscheck (FIM):** Real-time file integrity monitoring.
* **PowerShell:** Used for adversary simulation and validation.

**Architecture Diagram:**

```
![Architecture Diagram](screenshots/architecture-diagram.png)

```

---

## 🛠️ Implementation Steps

### 1️⃣ Advanced Telemetry Deployment

* Installed **Wazuh agents** on Windows endpoints.
* Deployed **Sysmon** with a hardened configuration to capture Event ID 1 (Process Creation), 11 (File Creation), and 13 (Registry).
* Configured the agent to forward Sysmon logs via the `eventchannel` format for structured data analysis.

### 2️⃣ FIM: The "Bait Directory" Strategy

Configured `ossec.conf` to monitor "Bait" (Honey-file) folders. Any modification here triggers an immediate high-priority alert, as legitimate users have no reason to access these files.

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>600</frequency>
  <directories check_all="yes" realtime="yes">C:\Users\Public\Documents\Bait</directories>
  <directories check_all="yes" realtime="yes">C:\Windows\Temp</directories>
</syscheck>

```

### 3️⃣ Custom Detection Rules (Detection Layer)

These rules identify specific "snapshot" actions of an attacker using shortened field names for modern Wazuh compatibility.

```xml
<group name="ransomware,behavioral,windows,">

  <rule id="100900" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)vssadmin.*delete.*shadows</field>
    <description>Behavioral Alert: Volume Shadow Copy Deletion Detected</description>
    <mitre><id>T1490</id></mitre>
  </rule>

  <rule id="100901" level="10">
    <if_sid>61613</if_sid>
    <field name="win.eventdata.targetFilename" type="pcre2">(?i)\.(locked|encrypted|aes|crypted)$</field>
    <description>Behavioral Alert: Suspicious File Extension Change (Possible Encryption)</description>
    <mitre><id>T1486</id></mitre>
  </rule>

</group>

```

### 4️⃣ Advanced Correlation Logic (Intelligence Layer)

This rule links multiple "Suspicious Extension" alerts into a single **Critical Incident** if 10 or more files are changed within 5 seconds.

```xml
<group name="ransomware,correlation,">
  <rule id="110900" level="15" frequency="10" timeframe="5">
    <if_matched_sid>100901</if_matched_sid>
    <same_host/>
    <description>CRITICAL: Potential Ransomware Attack - Mass Encryption Detected</description>
    <mitre><id>T1486</id></mitre>
  </rule>
</group>

```

---

## 🧪 Adversary Simulation (Technical Appendix)

The following PowerShell commands were used to validate the ruleset against real-world attack patterns.

**A. Recovery Inhibition (T1490):**

```powershell
vssadmin.exe delete shadows /all /quiet

```

**B. Mass Encryption Simulation (T1486):**

```powershell
# Create 15 bait files and rapidly rename them to trigger correlation
1..15 | ForEach-Object { 
    $f = "C:\Users\Public\Documents\Bait\file$_.txt"
    New-Item $f -Value "ImportantData"
    Rename-Item $f "$f.locked" 
}

```

**C. Insider Threat: Data Staging (T1074):**

```powershell
New-Item -ItemType Directory -Path "C:\Users\Public\Documents\Staging"
1..5 | ForEach-Object { New-Item "C:\Users\Public\Documents\Staging\Exfil_$_.xlsx" -Value "Internal" }

```

---

## 🛡️ Mitigations & Recommendations

### Mitigations Implemented

* **Directory Hardening:** Restricted write access to Public directories to prevent unauthorized staging.
* **Canary Infrastructure:** Deployed "Bait" files to act as early-warning triggers for automated crawlers.
* **Telemetry Optimization:** Filtered Sysmon noise at the agent level to ensure only actionable data reaches the manager.

### Strategic Recommendations

* **Automated Host Isolation:** Implement Wazuh Active Response to automatically firewall endpoints upon Rule `110900` trigger.
* **Immutable Backups:** Transition to off-site, immutable storage to counter the "Shadow Copy Deletion" tactic.
* **Egress Filtering:** Block non-standard outbound ports to disrupt Command & Control (C2) communication.

---

## 🔑 Key Takeaways & Skills Learned

* **Behavioral > Signature:** Shifted the defense posture from looking for "known bad" files to "known bad" behaviors.
* **Alert Fidelity:** Utilized correlation to eliminate alert fatigue, ensuring only critical clusters of activity reach the analyst.
* **SOC Workflow:** Developed a full-cycle investigation path from raw telemetry to incident resolution.

| Skill Category | Technical Proficiency |
| --- | --- |
| **SIEM Engineering** | Wazuh `ossec.conf` optimization & agent group management. |
| **Rule Development** | Advanced XML rule authoring, PCRE2 Regex, and Correlation logic. |
| **Threat Hunting** | MITRE ATT&CK mapping and TTP identification. |
| **Endpoint Security** | Sysmon telemetry deployment and eventchannel log analysis. |
| **Adversary Simulation** | PowerShell-based attack emulation for SOC validation. |

---

## 📊 Final Results

* **Alert Visibility:** 100% detection of simulated ransomware and staging activity.
* **Response Time:** Achieved near real-time (<2 seconds) alerting for mass file modifications.
* **Audit Ready:** All logs enriched with user, process, and command-line context for forensic integrity.

**Final Dashboard Screenshot:**

```
![Wazuh Dashboard](screenshots/wazuh-dashboard.png)

```

---

## 🚀 How to Install (GitHub Guide)

1. **Install Sysmon:** Use [SwiftOnSecurity's Config](https://github.com/SwiftOnSecurity/sysmon-config) on your Windows agent.
2. **Configure Wazuh Agent:** Add the `eventchannel` and `<syscheck>` blocks provided in Step 2 to your `ossec.conf`.
3. **Add Rules:** Copy the XML rules from Steps 3 & 4 into `/var/ossec/etc/rules/local_rules.xml` on your Wazuh Manager.
4. **Restart:** Restart the Wazuh Manager and Agent.
5. **Simulate:** Run the PowerShell scripts in the Technical Appendix to verify alerts.

---

### CV Summary

**Project:** Enterprise File Integrity Monitoring & Behavioral Ransomware Detection using Wazuh
**Description:** Engineered a SOC-ready detection engine focusing on behavioral TTPs (Mass Encryption, Backup Destruction, and Data Staging). Developed complex correlation rules in XML to link FIM and Sysmon telemetry, mapping all alerts to the MITRE ATT&CK framework. Successfully simulated ransomware lifecycles to validate real-time alerting and incident response workflows.
**Key Skills:** SIEM Engineering, Wazuh, Sysmon, File Integrity Monitoring (FIM), Threat Hunting, XML Rule Development, MITRE ATT&CK, Adversary Simulation.