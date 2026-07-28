# Credential-Based RDP Access → Domain Reconnaissance (BloodHound + Native Binaries) 

## Summary

This project documents the design of a multi-stage detection for credential-based Remote Desktop Protocol (RDP) access followed by Active Directory reconnaissance using LDAP enumeration and native Windows discovery binaries.

The project includes the attack scenario, detection logic, KQL and SPL queries, investigation workflow, MITRE ATT&CK mapping, and response recommendations.

This project represents a detection engineering design and has not yet been validated in a personal lab environment.

## Validation Status

**Current Status:** Detection Design (Not Yet Validated)

The attack scenario, detection logic, and analytics were developed while studying Microsoft Defender XDR, Microsoft Sentinel, Splunk, Sysmon, and MITRE ATT&CK.

The queries have not yet been executed against live or simulated telemetry and should be considered detection hypotheses pending lab validation.

### Planned Validation

- [ ] Validate native Windows discovery commands
- [ ] Validate LDAP reconnaissance telemetry
- [ ] Tune thresholds
- [ ] Document false positives
- [ ] Add screenshots from a lab environment

## Objective

Design a detection capable of identifying an attacker who:

1. Gains access using stolen domain credentials through RDP.
2. Performs LDAP-based Active Directory reconnaissance.
3. Executes native Windows discovery commands to confirm targets.
4. Correlates the activity into a single investigation.
 ## Attack Scenario

A domain account, `a.raza` (CORP.LOCAL), is compromised through a phishing attack. Using the stolen credentials, the attacker authenticates through the organization's internet-facing Remote Desktop Gateway (`RDGW01`) and establishes a Logon Type 10 (RemoteInteractive) session on the internal workstation `WKS-22`.

Microsoft Defender's User and Entity Behavior Analytics (UEBA) identifies the logon as anomalous because it originates from an unfamiliar location and occurs outside the user's normal activity baseline. Although this activity is immediately flagged, no malicious actions have yet been observed on the endpoint.

Over the next ~25 hours, the attacker performs BloodHound-style LDAP enumeration to collect Active Directory relationship data. While this generates significant LDAP traffic, many organizations do not log LDAP client queries by default, allowing the attacker to build an offline graph of the environment without generating traditional Windows Event Log telemetry.

Approximately two days later, the attacker returns to the compromised workstation and executes a small set of native Windows discovery commands (`whoami`, `nltest`, and `net`) to verify specific users, groups, and domain information identified during the earlier LDAP collection. Rather than performing another broad enumeration, the attacker limits activity to targeted verification, reducing additional reconnaissance noise.

This activity occurs during the **Discovery** phase of the MITRE ATT&CK framework and immediately precedes **Lateral Movement**. Detecting the attacker at this stage is significantly less costly than detecting them after they begin moving between systems, as defenders can contain the compromise before additional hosts, privileged accounts, or administrative paths are leveraged.
    


## Data Sources / Prerequisites

The detection logic in this project is presented for both **Microsoft Defender XDR/Microsoft Sentinel (KQL)** and **Splunk Enterprise (SPL)**. The following telemetry sources are required to support each stage of the detection.

| Detection Stage | Microsoft Telemetry | Splunk Telemetry | Purpose |
|-----------------|---------------------|------------------|---------|
| Stage 0 – Anomalous RDP Logon | `BehaviorAnalytics`, `DeviceLogonEvents` | Windows Security Event Logs (e.g., Event ID 4624) or equivalent ingested authentication logs | Detects anomalous Remote Desktop logons based on user behavior or authentication events. |
| Stage 1 – LDAP Reconnaissance | `IdentityDirectoryEvents` (Microsoft Defender for Identity) | SilkETW/SilkService (`Microsoft-Windows-LDAP-Client`) ingested into Splunk | Detects large-scale LDAP enumeration associated with BloodHound or SharpHound. |
| Stage 2 – Native Binary Reconnaissance | `DeviceProcessEvents` (Microsoft Defender for Endpoint) | Sysmon Event ID 1 (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`) | Detects execution of native Windows discovery commands such as `whoami`, `nltest`, and `net`. |

## Detection Logic

The detection is divided into four stages that mirror the attack progression. Each stage targets a different phase of the attack and uses different telemetry sources. Together, these stages provide higher confidence than relying on a single detection in isolation.

- **Stage 0:** UEBA detects an anomalous RDP logon using learned behavioral baselines.
- **Stage 1:** LDAP enumeration identifies large-scale Active Directory reconnaissance.
- **Stage 2:** Native Windows discovery commands confirm targeted reconnaissance on the compromised endpoint.
- **Correlated Hunt:** Correlates LDAP reconnaissance with native discovery activity to identify a multi-stage attack performed by the same account and device.

  ## Stage 0 – Anomalous RDP Logon (UEBA)

### Purpose

The first stage of the detection focuses on identifying anomalous Remote Desktop Protocol (RDP) logons performed using valid domain credentials. Rather than relying on a custom detection rule, this stage leverages Microsoft Sentinel's User and Entity Behavior Analytics (UEBA), which builds behavioral baselines for users and devices over time.

### Detection Strategy

In this scenario, the compromised account (`a.raza`) successfully authenticates to the internal workstation `WKS-22` through the organization's Remote Desktop Gateway (`RDGW01`). Although the authentication is successful, the activity deviates from the user's established behavioral baseline by occurring from an unfamiliar location and at an unusual time.

Because the logon uses valid credentials, a traditional rule looking only for successful RDP logons would generate a large number of false positives. UEBA instead evaluates the activity against the user's historical behavior and flags the deviation as anomalous.

### Why No Custom Analytics Rule?

No custom KQL analytics rule is authored for this stage because UEBA already performs this behavioral analysis natively. Recreating the same logic with static rules would not provide the same user-specific behavioral context and would likely increase false positives.

## Stage 1 – LDAP Reconnaissance

### Purpose

The second stage detects large-scale Active Directory reconnaissance performed through LDAP queries. In this scenario, the attacker uses BloodHound or SharpHound to enumerate directory information and build an offline graph of relationships between users, groups, computers, and other Active Directory objects.

### Detection Strategy

The detection focuses on LDAP queries targeting user account objects by identifying searches that contain the LDAP filter `samAccountType=805306368`. It aggregates matching queries performed by the same account and device within the configured hunt window and generates a detection when the query volume exceeds the defined threshold.

This detection is designed to identify one common LDAP enumeration pattern and does **not** attempt to detect every LDAP query generated by BloodHound.

### Detection Coverage

This detection primarily identifies LDAP enumeration targeting **user account objects**. It does not detect enumeration of other Active Directory object types, including:

- Computer objects
- Group objects
- Organizational Units (OUs)
- Group Policy Objects (GPOs)
- Domain trust relationships
- Other LDAP filters used by BloodHound

As a result, this detection provides **partial coverage** of BloodHound activity rather than complete coverage of all LDAP reconnaissance techniques.

### Detection Queries

**KQL**

Location: `kql/Stage-1-LDAP-Recon.kql`

**SPL**

Location: `spl/Stage-1-LDAP-Recon.spl`

### Detection Notes

- The query threshold (`QueryCount > 10`) is an initial design assumption and has not yet been validated against lab or production telemetry.
- The Microsoft implementation assumes **Microsoft Defender for Identity** telemetry (`IdentityDirectoryEvents`) is available.
- The Splunk implementation assumes LDAP client telemetry is collected using **SilkETW/SilkService** (`Microsoft-Windows-LDAP-Client`), as LDAP queries are not logged by default in Windows Event Logs.


