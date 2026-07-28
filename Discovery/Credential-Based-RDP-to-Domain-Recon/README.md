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
    

