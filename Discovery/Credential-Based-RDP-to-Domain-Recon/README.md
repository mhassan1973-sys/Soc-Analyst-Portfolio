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

