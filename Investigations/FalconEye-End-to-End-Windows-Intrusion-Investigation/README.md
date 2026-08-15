# FalconEye — End-to-End Windows Intrusion Investigation

## Overview

This project documents an end-to-end Windows intrusion investigation
performed using Splunk and Windows endpoint telemetry.

The investigation began with suspicious activity on `CLIENT02` and
progressively correlated process execution, Windows service activity,
PowerShell activity, credential-access techniques, Kerberos
authentication, and remote activity involving `CLIENT03`.

The objective was to correlate individual events and reconstruct the
attacker's activity across the environment.

The investigation covered multiple stages of the attack, including
- PowerShell execution and Active Directory reconnaissance
- Service creation and unquoted service path abuse
- Privilege escalation
- Credential access and DCSync
- Over-Pass-the-Hash
- Kerberos ticket abuse
- S4U impersonation and Pass-the-Ticket
- Remote authentication and lateral movement
- Process execution on the destination host

## Investigation Scope

| Host | Role |
|---|---|
| `CLIENT02` | Primary workstation where the initial activity and most of the attack chain was observed |
| `CLIENT03` | Destination host involved in lateral movement |
| Domain Controller | Kerberos and Active Directory authentication infrastructure |

## Data Sources

The investigation used Windows and endpoint telemetry available
through Splunk, including:

- Sysmon process creation events
- Windows Security Events
- PowerShell logging
- Windows service activity
- Kerberos authentication events
- Process command-line data
- File and process hash information

Important event types examined during the investigation included:

| Event ID | Purpose |
|---|---|
| `1` | Sysmon Process Creation |
| `4624` | Successful Logon |
| `4625` | Failed Logon |
| `4768` | Kerberos TGT Request |
| `4769` | Kerberos Service Ticket Request |
| `7045` | Windows Service Creation |
| `4103` | PowerShell Module Logging |
| `4104` | PowerShell Script Block Logging |

---
 # Investigation Findings

## 1. Initial Execution & Discovery

The investigation began by reviewing process and PowerShell activity on
`CLIENT02`. Sysmon process creation and PowerShell events were used to
identify suspicious execution and Active Directory reconnaissance.

Relevant queries:
- [`process-analysis.spl`](Splunk-Queries/process-analysis.spl)
- [`powershell-analysis.spl`](Splunk-Queries/powershell-analysis.spl)

The activity showed PowerShell-based reconnaissance of the environment.

---

## 2. Service Creation & Privilege Escalation

Service-related activity was investigated to identify newly created or
modified services. The suspicious service used an unquoted executable
path containing spaces.
Relevant query:
- [`service-analysis.spl`](Splunk-Queries/service-analysis.spl)

Process creation telemetry was then correlated to identify the executable
launched by the service and its execution context.

The service execution resulted in a process running with
`NT AUTHORITY\SYSTEM`, indicating privilege escalation.
---
## 3. Credential Access — DCSync

Process command-line telemetry was reviewed for credential-access
activity. The DCSync command was identified through suspicious
command-line parameters.

Relevant query:
- [`dcsync-analysis.spl`](Splunk-Queries/dcsync-analysis.spl)

The command indicated an attempt to replicate Active Directory
credentials.

---

## 4. Over-Pass-the-Hash

Kerberos authentication events were correlated with process activity
to investigate Over-Pass-the-Hash.

Relevant query:
- [`kerberos-analysis.spl`](Splunk-Queries/kerberos-analysis.spl)

Event IDs `4768` and `4769` were examined to identify the Kerberos
authentication activity and the account involved.

--
## 5. S4U / Pass-the-Ticket
A suspicious `s4u` command was identified containing an AES256 key,
an SPN for `CLIENT03`, Administrator impersonation, and `/ptt`.

Relevant query:
- [`s4u-analysis.spl`](Splunk-Queries/s4u-analysis.spl)

This activity indicated Kerberos service-ticket abuse and preparation
for access to `CLIENT03`.

---
## 6. Lateral Movement

Authentication activity on `CLIENT03` was investigated following the
S4U activity.

Relevant queries:
- [`remote-logon-analysis.spl`](Splunk-Queries/remote-logon-analysis.spl)
- [`process-analysis.spl`](Splunk-Queries/process-analysis.spl)

A successful remote logon was correlated with subsequent Sysmon process
creation on `CLIENT03`, allowing the process spawned after the remote
access to be identified.
---
# Conclusion

The investigation reconstructed a multi-stage attack:

```text
Initial Execution
      ↓
AD Reconnaissance
      ↓
Service Abuse
      ↓
Privilege Escalation
      ↓
DCSync
      ↓
Over-Pass-the-Hash
      ↓
S4U / Pass-the-Ticket
      ↓
Lateral Movement
      ↓
Remote Process Execution



## Attack Timeline

The detailed chronological timeline is available in
[`timeline.md`](timeline.md).

