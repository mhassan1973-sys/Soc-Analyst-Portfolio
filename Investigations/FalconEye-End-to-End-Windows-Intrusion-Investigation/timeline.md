# FalconEye — Investigation Timeline

> Timeline reconstructed from the investigation. Times reflect the timestamps observed in the lab telemetry.

| Time | Host | Activity | Significance |
|---|---|---|---|
| 02:09:57 | CLIENT02 | `whoami.exe` execution | Initial command/process activity observed |
| 03:27:51 | CLIENT02 | Active Directory reconnaissance | Enumeration activity identified |
| 04:57:36 | CLIENT02 | `C:\program.exe` executed by `services.exe` | Execution through the vulnerable unquoted service path |
| 05:08:57 | CLIENT02 | `fun.exe` created | Suspicious executable introduced to the host |
| 05:10:30 | CLIENT02 | Mimikatz-related activity | Credential-access activity identified |
| 05:49:10 | CLIENT02 | Over-Pass-the-Hash activity | Kerberos authentication abuse identified |
| 06:18:19 | CLIENT02 | S4U activity targeting `http/Client03` | Ticket impersonation/preparation for access to CLIENT03 |
| 06:21:44 | CLIENT03 | `wsmprovhost.exe` spawned | Process execution observed following remote access |
| 06:49:48 | CLIENT02 | Additional account/authentication activity | Further credential/Kerberos abuse observed |

## Attack Chain

```text
Initial Execution
      ↓
Active Directory Reconnaissance
      ↓
Unquoted Service Path Abuse
      ↓
Privilege Escalation
      ↓
Credential Access
      ↓
Over-Pass-the-Hash
      ↓
S4U / Pass-the-Ticket
      ↓
Lateral Movement to CLIENT03
      ↓
Remote Process Execution
```

## Key Correlations

- Service-abuse activity was correlated with process creation under `NT AUTHORITY\SYSTEM`.
- Credential-access activity was followed by Kerberos authentication activity.
- S4U activity targeting `http/Client03` preceded process activity on CLIENT03.
- Remote authentication and subsequent process creation established the lateral-movement sequence.
