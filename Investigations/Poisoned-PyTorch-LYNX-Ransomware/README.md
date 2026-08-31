# Poisoned PyTorch Dependency — Supply Chain Compromise to Domain-Wide LYNX Ransomware

**Type:** Full Intrusion Investigation (Supply Chain Compromise → Ransomware)
**Environment:** Windows domain — PC01, DC01, FILE-SERVER-01, BACKUP-SERVER-0
**Log Sources:** Sysmon, Windows Security Event Log, process/PowerShell telemetry
**Outcome:** Confirmed — a tampered third-party Python dependency led to silent code execution, persistence, a failed privilege-escalation attempt, credential theft, domain compromise, and LYNX ransomware deployed across three hosts.

## Scenario

On 2 February 2026 (UTC), a developer at UNUCORB ran a model-training script from VS Code on PC01. A trusted third-party Python dependency in the project had been tampered with, triggering silent code execution and giving the attacker a foothold on the workstation. Objective: reconstruct the intrusion timeline, determine initial access, track lateral movement across the domain, and identify pre-encryption behavior through ransomware impact.

## Scope

- Hosts: PC01 (dev workstation), DC01 (domain controller), FILE-SERVER-01, BACKUP-SERVER-0
- Initial account: `UNUCORB\michelvic`
- Compromised path: `domain.admin` (recovered from Unattend.xml)
- Rogue account created: `welsam` (display name: welsam maslew)
- Ransomware: LYNX

## Attack Chain

```
Tampered Python dependency executed via train.py (PC01)
        |
PowerShell download cradle
        |
DLL persistence via Registry Run key (updlate.dll)
        |
Failed WSL privilege-escalation attempt
        |
Unattend.xml → cleartext domain.admin credentials
        |
RDP lateral movement → DC01
        |
Masquerading binary (systern.exe) + rogue Domain Admin account (welsam)
        |
RDP expansion → FILE-SERVER-01, second-stage payload
        |
Volume Shadow Copies deleted (vssadmin)
        |
LYNX ransomware deployed — DC01, FILE-SERVER-01, BACKUP-SERVER-0
```

## Timeline

| Time (UTC)        | Event                              | Notes                                        |
|--------------------|--------------------------------------|-----------------------------------------------|
| 01:17:00          | `train.py` executed                 | PC01, via tampered dependency chain          |
| 01:48–01:54       | Multiple PowerShell executions      | `-NoProfile -EncodedCommand -nop -exec bypass` |
| TBD*               | `updlate.dll` dropped, Run key set  | Persistence via `rundll32.exe`               |
| 01:54:53–01:58:58 | WSL privilege-escalation attempts   | `wsl -u root` — failed                       |
| TBD*               | Unattend.xml discovered             | Cleartext `domain.admin` credentials         |
| 03:01:09          | RDP: PC01 → DC01                    | Logon Type 10, using `domain.admin`          |
| TBD*               | `systern.exe` dropped/executed      | DC01, masquerading as `system.exe`           |
| 03:15:18          | Rogue account `welsam` created      | EventCode 4720                               |
| 03:15:31          | `welsam` → Domain Admins            | EventCode 4728                               |
| 03:15:51          | `welsam` → RDP Users                |                                                |
| 04:17:07          | RDP: PC01 → FILE-SERVER-01          | Logon Type 10                                |
| 04:37:54          | Second-stage download               | `http://54.93.78.216/b`                      |
| TBD*               | Shadow copies deleted               | `vssadmin.exe`, pre-ransomware prep          |
| TBD*               | LYNX ransomware deployed            | DC01, FILE-SERVER-01, BACKUP-SERVER-0        |

*No exact timestamp recovered from available telemetry — placed by causal order, not assumed.

## Investigation

**1. Initial execution (PC01).** `train.py` run under the project's Python 3.12 interpreter. The Jedi language-server component (`jedilsp 3.12.9`) appears in the execution chain — legitimate tooling, but the specific instance in this chain was the tampered link that triggered code execution.

![Initial execution](screenshots/01-initial-execution.png)

**2. PowerShell download cradle.** A dozen PowerShell executions between 01:48 and 01:54, flagged by `-NoProfile`, `-EncodedCommand`, `-nop`, `-exec bypass` — the attacker's downloader/loader stage.

![PowerShell cradle](screenshots/02-powershell-cradle.png)

**3. Payload and persistence.** `updlate.dll` dropped to `C:\Users\michelvic\AppData\Roaming\`. Persistence set via `HKU\...\Run\Updater` → `rundll32.exe "...\updlate.dll",StartW`. The Registry Run key is the actual persistence mechanism; the DLL alone isn't.

![DLL + registry persistence](screenshots/03-persistence-dll-registry.png)

**4. Failed privilege escalation — WSL.** Attacker checked for `bash.exe`/`wsl.exe`, ran `wsl whoami`, then attempted `wsl -u root`. Escalation failed.

![WSL escalation attempt](screenshots/04-wsl-privesc-attempt.png)

**5. Credential access.** Filesystem reconnaissance turned up `Unattend.xml` with cleartext `domain.admin` credentials — the pivot from local compromise to domain-level access.

![Unattend.xml discovery](screenshots/05-credential-access-unattend.png)

**6. Lateral movement to DC01.** RDP session at 03:01:09 using `domain.admin`, EventCode 4624, Logon Type 10 (RemoteInteractive).

![RDP to DC01](screenshots/06-rdp-lateral-movement-dc01.png)

**7. Masquerading binary.** `systern.exe` staged on DC01 via `Explorer.EXE` (consistent with drag-and-drop over the RDP session), then executed — named to resemble `system.exe`.

![Masquerading binary](screenshots/07-masquerading-binary-systern.png)

**8. Domain Admin backdoor.** Account `welsam` created (4720), added to Domain Admins (4728) 13 seconds later, then to RDP Users 20 seconds after that. Under a minute from account creation to privileged, remotely-accessible backdoor.

![Rogue admin account](screenshots/08-rogue-admin-account.png)

**9. Expansion to file/backup infrastructure.** RDP to FILE-SERVER-01 at 04:17:07, followed by a second-stage PowerShell download from the same C2 (`54.93.78.216`), path `/b`.

![File server expansion](screenshots/09-file-server-expansion.png)

**10. Recovery destruction.** `vssadmin.exe delete shadows /all /quiet` and `/for=C: /quiet`, followed by `vssadmin list shadows` — classic pre-ransomware shadow-copy wipe.

![Shadow copy deletion](screenshots/10-vssadmin-shadow-deletion.png)

**11. Ransomware deployment.** `system recovery.exe` executed from `C:\Users\domain.admin\Documents\` across DC01, FILE-SERVER-01, and BACKUP-SERVER-0. Hash and behavioral artifacts attribute the binary to **LYNX ransomware**.

![Ransomware deployment](screenshots/11-ransomware-deployment.png)

## Root Cause & Impact

A tampered third-party Python dependency in an AI/ML project directory achieved silent code execution during a routine script run. From there, a Windows deployment artifact (Unattend.xml) with exposed cleartext credentials turned a single-host compromise into full domain compromise within roughly two hours, ending in a Domain Admin backdoor, destroyed recovery points, and ransomware across three hosts.

## Recommendations

- Verify third-party Python dependencies (hash/signature pinning) before execution in ML dev environments.
- Remove or restrict access to Unattend.xml and other deployment artifacts that may contain cleartext credentials post-provisioning.
- Alert on rapid account-creation → Domain Admins → RDP Users sequences.
- Alert on `vssadmin` shadow-copy deletion as a near-certain ransomware precursor.
- Monitor/restrict WSL usage and flag PowerShell invocations using `-EncodedCommand`/`-nop`/`-exec bypass`.

## Indicators

| Type                  | Value                                                                 |
|------------------------|--------------------------------------------------------------------|
| Compromised user       | UNUCORB\michelvic                                                    |
| Persistence DLL        | `updlate.dll` — SHA-256: `0829B7E5ABE2BAA6D7D001D4B69221D273D377C5E359E7A9C44F4D7A8EB214A0` |
| Persistence key        | `HKU\...\Run\Updater` → `rundll32.exe updlate.dll,StartW`            |
| C2                      | `54.93.78.216` (second-stage URI: `/b`)                              |
| Recovered credentials  | `domain.admin` (via Unattend.xml)                                    |
| Masquerading binary     | `systern.exe` (mimics `system.exe`)                                  |
| Rogue account           | `welsam` (welsam maslew) — Domain Admins, RDP Users                  |
| Ransomware binary       | `system recovery.exe`                                                 |
| Ransomware hash         | SHA-256: `EAA0E773EB593B0046452F420B6DB8A47178C09E6DB0FA68F6A2D42C3F48E3BC` |
| Ransomware family       | LYNX                                                                   |
