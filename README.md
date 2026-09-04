# SOC Analyst Portfolio

Detection engineering case studies and incident investigations built while working toward **SC-200** and **BTL1**, using Microsoft Sentinel, Defender XDR, and Splunk.

Every investigation here follows the same shape a real incident report would: attack chain → timeline → query-by-query evidence → root cause → recommendations. Nothing is a walkthrough of someone else's writeup — each one is my own KQL, run against my own data.

## How to read the status labels

- ✅ **Completed Investigation** — full end-to-end analysis: timeline reconstructed, every step backed by a query and evidence, root cause and recommendations included.
- 🛠️ **Detection Design (Not Yet Validated)** — the detection logic is built and reasoned through, but not yet tested against live telemetry. I label it this way rather than blur the line.

## Investigations

| Category | Project | Status |
|---|---|---|
| Identity & Access — Device-Code Phishing, Guest Abuse, Privilege Escalation | [**Entra ID Guest Privilege Escalation via Dynamic Group Abuse**](Investigations/Entra-ID-Dynamic-Group-PrivEsc/README.md) — phishing → device-code auth compromise → attacker shapes a guest account's `Country`/`Department` attributes until Entra's dynamic-group engine adds it to a privileged group automatically, 58 seconds later | ✅ Completed |
| Reconnaissance, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Lateral Movement, C2 | [**FalconEye — End-to-End Windows Intrusion Investigation**](Investigations/) — full multi-stage Windows intrusion, chained from initial access through to command-and-control | ✅ Completed |
| Discovery | [**Credential-Based RDP Access → Domain Reconnaissance**](Discovery/Credential-Based-RDP-to-Domain-Recon/) — detection logic for domain enumeration following a credentialed RDP session | 🛠️ Detection Design |
| Supply Chain Compromise, Persistence, Privilege Escalation, Credential Access, Lateral Movement, Impact | [Poisoned PyTorch Dependency — Supply Chain Compromise to Domain-Wide LYNX Ransomware](Investigations/Poisoned-PyTorch-LYNX-Ransomware/README.md) | Completed Investigation |
|Reconnaissance, Password Spray, Phishing, Device Code Phishing, Token Abuse, Mailbox Reconnaissance, Persistence, Credential Access, Lateral Movement, Azure Resource Enumeration, Key Vault Access, Secret Exfiltration |[Meridian Health Breach — Password Spray to Key Vault Secret Exfiltration (Phase 1)]([Meridian Health Breach — Device Code Phishing to Key Vault Secret Exfiltration/README.md) 

Device Code Phishing

Token Abuse / FOCI Reuse

Mailbox Reconnaissance

Persistence via Mail Rules

Credential Harvesting

Lateral Movement to Service Accounts

Azure Resource Enumeration

Key Vault Access

Secret Exfiltration
## Tools & Techniques

`Microsoft Sentinel` `KQL` `Microsoft Defender XDR` `Splunk` `MITRE ATT&CK` `UnifiedAuditLogs / Entra ID audit analysis` `Azure AD dynamic groups` `Windows intrusion analysis`

## Certifications in progress

- SC-200 — Microsoft Security Operations Analyst
- BTL1 — Blue Team Level 1

## About me

Aspiring SOC/L1 analyst based in Attock, Pakistan. I run a home  lab (Sentinel, Defender XDR, Azure Arc) to generate and investigate my own telemetry rather than relying only on pre-built training scenarios — [see it in this repo](Investigations/Entra-ID-Dynamic-Group-PrivEsc/README.md) for an example of that end to end.

📫 Open to entry-level SOC/L1 opportunities — [LinkedIn](#)
