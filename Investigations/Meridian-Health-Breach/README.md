# Meridian Health Breach — Password Spray to Key Vault Secret Exfiltration (Phase 1)

**Type:** Cloud Identity & Azure Investigation (Phase 1 of 2)
**Platform:** Microsoft Sentinel (KQL)
**Log Sources:** SignInLogs, AuditLogs, KeyVaultLogs, AzureActivity, StorageBlobLogs, MiroAuditLogs, OfficeActivity
**Outcome:** Confirmed — password spray led to device-code phishing, OAuth token theft, mailbox persistence, and a pivot into Azure that ended with a SAML signing certificate pulled from Key Vault. Phase 2 (federation/SAML abuse and exfiltration) is a separate writeup.

## Scenario

Meridian Health, a healthcare organization running outpatient clinics, diagnostic centers, and a research division, had recently migrated to Azure and adopted Microsoft 365 and Miro under a SAML-federated SSO setup. On 2026-02-10 the SOC flagged failed authentication attempts against a user account followed by a successful login from an unfamiliar IP, then suspicious OAuth consent activity and unauthorized access across Azure resources, Key Vault, and connected apps. Objective: trace the attacker across Azure and connected applications, identify every compromised account, and document the techniques used.

## Scope

- Organization: Meridian Health (healthcare — clinics, diagnostics, research)
- Initial victim: `Taylor`
- Compromised service accounts: `svc-automation@meridianhealth.org`, `svc-federation@meridianhealth.org`
- Key Vault: `KV-MERIDIAN-PROD-9474`
- Secret extracted: `miro-saml-certificate`
- Environment: Entra ID, Microsoft 365, Miro (SaaS), federated SAML SSO

## Attack Chain

```
Password spray — Taylor (errors 50126 → 50076)
        |
Phishing email — typosquatted sender (rnicrosoft.com)
        |
Device code phishing — OAuth token obtained
        |
FOCI token reuse — 4 additional first-party apps accessed
        |
Directory enumeration
        |
Mailbox forwarding rule ("IT Updates" → t.martinez.backup@protonmail.com)
        |
Mailbox reconnaissance — 64 emails, 96 files accessed
        |
Pivot: svc-automation@meridianhealth.org compromised
        |
Automation Accounts enumerated — password exposed in job output
        |
Pivot: svc-federation@meridianhealth.org discovered
        |
Key Vault (KV-MERIDIAN-PROD-9474) accessed
        |
SAML signing certificate extracted (miro-saml-certificate)
        |
-> Phase 2: federation/SAML abuse & exfiltration
```

## Timeline

| Step | Event                                | Detail                                                      |
|------|----------------------------------------|---------------------------------------------------------------|
| 1    | Password spray — Taylor               | Error codes 50126, 50076 (chronological)                     |
| 2    | Phishing email delivered              | Sender: `rnicrosoft.com` (typosquat)                          |
| 3    | Device code phishing initiated        | Code lifetime: 15 minutes                                     |
| 4    | OAuth token abuse (FOCI)              | 4 additional apps accessed beyond the phishing app             |
| 5    | Victim changed password               | **2026-02-10 11:48 UTC**                                       |
| 6    | First directory enumeration           | CorrelationId `e60ef323-cc98-3fb1-a8da-fb7097909857`          |
| 7    | Malicious forwarding rule created     | "IT Updates" → t.martinez.backup@protonmail.com               |
| 8    | Mailbox reconnaissance                | 64 emails accessed, 96 files downloaded                        |
| 9    | First service account compromised     | `svc-automation@meridianhealth.org` from `91.132.139.195`      |
| 10   | Automation Accounts discovered        | `aa-meridian-prod`, `meridian-automation`                       |
| 11   | Password exposed in job output        | `D3pl0y#Pr0d!2026`                                              |
| 12   | Third service account discovered      | `svc-federation@meridianhealth.org`                             |
| 13   | Key Vault accessed                    | `KV-MERIDIAN-PROD-9474`                                          |
| 14   | SAML signing certificate extracted    | `miro-saml-certificate`                                          |

Note: source data references a fourth service account's password stored in a Key Vault secret, but that account isn't named in available telemetry — flagged for Phase 2.

## Key Concepts

**Device code phishing.** The OAuth 2.0 Device Authorization Grant (RFC 8628) exists for input-constrained devices — an app requests a device code and user code, the user visits a *legitimate* Microsoft URL and enters the user code, and the app polls until authentication completes. Attackers abuse this by generating the device code themselves and phishing the victim into entering the attacker's user code on the real Microsoft login page. Because the victim authenticates on a genuine Microsoft domain, this sails past most anti-phishing training and URL-based defenses — the attacker's polling client walks away with valid OAuth tokens, no fake login page required. The 15-minute code lifetime here is also why this style of phishing tends to use urgent, time-pressured pretexts.

**FOCI (Family of Client IDs).** A set of first-party Microsoft public client apps (Teams, OneDrive, Outlook Mobile, Azure CLI, and others) share a common client "family." A refresh token issued to one FOCI app can be redeemed for access tokens to any other FOCI-enabled app, without a new interactive sign-in. Once the attacker held a refresh token from the phished app, FOCI let them pivot into four more first-party apps without tripping additional auth prompts — one token theft became broad access across the Microsoft ecosystem.

**OAuth token abuse, generally.** Both techniques above exploit the same weakness: an OAuth token is a bearer credential — whoever holds it acts as the user until it's revoked or expires, independent of the account password. That's why the victim's password reset at 11:48 UTC didn't end the incident — the attacker was already operating on stolen tokens, and a password change alone doesn't invalidate access tokens already issued.

**MITRE ATT&CK mapping**

| Stage                          | Technique                                                   | ID         |
|----------------------------------|----------------------------------------------------------------|-------------|
| Password spray                 | Brute Force: Password Spraying                                | T1110.003  |
| Typosquat phishing email       | Phishing: Spearphishing Link                                   | T1566.002  |
| Device code phishing           | Phishing for Information / Steal Application Access Token      | T1598 / T1528 |
| OAuth token reuse (FOCI)       | Use Alternate Authentication Material: Application Access Token | T1550.001  |
| Directory enumeration          | Cloud Account Discovery                                         | T1087.004  |
| Mailbox forwarding rule        | Email Collection: Email Forwarding Rule                         | T1114.003  |
| Credential in job output       | Unsecured Credentials: Credentials In Files                     | T1552.001  |
| Service account authentication | Valid Accounts: Cloud Accounts                                  | T1078.004  |
| Key Vault secret extraction    | Credentials from Password Stores: Cloud Secrets Management Stores | T1555.006 |

## Investigation

**1. Initial access.** Password spray against `Taylor` (auth errors 50126 → 50076), followed by a phishing email from the typosquatted domain `rnicrosoft.com` that walked the victim through a device-code sign-in — handing the attacker valid OAuth tokens without ever presenting a fake login page.

![Initial access](screenshots/01-initial-access.png)

**2. OAuth token abuse (FOCI).** The stolen refresh token was redeemed for access to four additional first-party Microsoft apps beyond the one used in the phishing lure, via the shared FOCI client family — no further authentication prompts triggered.

![OAuth/FOCI token abuse](screenshots/02-oauth-foci-abuse.png)

**3. Mailbox persistence & reconnaissance.** A forwarding rule named "IT Updates" was created, routing mail to `t.martinez.backup@protonmail.com`. The attacker then accessed 64 emails and downloaded 96 files from the mailbox — reconnaissance that surfaced credentials in email attachments and Automation job output.

![Mailbox persistence and recon](screenshots/03-mailbox-persistence.png)

**4. Pivot to service accounts.** Harvested credentials authenticated as `svc-automation@meridianhealth.org` from `91.132.139.195`. Enumeration turned up Automation Accounts `aa-meridian-prod` and `meridian-automation`; a job output leaked the plaintext password `D3pl0y#Pr0d!2026`.

![Service account pivot](screenshots/04-service-account-pivot.png)

**5. Escalation to Key Vault.** A third service account, `svc-federation@meridianhealth.org`, was discovered with Key Vault access, leading into `KV-MERIDIAN-PROD-9474`.

![Key Vault access](screenshots/05-keyvault-access.png)

**6. Secret exfiltration.** The `miro-saml-certificate` secret — the SAML signing certificate — was extracted from Key Vault, setting up the federation/SAML abuse covered in Phase 2.

![Secret exfiltration](screenshots/06-secret-exfiltration.png)

## Root Cause & Impact

Device-code phishing bypassed standard anti-phishing controls by keeping the victim on a genuine Microsoft login page, and FOCI turned that single token theft into access across multiple first-party apps. From there, credentials left in plaintext (an Automation job output) and an unmonitored Key Vault let the attacker escalate from a phished user mailbox to a stolen SAML signing certificate — the exact material needed to forge federated identity assertions in Phase 2. A password reset mid-incident didn't help, since the attacker was operating on already-issued OAuth tokens.

## Recommendations

- Block or tightly restrict the device code auth flow via Conditional Access.
- Revoke all active OAuth access/refresh tokens for affected users and apps — a password reset alone doesn't do this.
- Rotate every exposed credential, including service account passwords and Key Vault secrets/certificates.
- Remove credentials from Automation job outputs; use Managed Identities instead.
- Alert on mailbox forwarding rule creation, mass mailbox/file access, and Key Vault secret-read events.
- Alert on the CorrelationId and attacker IPs below for any recurrence.

## Indicators

| Type                          | Value                                                            |
|---------------------------------|---------------------------------------------------------------|
| Victim account                | Taylor                                                            |
| Auth error codes              | 50126, 50076                                                       |
| Phishing sender domain        | rnicrosoft.com                                                      |
| Device code lifetime          | 15 minutes                                                          |
| Attacker IP (phishing/federation) | 193.36.119.162                                                 |
| Attacker IP (service account auth) | 91.132.139.195                                                |
| Malicious forwarding rule     | "IT Updates" → t.martinez.backup@protonmail.com                    |
| Compromised service accounts  | svc-automation@meridianhealth.org, svc-federation@meridianhealth.org |
| Exposed password              | D3pl0y#Pr0d!2026                                                    |
| Automation Accounts           | aa-meridian-prod, meridian-automation                                |
| Key Vault                     | KV-MERIDIAN-PROD-9474                                                |
| Extracted secret              | miro-saml-certificate                                                |
| Directory enum CorrelationId  | e60ef323-cc98-3fb1-a8da-fb7097909857                                 |
| Phase 2 IPs (reserved)        | 193.36.116.119 (exfiltration), 141.255.164.11 (OAuth credential injection) |

---

*Phase 2 of this investigation — federation/SAML abuse and exfiltration using the certificate extracted here — is a separate writeup.*
