# patches
Microsoft that patches can be used against them 
Microsoft’s Nov 11, 2025 Patch Tuesday fixed ~60+ CVEs including an actively exploited Windows Kernel elevation-of-privilege (EoP) zero-day (CVE-2025-62215) plus several critical remote code execution (RCE) bugs affecting Office, RRAS, graphics/DirectX components and others. Attackers who have an initial foothold (via phishing, exposed services, or RCE) can chain an RCE → EoP → persistence → mass-encrypt routine to push ransomware. Patch now, restrict exposed services, and hunt for post-exploit behaviours. 
Qualys
+2
BleepingComputer
+2

Which types of fixed bugs matter most for ransomware (plain talk)

Remote Code Execution (RCE) in Office, RRAS, SharePoint, image/GDI components: attacker runs code on your box remotely (e.g., via a malicious doc, network service exploit). That’s how they get in. 
Zero Day Initiative
+1

Kernel Elevation of Privilege (EoP) (e.g., CVE-2025-62215): attacker on a low-privileged account can escalate to SYSTEM/kernel level — necessary to stop AV/EDR and touch backups. 
SOC Prime

Graphics / driver / DirectX bugs: can allow local code to break out to higher privileges or crash/disable telemetry. Useful for stealth. 
Zero Day Initiative

Routing/remote services (RRAS) RCE: network-facing services are juicy — exploit these, you get remote code execution without tricking a user. 
Zero Day Initiative

How attackers typically chain these into ransomware (simple flow)

Initial access — phishing doc with RCE, or exposed RRAS/cloud service exploited. (Patch RCEs close this door.)

Privilege escalation — use an EoP bug (like the Nov zero-day) to become SYSTEM so they can disable defenses and access backups.

Lateral movement — steal creds, abuse RDP/SMB, or use PowerShell/WMIC to run on other machines.

Backup destruction — delete VSS/shadow copies or erase backups (needs privileges).

Encrypt & extort — mass file writes/encryption, drop ransom notes, plus exfiltrate sensitive data first (double extortion).
(That whole chain is why RCE + EoP = dangerous.) 
BleepingComputer
+1

What attackers will try to use against these patches (defensive mindset)

Exploit the RCEs in Office/Remote services to get a foothold — deliver a payload that runs a downloader.

Chain to the kernel EoP to disable EDR or gain access to backup stores and shadow copies.

Use drivers/DirectX bugs to hide or crash telemetry so detection is harder.

Exploit unpatched or end-of-life systems (old Windows versions or unsupported builds) that don’t get the fix. 
Tenable®
+1

Immediate, concrete defensive checklist (do these now)

Patch everything: deploy November 2025 updates for Windows, Office, server components, and drivers — fast. (If you can’t, isolate the vulnerable hosts.) 
Microsoft Support
+1

Block & harden network-facing services: block RRAS and other exposed services at the firewall if not required. Use VPN + MFA for remote access. 
Zero Day Initiative

Harden Office: disable macros by default, enable Protected View, block risky attachments.

Enforce Least Privilege: don’t let users run as admin; enable LAPS / JIT admin for ops.

Protect backups: make backups immutable / offline / air-gapped and test restores.

EDR & logging: ensure EDR is up to date, tamper-protected and logs are forwarded off-host (SIEM).

Detect the chain: add hunts/alerts for (a) RCE indicators (suspicious child processes from Office), (b) EoP signs (sudden token changes, LSASS dumps), (c) mass file writes and VSS deletion.

Segment: isolate admin workstations, backup servers, hypervisors — assume compromise and limit blast radius.

User MFA & phishing controls: phishing-resistant MFA (WebAuthn/FIDO) for admins, mail filtering, URL sandboxing.

Patch management: prioritize hosts with internet-facing services and all domain controllers.

Quick  examples of detections to add (non-exploit, for SIEM)

Alert if winword.exe/excel.exe spawns powershell.exe or cmd.exe with encoded commands.

Alert on a process performing >X file writes per second across user directories (mass file churn).

Alert on vssadmin delete shadows or wbadmin delete catalog or sudden shadow copy failures.

Alert on new service installs & scheduled tasks created by non-admin installers.
(These are behavioral — they don’t need exploit details.)

Sources / read further

Microsoft & Patch Tuesday coverage (Nov 11, 2025) — fixes for CVE-2025-62215 (kernel EoP) and several RCEs. 
Microsoft Support
+1

Reviews from Qualys, Tenable, ZDI and Malwarebytes summarizing the November 2025 fixes and why they matter.
