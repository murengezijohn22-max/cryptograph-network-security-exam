# Risk Assessment – ULK Polytechnic Institute

Scope: central student-records server, inter-campus file transfers, staff/guest networks (from the security review).

## a. Assets, vulnerabilities and consequences

| # | Asset | Vulnerability | Possible consequences |
|---|-------|---------------|-----------------------|
| R1 | Student records (database and files: names, grades, IDs) | Files transferred between campuses **unencrypted** | Interception (sniffing / man-in-the-middle) leaks personal data; silent modification of grades; breach of data-protection duties; reputational damage |
| R2 | Records server (hardware, OS, services) | **Guest network can reach the server** and **outdated software** | Exploitation of known CVEs, lateral movement from guest devices, ransomware, data theft, downtime; the repeated probes from an unfamiliar external address show the server is already being targeted |
| R3 | Staff accounts / credentials | **Weak passwords** | Brute-force or password-guessing gives an attacker legitimate access; records altered or exfiltrated with no obvious sign of intrusion |

## b. Ranking (Likelihood and Impact, 1 = low, 5 = high)

| Rank | Risk | L | I | Score | Reasoning |
|------|------|---|---|-------|-----------|
| 1 | R2 – guest reachability + outdated software on the server | 5 | 5 | **25** | Reconnaissance is *already observed*; guests are untrusted devices; public exploits exist for outdated software; a compromised server exposes every record and service |
| 2 | R3 – weak staff passwords | 4 | 5 | **20** | Very common attack (credential guessing/stuffing); valid credentials bypass most other controls, so impact is as high as full access |
| 3 | R1 – unencrypted inter-campus transfers | 3 | 4 | **12** | Requires an attacker positioned on the path (WAN/ISP or an internal tap) – less likely; impact is high for confidentiality and integrity but limited to data in transit |

## c. Recommended controls

| Risk | Control | How it reduces the risk |
|------|---------|-------------------------|
| R2 | **Network segmentation + host firewall** (deny guest VLAN to the server, allow only staff subnet to the required service) and a patch-management schedule | Removes guest attack path; shrinks exposed surface (implemented in `firewall/firewall_rules.sh`); patches close known CVEs |
| R3 | **Strong password policy plus multi-factor authentication** (minimum 12 characters, lockout after failed attempts, MFA for staff) | Makes guessing impractical and stolen passwords insufficient |
| R1 | **Encrypt files before/while transferring** (AES-256-GCM via `src/secure_records.py`, and SFTP/TLS for transport) with SHA-256 integrity checks | Interceptors see only ciphertext; tampering is detected |
