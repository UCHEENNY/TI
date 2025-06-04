# 🛡️ Passive Threat Intelligence Report – Hapuna Financial Ltd

**Report Date:** May 26, 2025  
**Target Organization:** Hapuna Financial Ltd  
**Analyst:** UCHE ABIODUN ENIOLA  
**Tool Used:** `theHarvester`  
 

---

## 📌 Executive Summary

This report presents the findings of a passive reconnaissance assessment of Hapuna Financial Ltd, a fintech institution offering savings and loan services. The assessment was designed to identify publicly available information that could potentially expose the organization to cybersecurity threats. Using tools like `theHarvester`, public OSINT sources were queried to discover exposed data. No active scanning was performed.

---

## 🛠️In the course of this project, several open-source intelligence (OSINT) platforms and threat intelligence communities were leveraged to assess the level of public exposure of Hapuna Financial Ltd. These sources provided passive insights into the organization’s infrastructure, email footprint, and external reputation.

### The following are the Open-Source Tools used:
- `theHarvester`
- `Shodan.io`- I used this to scan publicly available internet-connected systems associated with Hapuna Fin.Ltd for exposed services and misconfigurations
- `Hunter.io`-This was used to identify Hapuna valid and exposed corporate email addresses across public records and data breaches.
- `crt.sh`- I used this to search for Hapuna SSL/TLS certificates both active and expired, which revealled additional infrastructure.
- `Spyse / SecurityTrails`-This provided me historical DNS, port scanning data, tech stack information, and IP-to-domain mapping to identify potential forgotten or vulnerable assets
- `GreyNoise`- This helped me to find out if any of Hapuna Fin. Ltd IP address is part of known scanning or botnet activity
- `WHOIS`-It helped to provide information about domain name registrations of Hapuna 
- `URL Redirect Checker`- It helped me to tracks and analyzes the full redirect path of some of the URL found 

### Below are some of the Threat Intelligence Platforms I used in the course of this project:
- LinkedIn
- VirusTotal
- Twitter
- AlienVault OTX
- AbuseIPDB
- FS-ISAC, FIRST, CTA, AfricaCERT, ngCERT

## 🔍I did some Security Risk Assessment and I category them under Threat, Potential Risk, vulnerabilies also how to mitigate my findings: 

| **Asset Type** | **Examples** | **Risk** | **Mitigation** |
|----------------|--------------|----------|----------------|
| **Emails** | `info@hapuna.org`, `careers@hapuna.org`, etc. | Phishing, spoofing, credential stuffing | Use SPF, DKIM, DMARC; train staff |
| **URLs** | `https://career.hapuna-nigeria.org` | Brute-force, data leaks | Enforce HTTPS, secure login |
| **IPs** | `102.135.200.67`, `18.211.102.144`, etc. | DDoS, exposure via Shodan | Use firewalls, Cloudflare, patching |
| **Hosts** | 59 identified | Enumeration, CVE exploitation | Harden services, scan regularly |
| **ASN** | AS13335 (Cloudflare), AS14618 (AWS) | Infrastructure mapping | Mask ASN info, use dynamic hosting |

## ⚠️ Threat Classifications

| **Threat Type** | **Risk** |
|-----------------|----------|
| Targeted Phishing | Employee emails + LinkedIn data enable social engineering |
| Infrastructure Recon | IPs, hosts, and SSL certs expose internal layout |
| Brand Damage | Email spoofing or impersonation can reduce trust |
| Credential Reuse | Public email leaks may allow reuse-based attacks |


---

## Participation in the following threat intelligence communities will significantly enhance Hapuna's security posture:

FS-ISAC (Financial Services Information Sharing and Analysis Center) – Provides timely, relevant cyber threat intelligence tailored for the financial sector.

FIRST (Forum of Incident Response and Security Teams) – Connects global incident response teams to foster collaboration and rapid response to cyber threats.

MISP Project (Malware Information Sharing Platform & Threat Sharing) – Enables structured threat data sharing and collaborative analysis.

Cyber Threat Alliance (CTA) – Facilitates real-time sharing of threat intelligence among trusted cybersecurity organizations.

AfricaCERT / ngCERT (Nigeria Computer Emergency Response Team) – Regional and national CERTs that provide alerts, guidance, and coordination on cyber incidents in Africa and Nigeria.

## 👥 Key Threat Actors (Relevant to Fintech)

### APT38 (North Korea) – **Primary Threat**
- **Tactics:** SWIFT exploitation, banking theft, persistence
- **Techniques:** T1036 (Masquerading), T1041 (C2 Exfil), T1059 (Script Execution)

### Others:
- **Lazarus Group** – Destructive malware, ransomware  
- **FIN7 / Carbanak** – Email malware, data theft  
- **TA505** – Ransomware and phishing  
- **EvilCorp** – Dridex malware, RaaS  
- **Silence Group** – ATM fraud, email compromise

---

## 🧠 Historical Campaigns by DPRK Actors

- **Bangladesh Bank Heist (APT38)** – $81M stolen via SWIFT fraud  
- **Sony Hack (Lazarus)** – Data destruction + leaks  
- **WannaCry (Lazarus)** – Global ransomware  
- **Bank of Chile (APT38)** – $10M financial breach  
- **APT37 Mobile Espionage** – Android malware for surveillance

---

## 🧩 APT38 – MITRE ATT&CK Mapping

| **ID** | **Technique** | **Category** | **Purpose** |
|--------|----------------|--------------|-------------|
| T1036 | Masquerading | Defense Evasion | Fake legitimate names |
| T1041 | Exfil over C2 | Exfiltration | Hide data exfil |
| T1140 | Decode Files | Defense Evasion | Bypass detection |
| T1059 | Script Execution | Execution | Malicious commands |
| T1071 | Application Protocol | C2 | Use HTTPS/DNS |
| T1566.001 | Spearphishing Attachment | Initial Access | Email-based delivery |
| T1003 | Credential Dumping | Credential Access | Extract stored passwords |
| T1027 | Obfuscation | Defense Evasion | Encode payloads |

---

## 🔐 Security Recommendations

- Limit public exposure of employee emails  
- Regularly audit subdomains and infrastructure  
- Implement WAFs, VPN access, and penetration testing  
- Use multi-factor authentication (MFA) across services  
- Subscribe to intel feeds for monitoring leaks  

---

## 📄 Full Report

📥 [Download: Final Threat Intelligence Report (DOCX)](./final%20on%20TI%20REPORT.docx)

---

## 📘 Sample theHarvester Command

```bash
theHarvester -d hapuna-nigeria.org -b all -l 200 -f hapuna_report.html
