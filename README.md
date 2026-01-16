#  Task 1: Cybersecurity Basics & Attack Surface

This repository documents my learning and research for **Task 1**, covering foundational cybersecurity concepts including the **CIA Triad**, **Types of Attackers**, **Attack Surfaces**, **OWASP Top 10**, and **Data Flow Mapping**.  
It is designed to build a strong base for penetration testing, threat modeling, and interview preparation.

---

# Introduction to Cybersecurity
Cybersecurity is more than firewalls, passwords, or antivirus software — it is the discipline of safeguarding digital systems, networks, and data against unauthorized access, damage, or disruption. At its core, cybersecurity is about trust: trust that your bank will protect your money, trust that your WhatsApp messages remain private, trust that your online purchases won’t expose your card details.
### Why Cybersecurity Matters
• 	Digital dependency: Modern life runs on digital systems — from banking and healthcare to social media and cloud storage.

• 	Invisible risks: Unlike physical theft, cyberattacks are often invisible until damage is done.

• 	Global impact: A single breach can affect millions of users across countries (e.g., Aadhaar leaks, ransomware on hospitals).

Cybersecurity ensures that digital trust is not broken. Without it, people, businesses, and governments lose confidence in technology.

# *Cybersecurity is strongest when technology, processes, and people work together.*

## Cybersecurity as Layers of Defense
Think of cybersecurity like an onion — multiple layers protect the core data:
- Perimeter defense: Firewalls, VPNs, IDS/IPS.
- Application defense: Secure coding, OWASP Top 10 controls.
- Data defense: Encryption, backups, access control.
- User defense: Awareness training, MFA, phishing detection.
If one layer fails, others still protect the system. This is called defense in depth.

# **Overview**
Cybersecurity is the discipline of protecting digital systems, networks, and data from unauthorized access, damage, or disruption. It is not just about technology — it’s about trust. Every time you log into your bank, send a WhatsApp message, or buy something online, you rely on cybersecurity principles to keep your information safe.
This report explores:

• 	The CIA triad (Confidentiality, Integrity, Availability).

• 	Different types of attackers and their motivations.

• 	The concept of an attack surface.

• 	The OWASP Top 10 vulnerabilities.

• 	Mapping daily applications to attack surfaces.

• 	A data flow model showing where attacks can occur.

# CIA Triad — The Foundation of Security
The CIA Triad (Confidentiality, Integrity, Availability) is the core model of cybersecurity. Every security control, policy, and defense mechanism is designed to protect one or more of these three pillars. If any one fails, trust in the system collapses.
Think of it as a triangle: each side supports the others. Remove one side, and the triangle breaks.

## Why CIA Triad Matters
• 	It is the foundation of all cybersecurity policies.

• 	Every incident can be analyzed by asking:

• 	Was Confidentiality broken? (Data stolen)

• 	Was Integrity broken? (Data altered)

• 	Was Availability broken? (System down)

• 	Recruiters often ask about CIA triad because it shows you understand the core principles of security.

# Confidentiality
### Definition
Ensuring that information is accessible only to authorized users and protected from unauthorized disclosure.

### Technical Depth
• 	Encryption: AES, RSA, TLS/SSL.

• 	Access Control: Role-Based Access Control (RBAC), Identity & Access Management (IAM).

• 	Authentication: Passwords, biometrics, multi-factor authentication (MFA).

• 	Data Masking: Hiding sensitive fields (e.g., credit card numbers).
### Analogy
Like a locker with a key — only the person with the key can open it.
Real-World Examples

• 	WhatsApp uses end-to-end encryption so only sender and receiver can read messages.

• 	Banks encrypt passwords and use MFA to prevent unauthorized logins.
### Attacker Perspective
• 	Data Breaches: Hackers steal customer records.

• 	Insider Threats: Employees leak confidential data.

• 	Weak Encryption: Attackers crack outdated algorithms.
### Defense Strategies
• 	Strong encryption standards (AES-256).

• 	Least privilege access.

• 	Regular audits and monitoring.

# Integrity
Definition
Ensuring that data remains accurate, consistent, and unaltered unless changed by authorized users.
Technical Depth

• 	Hashing: SHA-256, MD5 (obsolete).

• 	Digital Signatures: Verify authenticity of data.

• 	Checksums: Detect accidental corruption.

• 	Database Constraints: Prevent unauthorized modifications.
### Analogy
Like a sealed medicine packet — if the seal is broken, you know it’s unsafe.

### Real-World Examples
• 	UPI transactions use digital signatures to prevent tampering.

• 	Software updates are signed to ensure they aren’t modified.
### Attacker Perspective

• 	SQL Injection: Altering exam results or bank balances.

• 	Malware: Modifying files or logs.

• 	Man-in-the-Middle (MITM): Changing data during transmission.
### Defense Strategies
• 	Input validation and sanitization.

• 	Integrity checks with hashing.

• 	Secure coding practices.

# Availability
Definition
Ensuring that systems and data are accessible when needed by authorized users.
Technical Depth

• 	Redundancy: Multiple servers or data centers.

• 	Load Balancing: Distributing traffic evenly.

• 	Failover Systems: Backup systems ready to take over.

• 	DDoS Protection: Firewalls, rate limiting, cloud scrubbing.
### Analogy
Like electricity supply — if it’s down, everything halts.
Real-World Examples

• 	Railway ticketing servers must stay online during peak booking.

• 	Cloud services like AWS use multiple data centers to ensure uptime.
### Attacker Perspective
• 	DDoS Attacks: Flooding servers with traffic.

• 	Ransomware: Locking systems until ransom is paid.

• 	Hardware Failures: Exploited by lack of backups.
### Defense Strategies
• 	Disaster recovery plans.

• 	Cloud-based DDoS mitigation.

• 	Regular backups and monitoring.

# Types of Attackers 
Cyber attackers (also called threat actors) are people or groups who try to break into systems. They differ in skills, motivations, and resources. Knowing them helps defenders predict attacks and design protections.

### 1. Script Kiddies
- Easy: Beginners using ready‑made hacking tools without deep knowledge.
- Deep: They download tools like DDoS scripts or SQL injection kits from the internet. They don’t create exploits but can still cause damage.
- Analogy: Like kids throwing stones at windows — they didn’t make the stones, but they can break glass.
- Example Attack: Defacing a website, running a small DDoS attack.
- Risk Level: Low–moderate, but disruptive.


### 2. Insiders
- Easy: Employees or contractors misusing their access.
- Deep: They already have legitimate credentials, so they bypass firewalls and perimeter defenses. Can be malicious (revenge, greed) or accidental (negligence).
- Analogy: Like a guard who opens the gate for thieves.
- Example Attack: Copying customer data, sabotaging systems, leaking trade secrets.
- Risk Level: High — insiders are trusted, so harder to detect.

### 3. Hacktivists
- Easy: Attackers motivated by ideology or protest.
- Deep: They target organizations to spread political, social, or environmental messages. Often use DDoS, leaks, or defacement.
- Analogy: Like street protesters, but online.
- Example Attack: Defacing government websites, leaking sensitive documents.
- Risk Level: Variable — depends on their resources and target.

### 4. Nation‑State / Advanced Persistent Threats (APT)
- Easy: Cyber armies backed by governments.
- Deep: Highly skilled, well‑funded groups. They use zero‑day exploits, custom malware, and social engineering. Their attacks are stealthy, long‑term, and persistent.
- Analogy: Like professional spies, but digital.
- Example Attack: Stealthy intrusion into defense systems, stealing trade secrets, disrupting power grids.
- Risk Level: Very high — patient, advanced, and persistent.

## Comparison Table

| Attacker Type       | Motivation              | Example Attack              | Risk Level   |
|---------------------|-------------------------|-----------------------------|--------------|
| Script Kiddies      | Fun, curiosity          | Website defacement, DDoS    | Low–Moderate |
| Insiders            | Revenge, greed          | Data theft, sabotage        | High         |
| Hacktivists         | Ideology, protest       | Defacing sites, leaking data| Variable     |
| Nation‑State / APT  | Espionage, warfare      | Stealthy long‑term intrusion| Very High    |



## Why This Matters
• 	Different attackers = different defenses.

• 	Script kiddies → basic hardening (patching, firewalls).

• 	Insiders → strict access control + monitoring.

• 	Hacktivists → resilience against leaks/defacement.

• 	Nation‑state/APTs → advanced detection, segmentation, and threat intelligence.


# Attack Surfaces 
Think of  Entry Points for Attackers
An attack surface is the total number of ways an attacker can try to enter or interact with a system. Think of it like all the doors and windows of a digital house — the more doors, the harder it is to guard.

## Why Attack Surfaces Matter
• 	The larger the attack surface, the more opportunities attackers have.

• 	Security teams aim to reduce and harden attack surfaces.

• 	Penetration testers map attack surfaces to plan their tests.

• 	Real‑world breaches often happen because attack surfaces weren’t minimized.

### 1. Web Applications
- Easy: Websites where users log in or enter data.
- Deep: Login forms, cookies, session tokens, input fields. Vulnerabilities include SQL injection, XSS, broken access control.
- Analogy: Like the front door of a shop — if the lock is weak, anyone can walk in.
- Real Example: A poorly coded login form can allow attackers to bypass authentication.

### 2. Mobile Applications
- Easy: Apps on your phone.
- Deep: Local storage, weak encryption, exposed APIs, insecure permissions.
- Analogy: Like carrying valuables in your pocket — if the pocket is torn, things fall out.
- Real Example: Banking apps storing PINs in plain text on the device.

### 3. APIs (Application Programming Interfaces)
- Easy: Hidden doors that apps use to talk to servers.
- Deep: Endpoints leaking too much data, poor authentication, rate‑limit bypass.
- Analogy: Like a secret back door — if not locked, intruders can sneak in.
- Real Example: An API that returns full customer records without proper authorization checks.

### 4. Networks
- Easy: The roads data travels on.
- Deep: Open ports, weak Wi‑Fi, misconfigured firewalls, unpatched routers.
- Analogy: Like highways — if toll booths are missing, anyone can drive through.
- Real Example: Attackers scanning open ports to find vulnerable services.

### 5. Cloud Infrastructure
- Easy: Data stored online in services like AWS, Azure, GCP.
- Deep: Public storage buckets, leaked API keys, weak IAM roles, misconfigured servers.
- Analogy: Like renting a warehouse — if you leave the door open, anyone can walk in.
- Real Example: Misconfigured Amazon S3 buckets leaking sensitive files

## Comparison Table

| Surface            | Examples                        | Common Risks                          |
|--------------------|---------------------------------|---------------------------------------|
| Web Apps           | Login forms, cookies            | SQL injection, XSS, broken auth       |
| Mobile Apps        | Local storage, APIs             | Weak encryption, insecure permissions |
| APIs               | Endpoints, tokens               | Data leaks, poor authentication       |
| Networks           | Ports, Wi‑Fi, firewalls         | MITM, open ports, misconfigurations   |
| Cloud Infrastructure | Buckets, IAM roles, servers   | Public leaks, weak access control     |


# OWASP Top 10
The OWASP Top 10 is a globally recognized list of the most critical web application security risks. It’s updated periodically to reflect real-world threats and serves as a foundation for secure coding, penetration testing, and interview preparation.


## OWASP Top 10 
1. Broken Access Control  
2. Cryptographic Failures  
3. Injection (SQL/NoSQL)  
4. Insecure Design  
5. Security Misconfiguration  
6. Vulnerable Components  
7. Identification & Authentication Failures  
8. Software & Data Integrity Failures  
9. Logging & Monitoring Failures  
10. Server‑Side Request Forgery (SSRF)  

---

##  A01: Broken Access Control
- **Definition:** Users gain access to resources they shouldn’t.  
- **Example:** A normal user accessing admin dashboards.  
- **Attacker View:** Exploit weak role checks, manipulate URLs.  
- **Defense:** Enforce least privilege, deny by default, test authorization paths.

---

##  A02: Cryptographic Failures
- **Definition:** Sensitive data exposed due to weak or missing encryption.  
- **Example:** Passwords stored in plain text.  
- **Attacker View:** Steal or crack weakly encrypted data.  
- **Defense:** Use strong algorithms (AES, TLS), hash + salt passwords, secure key storage.

---

##  A03: Injection
- **Definition:** Attacker injects malicious code into inputs.  
- **Example:** SQL injection altering exam results.  
- **Attacker View:** Exploit unsanitized inputs to control queries.  
- **Defense:** Parameterized queries, input validation, ORM frameworks.

---

##  A04: Insecure Design
- **Definition:** Flaws in system architecture from the start.  
- **Example:** Payment system without fraud detection.  
- **Attacker View:** Exploit weak workflows, bypass logic.  
- **Defense:** Threat modeling, secure design principles, security by design.

---

##  A05: Security Misconfiguration
- **Definition:** Default or weak settings left open.  
- **Example:** Default “admin/admin” login still active.  
- **Attacker View:** Scan for misconfigured servers.  
- **Defense:** Harden configurations, patch regularly, automate security checks.

---

##  A06: Vulnerable and Outdated Components
- **Definition:** Using libraries or frameworks with known flaws.  
- **Example:** Exploiting old Apache Struts vulnerability.  
- **Attacker View:** Search for apps using outdated versions.  
- **Defense:** Update dependencies, monitor CVEs, use dependency scanners.

---

##  A07: Identification & Authentication Failures
- **Definition:** Weak login and session management.  
- **Example:** Session hijacking via stolen cookies.  
- **Attacker View:** Steal credentials, brute force weak passwords.  
- **Defense:** Strong authentication, secure session handling, MFA.

---

##  A08: Software & Data Integrity Failures
- **Definition:** Data or code can be tampered with.  
- **Example:** Malicious code injected into software updates.  
- **Attacker View:** Supply chain attacks, tampering with builds.  
- **Defense:** Code signing, integrity checks, secure CI/CD pipelines.

---

##  A09: Security Logging & Monitoring Failures
- **Definition:** Attacks go unnoticed due to poor logging.  
- **Example:** Breach detected months later.  
- **Attacker View:** Exploit blind spots, stay undetected.  
- **Defense:** Centralized logging, SIEM tools, monitoring alerts.

---

##  A10: Server-Side Request Forgery (SSRF)
- **Definition:** Server tricked into fetching data it shouldn’t.  
- **Example:** Accessing cloud metadata via SSRF.  
- **Attacker View:** Exploit server trust, pivot into internal networks.  
- **Defense:** Validate URLs, restrict outbound requests, whitelist domains.



## Comparison Table

| Risk ID | Name                               | Easy View | Example Attack | Defense Strategy |
|---------|------------------------------------|-----------|----------------|------------------|
| A01     | Broken Access Control              | Unauthorized access | User accessing admin page | Least privilege, deny by default |
| A02     | Cryptographic Failures             | Weak/missing encryption | Plain-text passwords | Strong algorithms, secure key mgmt |
| A03     | Injection                          | Malicious input | SQL injection | Parameterized queries |
| A04     | Insecure Design                    | Bad architecture | Weak payment system | Threat modeling, secure design |
| A05     | Security Misconfiguration          | Default settings | Default admin login | Harden configs, patching |
| A06     | Vulnerable Components              | Old libraries | Exploiting CVEs | Update dependencies |
| A07     | Auth Failures                      | Weak login | Session hijacking | MFA, secure sessions |
| A08     | Integrity Failures                 | Tampered data/code | Malicious update | Code signing, CI/CD security |
| A09     | Logging Failures                   | No monitoring | Breach unnoticed | Centralized logging, SIEM |
| A10     | SSRF                               | Server tricked | Cloud metadata access | Validate URLs, restrict requests |


#  Mapping Daily Apps to Attack Surfaces

Attack surfaces aren’t just abstract — they exist in the apps we use daily.  
By mapping **Email, WhatsApp, and Banking Apps** to their attack surfaces, we can see how vulnerabilities appear in real life.

---

## 📧 Email
- **Attack Surfaces:**  
  - Login forms → weak passwords, brute force.  
  - Attachments → malware, ransomware.  
  - Links → phishing, spoofing.  
  - Servers → misconfiguration, open relays.  
- **Real Example:** Phishing emails trick users into entering credentials on fake sites.  
- **Analogy:** Like a mailbox — if you don’t lock it, anyone can drop in fake letters.  

---

## 💬 WhatsApp / Messaging Apps
- **Attack Surfaces:**  
  - SIM swap attacks → stealing phone number.  
  - Metadata leaks → who you talk to, when.  
  - Backup exposure → unencrypted cloud backups.  
  - Device vulnerabilities → malware stealing chats.  
- **Real Example:** Attackers hijack WhatsApp accounts via SIM swap.  
- **Analogy:** Like private conversations overheard if someone taps your phone line.  

---

## 🏦 Banking Apps
- **Attack Surfaces:**  
  - APIs → poor authentication, insecure endpoints.  
  - Mobile storage → PINs or tokens stored insecurely.  
  - Network → MITM attacks on public Wi‑Fi.  
  - Servers → DDoS attacks during peak hours.  
- **Real Example:** Attackers exploit insecure APIs to transfer funds.  
- **Analogy:** Like a vault with multiple doors — if one door is weak, the money is at risk.  

---

##  Comparison Table

| Daily App   | Attack Surfaces                        | Common Risks                        |
|-------------|----------------------------------------|-------------------------------------|
| Email       | Login, attachments, links, servers     | Phishing, malware, spoofing         |
| WhatsApp    | SIM swap, metadata, backups, device    | Account hijack, data leaks          |
| Banking App | APIs, mobile storage, network, servers | Fraud, MITM, DDoS, insecure storage |

---

##  Why This Matters
- Shows how **attack surfaces exist in everyday life**.  
- Helps connect **theory to practice**.  
- Useful for **interviews**: recruiters love real‑world examples.  
- Builds awareness: even common apps can be exploited if not secured.

#  Data Flow & Attack Points

Every application has a **data flow** — information moves from the **user** to the **application**, then to the **server**, and finally to the **database**.  
At each stage, attackers can exploit vulnerabilities. Mapping these points helps penetration testers and defenders understand where risks exist.

---

##  Data Flow Model
User → Application → Server → Database

##  Attack Points

### 1. User Device
- **Risks:** Malware, credential theft, phishing.  
- **Example:** Keyloggers stealing login details.  
- **Defense:** Antivirus, MFA, user awareness.

---

### 2. Transport Layer (Network)
- **Risks:** Man‑in‑the‑Middle (MITM), TLS stripping, packet sniffing.  
- **Example:** Attacker intercepts traffic on public Wi‑Fi.  
- **Defense:** TLS/SSL encryption, VPNs, secure protocols.

---

### 3. Application Layer
- **Risks:** Injection attacks (SQL, XSS), broken authentication, insecure APIs.  
- **Example:** SQL injection through login forms.  
- **Defense:** Input validation, secure coding, OWASP Top 10 controls.

---

### 4. Server Layer
- **Risks:** Misconfigurations, privilege escalation, outdated software.  
- **Example:** Exposed admin panels with default credentials.  
- **Defense:** Patch management, hardened configurations, monitoring.

---

### 5. Database Layer
- **Risks:** SQL injection, backup leaks, weak access control.  
- **Example:** Attacker modifies exam results in the database.  
- **Defense:** Parameterized queries, encrypted storage, strict access policies.

---

### 6. Cloud / IAM Layer
- **Risks:** Public buckets, leaked API keys, weak IAM roles.  
- **Example:** Sensitive files exposed in misconfigured S3 buckets.  
- **Defense:** Strong IAM policies, access reviews, cloud security monitoring.

---

## Comparison Table

| Layer        | Risks                                | Example Attack                  | Defense Strategy                  |
|--------------|--------------------------------------|---------------------------------|-----------------------------------|
| User Device  | Malware, phishing, credential theft  | Keylogger stealing passwords    | Antivirus, MFA, awareness         |
| Transport    | MITM, TLS stripping, sniffing        | Intercepting traffic on Wi‑Fi   | TLS/SSL, VPN, secure protocols    |
| Application  | Injection, broken auth, insecure APIs| SQL injection via login form    | Input validation, secure coding   |
| Server       | Misconfig, privilege escalation      | Exposed admin panel             | Patch mgmt, hardened configs      |
| Database     | SQL injection, backup leaks          | Altering exam results           | Parameterized queries, encryption |
| Cloud/IAM    | Public buckets, leaked keys          | Misconfigured S3 bucket         | Strong IAM, monitoring            |

##  Why This Matters
- Shows how **attacks can happen at every step of data flow**.  
- Helps penetration testers plan **where to probe**.  
- Builds awareness that **security is layered** — protecting only one stage is not enough.


#  Interview Prep Questions (Deep & Easy)

This section prepares for common cybersecurity interview questions with **layered answers**:  
- **Definition** (short, clear)  
- **Deep Explanation** (technical detail)  
- **Example** (real-world scenario)  
- **Analogy** (easy to visualize)  

---

## 1. What is the CIA Triad?
- **Definition:** The three pillars of cybersecurity — Confidentiality, Integrity, Availability.  
- **Deep Explanation:**  
  - **Confidentiality:** Prevents unauthorized access to data (encryption, access control, MFA).  
  - **Integrity:** Ensures data accuracy and trustworthiness (hashing, digital signatures, checksums).  
  - **Availability:** Ensures systems are accessible when needed (redundancy, load balancing, DDoS protection).  
- **Example:** Online banking must encrypt transactions (Confidentiality), prevent tampering (Integrity), and stay online during peak hours (Availability).  
- **Analogy:** Like a bank vault — locked (Confidentiality), contents untouched (Integrity), and open during business hours (Availability).

---

## 2. What is an Attack Surface?
- **Definition:** The total number of possible entry points an attacker can exploit in a system.  
- **Deep Explanation:** Includes web apps, mobile apps, APIs, networks, and cloud infrastructure. Larger attack surfaces = more opportunities for attackers.  
- **Example:** A misconfigured AWS S3 bucket exposing sensitive files expands the attack surface.  
- **Analogy:** Like all the doors and windows of a house — the more doors, the harder it is to guard.

---

## 3. Difference Between Vulnerability, Threat, and Risk
- **Vulnerability:** A weakness in a system.  
  - *Example:* Unpatched software with known CVEs.  
- **Threat:** A potential cause of harm.  
  - *Example:* Hacker exploiting a buffer overflow.  
- **Risk:** The likelihood and impact of a threat exploiting a vulnerability.  
  - *Example:* High risk if critical servers run outdated software.  
- **Analogy:**  
  - Vulnerability = a hole in the wall.  
  - Threat = a thief outside.  
  - Risk = chance the thief enters through the hole.

---

## 4. What Are Common Cyber Attackers?
- **Script Kiddies:** Beginners using pre‑made tools (low skill, disruptive
- **Insiders:** Employees misusing legitimate access (high risk, bypass defenses).  
- **Hacktivists:** Ideology‑driven attackers (political/social motives).  
- **Nation‑State/APT:** Highly skilled, government‑backed groups (espionage, cyber warfare).  
- **Deep Note:** Each attacker type requires different defenses — insiders need monitoring, APTs need advanced detection.  
- **Analogy:**  
  - Script Kiddies = pranksters.  
  - Insiders = traitors.  
  - Hacktivists = protesters.  
  - Nation‑State/APT = spies.

---

## 5. Why is OWASP Top 10 Important?
- **Definition:** A globally recognized list of the most critical web application security risks.  
- **Deep Explanation:**  
  - Acts as a **checklist** for developers and testers.  
  - Helps organizations prioritize security controls.  
  - Used in interviews, audits, and compliance frameworks.  
- **Examples of Risks:** Broken Access Control, Injection, Security Misconfiguration, SSRF.  
- **Analogy:** Like a “Top 10 most wanted criminals” list — knowing them helps you defend better.  
- **Key Point:** Mastering OWASP Top 10 shows you understand **real‑world web app threats**.

---

# Notes Table

| Question | Deep Answer Summary |
|----------|----------------------|
| CIA Triad | Confidentiality (encryption), Integrity (hashing), Availability (redundancy) |
| Attack Surface | All entry points attackers can exploit (apps, APIs, networks, cloud) |
| Vuln/Threat/Risk | Weakness / Potential harm / Likelihood + impact |
| Types of Attackers | Script Kiddies, Insiders, Hacktivists, Nation‑State/APT |
| OWASP Top 10 | Global checklist of critical web app risks |

##  Final Outcome
- Built a strong foundation in cybersecurity principles.  
- Mapped real-world apps to attack surfaces.  
- Understood OWASP Top 10 vulnerabilities.  
- Prepared for interviews with deep, structured answers.



