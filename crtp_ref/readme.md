# Execution policy bypass

powershell - ExecutionPolicy bypass
powershell -c <cmd>
powershell -encodedcommand $env:PSExecutionPolicyPreference="bypass"

Import-Module 
Get-Command -Module 

![](20220801163041.png) 

# kerberoasting

In such an attack, an adversary masquerading as an account user with a service principal name (SPN) requests a ticket, which contains an encrypted password, or Kerberos. (An SPN is an attribute that ties a service to a user account within the AD). The adversary then works offline to crack the password hash, often using brute force techniques.


START FREE TRIAL
PRODUCTS
SERVICES
WHY CROWDSTRIKE?
PARTNERS
COMPANY
RESOURCES
CROWDSTRIKE BLOG
CYBERSECURITY 101
CONTACT US
REQUEST INFO
EXPERIENCED A BREACH?
LANGUAGES
MAIN MENU
ABOUT CROWDSTRIKE
Executive Team
Board of Directors
Investors
Corporate Brochure
News
CrowdStrike & F1 Racing
Public Policy
Code of Ethics/Compliance
Falcon Fund
Suppliers
Environmental, Social & Governance
CAREERS
Sales & Marketing
Engineering & Technology
Professional Services
HR, Finance, & Legal
Intel & R&D
Internships
View Open Positions
EVENTS
Conferences
Workshop Wednesdays
Fal.Con 2022
MAIN MENU
PARTNERS PROGRAM
Store Partners
Solution Providers
Technology Partners
Service Providers
Cloud Providers
Embedded OEM
CROWDSTRIKE PARTNERS
Red Hat
EY Alliance
Verizon Alliance
Amazon Web Services (AWS)
Managed Service Providers (MSP/MSSP)
Google Cloud Platform
Deloitte Alliance
LEARN MORE
Become a Partner
Partners Login
Become a CrowdStrike Falcon
MAIN MENU
PRODUCT BUNDLES
Falcon Pro: Replace Your AV
Falcon Enterprise: Breach Prevention
Falcon Elite: Advanced Breach Prevention
Falcon Complete: Managed Detection & Response
ENDPOINT SECURITY SOLUTIONS
Falcon Prevent: NGAV
Falcon Insight: EDR
Falcon Device Control
Falcon Firewall Management
Falcon XDR
CLOUD SECURITY SOLUTIONS
Falcon CWP: AWS, Azure, GCP
Falcon Horizon: CSPM
Container Security
Falcon CWP Complete
IDENTITY PROTECTION SOLUTIONS
Falcon Identity Threat Detection
Falcon Identity Threat Protection
THREAT INTELLIGENCE SOLUTIONS
Falcon X: Automated Intelligence
Falcon X Premium: Cyber Threat Intelligence
Falcon X Elite: Assigned Intel Analyst
Falcon X Recon: Digital Risk Monitoring
SECURITY & IT OPERATIONS SOLUTIONS
Falcon Discover: Security Hygiene
Falcon Spotlight: Vulnerability Management
Falcon Forensics: Forensic Cybersecurity
Falcon FileVantage: File Integrity Monitoring
ABOUT THE PLATFORM
Falcon Platform Architecture
CrowdStrike Threat Graph
Falcon Fusion
Visit the CrowdStrike Store
Falcon FAQs
CrowdStrike Zero Trust
CrowdStrike University
OBSERVABILITY & LOG MANAGEMENT
Humio
MAIN MENU
RESOURCES
Reports
Tech Center
Blog
Webinars
Cybersecurity 101
All Resources
Free Trial Guide
RANSOMWARE
Ransomware Solutions
How to Prevent Ransomware
How Ransomware Actors are Evolving
Ransomware-as-a-Service Explained
EXTENDED DETECTION & RESPONSE
Falcon XDR
CrowdXDR Alliance
XDR 101
ENDPOINT PROTECTION
What is Endpoint Security?
Endpoint Protection Buyer's Guide
Gartner MQ for Endpoint Protection Platforms
Legacy Endpoint Protection vs. CrowdStrike
ZERO TRUST
Zero Trust
What is Zero Trust
Identity Security 101
CLOUD SECURITY
Cloud Security Reimagined
Cloud Security 101
CrowdStrike Security Cloud
Report: The Maturation of Cloud-Native Security
MAIN MENU
PREPARE
Tabletop Exercise
Red Team / Blue Team Exercise
Adversary Emulation Exercise
Penetration Testing Exercise
RESPOND
Incident Response
Compromise Assessment
Endpoint Recovery
Network Security Monitoring
FORTIFY
Maturity Assessment
Technical Risk Assessment
SOC Assessment
Active Directory Assessment
MANAGED SERVICES
Managed Detection & Response
Managed Threat Hunting
Threat Hunting with Analyst Support
OverWatch Cloud Threat Hunting
ADDITIONAL SERVICES
Cloud Security
Identity Protection
MAIN MENU
WHY CROWDSTRIKE?
Industry Recognition
Our Customers
Compliance & Certifications
COMPARE CROWDSTRIKE
CrowdStrike vs. Carbon Black
CrowdStrike vs. Cylance
CrowdStrike vs. McAfee
CrowdStrike vs. SentinelOne
CrowdStrike vs. Symantec
SOLUTIONS
Election Security
Finance
Healthcare
Public Sector
Retail
Small Business
MAIN MENU
DEUTSCH
ENGLISH (AU)
ENGLISH (UK)
ESPAÑOL
FRANÇAIS
ITALIANO
PORTUGUÊS
LATAM
繁體中文
日本語
한국어
عربى
Cybersecurity 101 › Kerberoasting
KERBEROASTING ATTACKS
Venu Shastri - June 13, 2022

What is a Kerberoasting attack?
Kerberoasting is a post-exploitation attack technique that attempts to crack the password of a service account within the Active Directory (AD).

In such an attack, an adversary masquerading as an account user with a service principal name (SPN) requests a ticket, which contains an encrypted password, or Kerberos. (An SPN is an attribute that ties a service to a user account within the AD). The adversary then works offline to crack the password hash, often using brute force techniques.

Once the plaintext credentials of the service account are exposed, the adversary possesses user credentials that they can use to impersonate the account owner. In so doing, they appear to be an approved and legitimate user and have unfettered access to any systems, assets or networks granted to the compromised account.

Kerberoasting attacks are difficult to detect because:

Many traditional cybersecurity tools and solutions are not designed to monitor or analyze the behavior and activity of approved users.
The absence of malware in these types of attacks leaves other traditional defensive technologies, such as antivirus solutions, powerless.
As an “offline” attack, Kerberoasting attacks do not involve any unusual network traffic or the transmission of data packets, which means that such activity will not be logged or trigger an alert.
Why are Kerberoasting attacks so prevalent?
Adversaries go to great lengths to access user credentials via techniques like Kerberoasting because the ability to pose as a legitimate user helps the attacker avoid detection while advancing the attack path. Once on a system via credential theft, the hacker has access to any system, service or network the account is entitled to. Skilled attackers can also attempt to elevate their account privileges and move laterally throughout the network, collecting other account credentials, setting backdoors for future access and stealing data along the way.

How do Kerberoasting attacks work?
Kerberoasting attacks exploit a combination of weak encryption techniques and insecure or low-quality passwords. These attacks typically follow the below process:

An attacker who has already compromised the account of a domain user authenticates the account and launches a new session.
The attacker, who appears to be a valid domain user, requests a Kerberos service ticket from the ticket granting service (TGS) using tools like GhostPack’s Rubeus or SecureAuth Corporation’s GetUserSPNs.py.
The adversary receives a ticket from the Kerberos key distribution center (KDC). The ticket contains a hashed version of the account’s password, or Kerberos.
The adversary captures the TGS ticket and Kerberos from memory and takes it offline.
The hacker attempts to crack the SPN value or service credential hash to obtain the service account’s plaintext password using brute force techniques or tools like Hashcat or JohnTheRipper.
With the service account password in hand, the adversary attempts to log in to the service account and is granted access to any service, network or system associated with the compromised account.
The attacker is then able to steal data, escalate privileges or set backdoors on the network to ensure future access.

# for privilege escalation

https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html

