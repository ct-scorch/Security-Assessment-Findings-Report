# Security-Assessment-Findings-Report
Conducted a theoretical penetration test involving reconnaissance, vulnerability scanning, remediation, and documentation. Delivered a 15+ page technical report and 2-page executive summary. Utilized tools such as Nmap, Nessus, Netcat, OpenVAS, BurpSuite, and Wapiti.

# Penetration Testing Report

## Executive Summary
Artemis, Inc. has experienced substantial growth, prompting a cautious approach to maintaining and enhancing its security infrastructure. Despite having solid practices, areas for improvement remain that, when addressed, will help to ensure enhanced confidentiality, integrity, and availability. In July 2024, Artemis, Inc. (“AI”) engaged Cenunnos Security Consulting (“CSC”) to assess its security architecture. Throughout the assessment, CSC identified nine vulnerabilities (three critical, six high) based on NIST metrics. 

Significant gaps were found in data handling across Artemis' cloud infrastructure, web applications, and internal tools. A critical vulnerability in Microsoft Exchange (CVE-2021-26855) highlighted the need for robust patch management. CSC recommends further investigation into the Apollo and PARS systems as the sensitive nature of the stored and transmitted data involves trade secrets and intellectual property.

Addressing these vulnerabilities with careful and timely remediation can resolve issues with minimal business impact. Implementing robust management strategies and focusing IT staff efforts on securing web servers, internal infrastructure, and processes will yield significant long-term benefits, ensuring AI's continued growth and profitability without compromising security.

## Scope of Testing
Testing and validation will be performed between August 1, 2024, and August 31, 2024. The project's scope is limited to AI’s internal network, public-facing servers, and databases (cloud-based or on-premises). 

These tests will be conducted where feasible on duplicate but functionally identical versions of AI’s internal networks and networked assets to not impact AI’s day-to-day operations.

There are no time-of-day restrictions; however, AI has requested that CSC not approach any physical sites or attempt any form of social engineering. Additionally, they have stated that CSC is not to conduct any denial of service exercises, where applicable.   

Assets and infrastructure relevant to AI’s SCADA/ICS systems are to be considered explicitly out of scope.

## Findings
CSC initiated this security assessment from the perspective of an external attacker. AI provided CSC with several hosts, URLs, and IP addresses but did not furnish credentials for the remainder of the hosts that were later enumerated. CSC obtained all information beyond what was initially noted in the “Scope of Work” section throughout its assessment. 

                
|Severity  | Finding  |
|----------|----------|
|Critical  |  3       |
|High      |  6       |
|Medium    |  0       |
|Total     |  0       |

_Table 3: Severity Summary_

Below is a high-level view of the nine most notable vulnerabilities discovered throughout this assessment; more detailed information is available in the attached Threat Assessment document. It is worth noting that while the list is ordered from highest severity to lowest, the order within those categories is arbitrary and does not imply any recommendations as to which vulnerability should be addressed first. 

|Finding number | Finding Name | Severity Level|
|---------------|--------------|---------------|
|1 |CVE-2020-14882 |Critical |
|2 |CVE-2021-26855 |Critical |
|3 |Unpatched RDP exposed |Critical |
|4 |SQL Injection |High |
|5 |Default credentials |High|
|6 |CVE-2019-0211 | High |
|7 |Sensitive data exposure | High |
|8 |Broken access control | High |
|9 |Misconfigured AWS | High |

_Table 4: Findings List_

Initial vulnerability scans against AIs public-facing web applications revealed vulnerability to SQL injection. Testers note they could access internal databases and execute administration operations, notably exfiltrating data. 
Figure 1: SQL Injection Vulnerabilities discovered by Tenable Nessus

Additionally, testers determined several of AIs web servers were exposing sensitive information. Through SQL injection, testers could recover a database of user passwords they determined were unsalted. Testers could then expose the passwords using a rainbow table of pre-calculated hashes. 

Using data from previous SQL attacks, testers discovered account numbers corresponding to user accounts. With this information, they were able to modify the browser's 'acct' parameter to send a desired account number. As this information is not correctly verified, the tester had access to any user's account for which they had an account number, which is considered broken access control.

Testers noted that this web server was not hosted locally but inside Amazon Web Services (AWS). With this knowledge and the assistance of an overly permissive security group, testers were able to escalate privileges again within the AWS environment; this was accomplished using a tool called Pacu. 


Figure 2: AWS privilege escalation using “Pacu” (https://medium.com/@terminalsandcoffee/aws-iam-privilege-escalation-by-policy-misconfiguration-4be3aec755d4

Initial network scans using Nmap revealed several open ports, notably port 3389, corresponding to RDP or Remote Desktop Protocol. Testers determined they were then able to resolve several hosts within AIs' internal networks. They were then able to execute brute-force attacks through RDP against those hosts, facilitating privilege escalation. Testers were also able to navigate to internal file shares and exfiltrate sensitive data. 

Figure 3: Nmap scan reveals open ports, specifically 3389/Remote Desktop Protocol (3389)

Testers also determined that the on-premise Exchange server accepts untrusted connections over port 443, typically associated with CVE-2021-26855. Leveraging this vulnerability allowed testers to exfiltrate entire mailboxes from the mail server. Testers were able to deploy subsequent exploits that allowed for credential theft, privilege escalation, and address-book (offline address book, or OAB) theft. 

Note: This and other CVEs also appear in vulnerability scans using Nessus.

Figure 4: Using Nessus’ plugin search for specific CVEs 

The credentials appropriated at this stage were then compared with credentials from a previous stage, and testers noted a relatively high rate of re-use, indicating a weak password policy. 

Through careful parsing of the data extracted from mailboxes and compromised hosts, the testers were then able to enumerate two internal web servers: an Oracle WebLogic server and an Apache web server. 

Testers first successfully compromised the Oracle WebLogic server as they determined it was vulnerable to CVE-2020-14883. This CVE allows for remote code execution wherein the tester can “execute arbitrary commands” and take complete control of the host. This is accomplished by exploiting a flaw in the configuration of the “Path Traversal blacklist of the server URL, which you can find inside a handler class of the WebLogic HTTP access.” Exploiting this resource gave testers access to AI's ERP tool (SAP). 

Testers then determined that AI at one point, installed an Oracle WebLogic Server proxy plug-in for the Apache HTTP server. Using their escalated privileges from the previous compromise of the Oracle WebLogic server, testers could move laterally to the Apache server. 

At that point, they determined it was vulnerable to CVE-2019-0211. This particular CVE allows, again, for the execution of arbitrary code. In this case, however, the testers needed to wait until the Apache server had been ‘gracefully restarted’ to move forward. This process happens nightly, so our testers gained local root access to this particular server the following business day.  

With a toehold in the internal network, testers directed their attention to other hosts discovered during enumeration. Chief among them was an array of Cisco Firewalls, which they could breach using default login credentials; trying credentials easily sourced from a simple Google search in an instance such as this is standard practice. With those credentials, testers functionally owned a large portion of AIs internal network landscape. 

| Finding Number | Finding Name | External Reference |
|----------------|--------------|---------------------|
|1 | CVE-2020-14882 | https://nvd.nist.gov/vuln/detail/CVE-2020-14882|
|2 | CVE-2021-26855 | https://nvd.nist.gov/vuln/detail/CVE-2021-26855|
|3 | Unpatched RDP exposed | https://www.cloudflare.com/learning/access-management/rdp-security-risks/|
|4|SQL Injection|https://owasp.org/www-community/attacks/SQL_Injection|
|5|Default credentials|https://owasp.org/www-project-top-10-insider-threats/docs/2023/INT07_2023-Insecure_Passwords_and_Default_Credentials|
|6|CVE-2019-0211|https://nvd.nist.gov/vuln/detail/CVE-2019-0211|
|7|Sensitive data exposure|https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure|
|8|Broken access control|https://owasp.org/Top10/A01_2021-Broken_Access_Control/|
|9|Misconfigured AWS|https://www.barradvisory.com/resource/cloud-misconfiguration/|

_Table 5: External References_


## Risk Assessment
| Vulnerability                | Severity | Risk Level |
|-----------------------------|----------|------------|
| SQL Injection                | High     | Critical   |
| Cross-Site Scripting (XSS)  | Medium   | Moderate   |
| Insecure Direct Object Reference | Medium   | Moderate   |

## Conclusion
The penetration test identified several vulnerabilities that need to be addressed to improve the overall security posture of [Client Name]’s infrastructure. Immediate action is recommended for high-severity findings.

## Appendix
- **Testing Tools Used:**
  - Burp Suite, Nmap, [any other tools you used]
- **References:**
  - [Links to resources or frameworks used]


