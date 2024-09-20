# Security-Assessment-Findings-Report
Conducted a theoretical penetration test involving reconnaissance, vulnerability scanning, remediation, and documentation. Delivered a 15+ page technical report and 2-page executive summary. Utilized tools such as Nmap, Nessus, Netcat, OpenVAS, BurpSuite, and Wapiti.

The formatting of this document was modified to suit GitHub. The document in it's original format is available [here](https://docs.google.com/document/d/1O41CkQ6O5y-C_KMBGYYy3hBcR39NxCicLMDb5IoODnE/edit?usp=sharing) 

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

## Timeline
Test Start Date: 	01 August 2024 0800
Test End Date: 	31 August 2024 1700

Testers will generally adhere to a business-day/hours timeframe, though no specific exceptions regarding time have been stipulated. Testers will not be asked to work outside those hours, though if they have reason to believe it will in some way affect the outcome of a specific test, they may request accommodation to conduct their work outside of the commonly accepted hours. 

**Week 1**	Week one is earmarked for public web server testing and reconnaissance. 
**Week 2**	Week two is earmarked for additional public web server/application testing.
**Week 3**	Week three is earmarked for internal infrastructure/network testing. 
**Week 4**	Week four is earmarked for cloud-service testing/evaluation. 

**Post-test tasks**

After four weeks of testing, CSC will evaluate AIs' planned infrastructure changes (e.g., equipment vendors, service providers, etc.) and compile a supplementary report that includes risks and recommendations based on those changes. 
The material in that report does not explicitly endorse one provider/vendor over another and is provided to highlight possible vulnerabilities and considerations when making substantive system/infrastructure changes. 
After the supplementary report has been compiled, CSC will provide comprehensive testing documentation and additional supplementary materials, including logs, screenshots, network dumps, and any other ancillary data acquired or compiled throughout the initial testing phase. 
For the sake of post-test auditing, CSC will not attempt to obfuscate any of its activities in the testing environment, whether successful or otherwise. 

Note: CSC reserves the right to change or alter the timeline at any time but will make every effort to provide AI with adequate notification before doing so. 

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
## Recommendations

Recommendations

Recommendations will be listed in the same order as they appear in “Table 4: Finding List” to maintain continuity. It is worth noting that, as previously stated, vulnerabilities are listed from most severe to least (critical to high), but within their categories, their order is arbitrary. AI should endeavor to remediate these vulnerabilities quickly, but critical vulnerabilities should be addressed first. 

**Finding 1: CVE-2020-14882** - _Critical_

This CVE pertains to an RCE or remote code execution vulnerability in the console component of the Oracle WebLogic Server. Oracle recommends patching to resolve this issue, though compensating controls such as ensuring the administrator console isn’t exposed to the public internet can be used until maintenance can be conducted. That being said, we advise that this be patched as soon as possible, as ensuring the administrator console isn’t publicly facing doesn’t necessarily remove the vulnerability altogether (where patching does). 

**Finding 2: CVE-2021-26855** - _Critical_  

This CVE is a zero-day exploit that impacts Exchange Server versions 2010, 2013, 2016, and 2019. As 2019 is used in AI’s environment, patching this vulnerability is imperative. Additionally, this CVE is required in a chain of other CVEs that are equally devastating in their scope and impact. Microsoft has released patches to address this vulnerability, and we implore AI to implement them immediately. Compensating controls exist for this vulnerability, but we do not feel they are sufficient to address the threat this CVE represents. 

**Finding 3: Unpatched RDP exposed** - _Critical_ 

This vulnerability pertains to exploiting the insecure nature of the Remote Desktop Protocol and its implementation. Port 3389 is public-facing, and exploits are plentiful and accessible. Several solutions are available to resolve this issue, such as VPN, MFA, or a Remote Desktop Gateway however, AI must have a consistent, demonstrated need to keep this port open, or else we advise closing it altogether. There are many off-the-shelf options to accomplish RDP-like tasks, which AI can evaluate at their convenience.

**Finding 4: SQL Injection** - _High_  

“SQL injection vulnerabilities arise when user-controllable data is incorporated into database SQL queries unsafely. An attacker can supply crafted input to break out of the data context in which their input appears and interfere with the structure of the surrounding query” (Portswigger, 2024) . One of the most effective defenses against SQL injection is the use of “parameterized queries” or “prepared statements” for all database access. This solution is part of a more extensive set of solutions that involve more standardized code evaluation, DevSecOps methodologies, and code testing (static and dynamic). 

**Finding 5: Default credentials** - _High_  

During our assessment, we discovered that the Cisco Administrator portal was accessible using the default credentials. It is essential to point out that these credentials are included in Cisco literature and are widely available around the internet. This means anyone with sufficient access to AI's network could also easily access the entire Cisco equipment footprint. As a result, we advise changing those credentials as soon as possible, preferably to something conforming more to modern complexity requirements. More to the point, Cisco mentions in their documentation regarding password changes (https://www.cisco.com/c/en/us/support/docs/smb/switches/cisco-small-business-300-series-managed-switches/smb5563-configure-password-settings-on-a-switch-through-the-command.html) that contemporary and up-to-date iterations of their equipment have complexity requirements and a forced reset at first login, which may indicate that the current firmware/drivers/etc are not up to date. As a result, we also advocate checking for, testing, and deploying all available security/firmware updates as soon as possible. 

**Finding 6: CVE-2019-0211** - _High_  

This CVE pertains to a local root privilege escalation, and its remediation method is deceptively simple: patching. Upgrading to Apache 2.4.39 closes this loophole; however, this process is noted for its impact and complexity, so careful and thoughtful patch management and testing should be employed at a minimum. 

**Finding 7: Sensitive data exposure** - _High_ 

This vulnerability dovetails with the remediation suggestions found in Finding 4, which is to say standardized and regular code review (manual and otherwise), DevSecOps methodologies, and state/dynamic code testing. More specifically, however, we advise salting the password databases we were able to access to better protect them from attackers.

**Finding 8: Broken access control** - _High_ 

OWASP lists several remediation steps and states that "access control is only effective in trusted server-side code or server-less API, where the attacker cannot modify the access control check or metadata." Those steps include "deny by default, except for public resources," logging access control failures, and alerting admins when appropriate. The EC Council advocates for performing access validation; "if an attacker tries to tamper with an application or database by modifying the given references, the system should be able to shut down the request, verifying that the user does not have the proper credentials." 

**Finding 9: Misconfigured AWS** - _High_  

Remediation steps for common AWS misconfigurations include following the principle of least privilege, regularly reviewing and updating security group rules, and using Network Access Control Lists (NACLs) in conjunction with security groups for enhanced security. Additionally, taking advantage of security group features to permit only host groups that need to communicate and blocking unnecessary outbound traffic. 
Creating granularly defined IAM policies, utilizing groups and roles to manage permissions efficiently, and follow cloud IAM best practices to ensure that only the right people or services can access your AWS resources.

**General Recommendations** - _Informational_
	
	Per informal discussions CSC has had with AI regarding upcoming network infrastructure changes, we also advise that AI seriously consider maintaining some vendor diversity in its network topology. Specifically, they support (or even upgrade) their existing fleet of Cisco firewalls while complimenting it with Fortigate equipment. Vendor diversity eliminates single points of failure. Should one vendor become compromised or deploy a bad patch/firmware update, the organization wouldn’t need to stop work completely until that issue is resolved; they could effectively fail over to whatever equipment is up and running. 

**Apollo and PARS** - Informational
	Regrettably, we could not spend as much time as we would have liked evaluating the Apollo and PARS systems. However, based on how the workflow was explained to us, we would advise AI to investigate a secure document storage and transmission system to replace what appears to be an almost entirely manual system. 
	Given that AI has an existing relationship with Microsoft via O365, migrating to OneDrive seems logical. AI could leverage advisors within Microsoft’s organization to assist in onboarding, training, and best practices around its deployment and use. If AI would prefer to introduce more vendor diversity, they could evaluate other cloud-based storage companies such as Dropbox or IBM’s “Cloud Object Storage.” 
	Some critical considerations regarding document storage would be the vendor's encryption standards, uptime, scalability/elasticity, and post-purchase support/SLAs. 

## Conclusion
The penetration test identified several vulnerabilities that need to be addressed to improve the overall security posture of [Atremis]’s infrastructure. Immediate action is recommended for high-severity findings.

## Sources

https://research.nccgroup.com/2021/10/21/detecting-and-protecting-when-remote-desktop-protocol-rdp-is-open-to-the-internet/
https://www.cloudflare.com/learning/access-management/rdp-security-risks/
https://news.sophos.com/en-us/2024/03/20/remote-desktop-protocol-exposed-rdp-is-dangerous/
https://owasp.org/www-community/attacks/SQL_Injection
https://portswigger.net/web-security/sql-injection
https://owasp.org/www-project-top-10-insider-threats/docs/2023/INT07_2023-Insecure_Passwords_and_Default_Credentials
https://nvd.nist.gov/vuln/detail/CVE-2019-0211
https://www.tenable.com/blog/cve-2019-0211-proof-of-concept-for-apache-root-privilege-escalation-vulnerability-published
https://my.f5.com/manage/s/article/K32957101
https://securiti.ai/blog/sensitive-data-exposure/
https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure
https://www.paloaltonetworks.com/cyberpedia/sensitive-data
https://owasp.org/Top10/A01_2021-Broken_Access_Control/
https://owasp.org/www-community/Broken_Access_Control
https://www.eccouncil.org/cybersecurity-exchange/web-application-hacking/broken-access-control-vulnerability/
https://nvd.nist.gov/vuln/detail/CVE-2020-14882
https://www.rapid7.com/blog/post/2020/10/29/oracle-weblogic-unauthenticated-complete-takeover-cve-2020-14882-what-you-need-to-know/
https://www.tenable.com/blog/cve-2020-14882-oracle-weblogic-remote-code-execution-vulnerability-exploited-in-the-wild
https://www.barradvisory.com/resource/cloud-misconfiguration/
https://www.cypressdatadefense.com/blog/cloud-computing-security-vulnerabilities/
https://www.crowdstrike.com/blog/common-cloud-security-misconfigurations/
https://nvd.nist.gov/vuln/detail/CVE-2021-26855
https://www.upguard.com/blog/cve-2021-26855
https://msrc.microsoft.com/update-guide/en-us/vulnerability/CVE-2021-26855
https://www.tenable.com/blog/cve-2021-26855-cve-2021-26857-cve-2021-26858-cve-2021-27065-four-microsoft-exchange-server-zero-day-vulnerabilities



