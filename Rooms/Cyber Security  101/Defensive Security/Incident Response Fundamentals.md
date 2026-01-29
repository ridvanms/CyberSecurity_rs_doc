### What are Incidents?
Events are generated in huge numbers regularly. This is because many processes run on a device, each performing different routine tasks, generating numerous events. These events can sometimes point to something terrible going on in your device. How do we check these vast numbers of events and see if they point to some destructive activity? There are security solutions in place to solve this problem. These events are ingested into the security solutions as logs, and the security solutions can find harmful activities in them. This made our job way more easier! But wait a minute; the real challenge is after the security solution points these activities out.

So, when a security solution finds an event or group of events associated with a possible harmful activity, it triggers an alert. The security team then analyzes these alerts. Some of these alerts may be **False Positives**, while some would be **True Positives**. The alerts that point to something dangerous but are not harmful are referred to as false positives. In contrast, the alerts that point to something harmful and are actually dangerous are called true positives. You can get a better understanding of this from the example below:

**False positive:** A security solution raised an alert on a high amount of data being transferred from one system to an external IP address. Upon analyzing this alert, the security team found that the subject system was undergoing a backup process to a cloud storage service, which caused this. This is known as a false positive.

**True Positive:** A security solution raised an alert on a phishing attempt on one of the organization’s users. Upon analyzing this alert, the security team found that the email was a phishing email sent to this user to compromise the system. This is known as a true positive.

These true positive alerts are sometimes referred to as **Incidents**. Assuming the alert is now categorized as an incident, the next phase is to give a severity level to the incident. Imagine you are part of the security team and get multiple incidents simultaneously. Which incident would you choose first to respond to? This is where the idea of incident severity helps. Incidents can be categorized as low, medium, high, or critical based on the impact they can create. Critical Severity incidents are always the higher priority, followed by high severity, and so on.

#QUESTIONS 
**What is triggered after an event or group of events point at a harmful activity*?*
- 
**If a security solution correctly identifies a harmful activity from a set of events, what type of alert is it?**
- 
**If a fire alarm is triggered by smoke after cooking, is it a true positive or a false positive?**
- 

### Types of Incidents
- **Malware Infections**: Malware is a malicious program that can damage a system, network, or application. The majority of incidents are associated with malware infections.  There are different types of malware, each with a unique potential to cause damage. Malware infections are mostly caused by files that can be text, documents, executables, etc.

![Computer surrounded by tenticles.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1718267680505)

 - **Security Breaches:** Security Breaches arise when an unauthorized person gets access to confidential data (something we don’t want them to see or have).  Security Breaches are of the utmost importance as many businesses rely on their confidential data, which must only be accessible to authorized personnel.

![Attacker getting unauthorized access to a computer's data](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1718267680503)

- **Data Leaks:** Data leaks are incidents in which confidential information of an individual or an organization is exposed to unauthorized entities. Many attackers use data leaks for reputational damage to their victims or use this technique to threaten their victims and get what they need from them. Unlike Security Breaches, data leaks can also be unintentionally caused by human errors or misconfigurations.

![Data getting leaked from a computer.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1718267680577)
- **Insider Attacks:** Incidents from within an organization are known as insider attacks. Think about a disgruntled employee infecting the whole network through a USB on his last day. This is an example of an insider attack. Someone within your organization intentionally initiating an attack comes under this category. These attacks can be hazardous, as an insider always has greater access to resources than an outsider.

![An attacker shown as an insider in between all the employees.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1718267680502)
- **Denial Of Service Attacks:** Availability is one of the three pillars of cyber security. Defensive security solutions and people constantly find ways to protect information; they ensure that the data is available to the people simultaneously. This is because there is no point in protecting something that is unavailable to us. Denial of Service attacks, or DoS attacks, are incidents where the attacker floods a system/network/application with false requests, eventually making it unavailable to legitimate users. This happens due to the exhaustion of resources available to entertain the requests.

![DOS Missiles targeting a computer.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1718267680690)
All these incidents have their unique potential to impact the victim negatively. These incidents can not be compared in terms of the severity of the impact they create. This is because a particular incident can be disastrous for one organization while it can cause minor damage to another. For example, XYZ Corp. may not be heavily impacted by a data leak as the information it stores can be useless to anybody else. However, it can undergo a massive loss in case of a Denial of Service (DoS) attack on its primary website, as its services depend on that website.

### Incident Response Process
Due to the distinct nature of incidents in organizations, there should be a structured process for incident response. Incident Response Frameworks help us in this regard. These are the generic approaches to follow in any incident for effective response. We will discuss the two widely used incident response frameworks: SANS and NIST.

SANS and NIST are popular organizations contributing to cyber security. SANS has offered various courses and certifications in cyber security, and NIST played its role in developing standards and guidelines for cyber security. Both SANS and NIST have quite similar incident response frameworks.

The SANS incident Response framework has 6 phases, which can be called 'PICERL' to remember them easily.

|Phase|Explanation|Example|
|---|---|---|
|Preparation|This is the first phase. The preparation phase includes building the necessary resources to handle an incident. These resources include developing incident response teams, having a proper incident response plan in place, and deploying necessary security solutions to combat the incidents.|Conducting awareness training for employees on phishing emails. Phishing emails are fraudulent emails sent by malicious attackers that can trick you into performing actions that can lead you to an incident.|
|Identification|The identification phase refers to looking for any abnormal behavior that may indicate an incident. This involves using various security solutions and techniques to monitor abnormal events.|The security team notices a huge amount of data being sent out from one of the hosts. Upon analysis, it was found to be compromised after a malicious file was downloaded from a phishing email attachment.|
|Containment|Once an incident has been identified, the next step should be to contain it. This means minimizing the impact of the attack. This is usually done by isolating the victim machine, disabling the compromised user accounts, etc.|The Security team isolates the host from the network to minimize the impact and not allow the attacker to jump to other systems, leveraging the compromised host.|
|Eradication|This phase, as its name suggests, involves removing the threat from the attacked environment. The threat may be of any kind. The eradication phase will ensure the subject environment is clean, and now we can move to the recovery phase.|A deep malware scan was executed on the system to remove the malicious software from the host.|
|Recovery|The recovery phase is very important in this chain. It involves recovering the affected systems from backup or rebuilding them. The recovered systems are then tested and are ready to use.|The compromised host was re-configured, and the exfiltrated data was restored from the backup.|
|Lessons Learned|This is also an important part of the incident response lifecycle. Gaps in the detection and analysis of the incident are identified and documented, helping to improve the overall process in future incidents.|Conducting a post-incident review meeting to analyze the incident's root cause and improve the security to prevent future attacks.|

![SANS Incident Response phases.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1718265520999)  

The Incident Response Framework of NIST is similar to the SANS framework we studied above. The number of phases in this framework is reduced to 4.

![NIST Incident Response phases.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1718268206803)  

Following is the comparison of both:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1723217056943.png)  

Organizations may derive their incident response processes by following these frameworks. Every process has a formal document listing all the relevant organizational procedures. The formal incident response document is called the **Incident Response Plan**. This structured document underlines the approach during any incident. It is formally approved by senior management and consists of the procedures to be followed before, during, and after an incident has been completed.

The key components of this plan include (and are not limited to):

- Roles and Responsibilities
- Incident Response methodology
- Communication plan with stakeholders, including law enforcement
- Escalation path to be followed

### Incident Response Techniques
Remember we studied the second phase of the incident response lifecycle, ‘Identification’ in SANS, and ‘Detection and Analysis’ in NIST. It is very hard to look for abnormal behavior and identify incidents manually. There are multiple security solutions that serve their own unique roles in detecting any incidents. Some of them even have the capability to respond to the incidents and execute the other phases of the lifecycle, such as containment, eradication, etc. A brief explanation of some of these solutions is given below:

- **SIEM:** The Security Information and Event Management Solution (SIEM) collects all important logs in one centralized location and correlates them to identify incidents.
- **AV:** Antivirus (AV) detects known malicious programs in a system and regularly scans your system for these.
- **EDR:** Endpoint Detection and Response (EDR) is deployed on every system, protecting it against some advanced-level threats. This solution can also contain and eradicate the threat.

![Three computers showing SIEM, EDR and AV on each screen.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1718265646748)  

After incidents are identified, certain procedures must be followed, including investigating the extent of the attack, taking necessary actions to prevent further damage and eliminate it from the root. These steps may be different for different kinds of incidents. In this scenario, having step-by-step instructions to deal with each kind of incident helps you save a lot of time. These types of instructions are known as **Playbooks**.

Playbooks are the guidelines for a comprehensive incident response.

Following is an example of a **Playbook** for an incident: Phishing Email

![Picture showing a playbook.](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1718268773282)

1. Notify all the stakeholders of the phishing email incident
2. Determine if the email was malicious by conducting header and body analysis of the email
3. Look for any attachments with the email and analyze them
4. Determine if anybody opened the attachments
5. Isolate the infected systems from the network
6. Block the email sender

**Runbooks**, on the other hand, are the detailed, step-by-step execution of specific steps during different incidents. These steps may vary depending on the resources available for investigation.

#QUESTIONS 
**Step-by-step comprehensive guidelines for incident response are known as?**
-   

### Conclusion
In this room, we learned about the different concepts of incident response. We studied how and when an event is categorized as an incident and the priorities given to different incidents. We also looked into types of incidents and the frameworks of incident response: SANS and NIST, which guide us through handling an incident. Lastly, we saw some tools for incident response and carried out a realistic hands-on lab.


