### Introduction to Logs
Attackers are clever. They avoid leaving maximum traces on the victim’s side to avoid detection. Yet, the security team successfully determines how the attack was executed and is even sometimes successful in finding who was behind the attack.

Suppose a few policemen are investigating the disappearance of a precious locket in a snowy jungle cabin. They observed that the wooden door of the cabin was brutally damaged, and the ceiling collapsed. There were some footprints on the snowy path to that cabin. Lastly, they discovered some CCTV footage from a neighbouring residence. By placing together all these traces, the police successfully determined who was behind the attack. Various traces are found in several such cases; putting all these together takes you closer to the criminal.


It seems like these traces play a big role in the investigations.

What if something happened within a digital device? Where do we find all these traces to investigate further?

There are various places inside a system where the traces of an attack could be fetched. The logs contain most of these traces. Logs are the digital footprints left behind by any activity. The activity could be a normal one or the one with malicious intent. Tracing down the activity and the individual behind the execution of that activity becomes easier through logs.

Footprints on a floor.

Use Cases of Logs
The following are some key areas in which the logs play an integral role.

Use Case	Description
Security Events Monitoring	Logs help us detect anomalous behavior when real-time monitoring is used.
Incident Investigation and Forensics	Logs are the traces of every kind of activity. It offers detailed information on what happened during the incident. The security team utilizes the logs to perform root cause analysis of incidents.
Troubleshooting	As the logs also record the errors in systems or applications, they can be used to diagnose issues and helpful in fixing them.
Performance Monitoring	Logs can also provide valuable insights into the performance of applications.
Auditing and Compliance	Logs play a major role in Auditing and Compliance, making it easier with its capability to establish a trail of different kinds of activities.
This room will equip you with an understanding of various types of logs maintained in different systems. We will also be practically investigating logs as traces of different attacks.

Learning Objectives
After completing this room, you will learn about the following:
- The different types of logs
- How to analyze logs
- Analyzing Windows Event logs
- Analyzing Web Access logs

### Types of logs
In the previous task, we saw various use cases of logs. But there is a challenge. Imagine you have to investigate an issue in a system through the logs; you open the log file of that system, and now you are lost after seeing numerous events of different categories.

Here is the solution: Logs are segregated into multiple categories according to the type of information they provide. So now you just need to look into the specific log file for which the issue relates.

For example, you need to investigate the successful logins from yesterday at a specific timeframe in Windows OS. Instead of looking into all the logs, you only need to see the system’s Security Logs to find the login information. We also have other types of logs that are useful in investigating different incidents. Let’s have a look at them.


Log Type	Usage	Example
System Logs	The system logs can be helpful in troubleshooting running issues in the OS. These logs provide information on various operating system activities.	- System Startup and shutdown events
- Driver Loading events
- System Error events
- Hardware events
Security Logs	The security logs help detect and investigate incidents. These logs provide information on the security-related activities in the system.	-Authentication events
- Authorization events
- Security Policy changes events
- User Account changes events - Abnormal Activity events
Application Logs	The application logs contain specific events related to the application. Any interactive or non-interactive activity happening inside the application will be logged here.	- User Interaction events
- Application Changes events
- Application Update events
- Application Error events
Audit Logs	The Audit logs provide detailed information on the system changes and user events. These logs are helpful for compliance requirements and can play a vital role in security monitoring as well.	- Data Access events
- System Change events
- User Activity events
- Policy Enforcement events
Network Logs	Network logs provide information on the network’s outgoing and incoming traffic. They play crucial roles in troubleshooting network issues and can also be handy during incident investigations.	- Incoming Network Traffic events
- Outgoing Network Traffic events
- Network Connection Logs - Network Firewall Logs
Access Logs	The Access logs provide detailed information about the access to different resources. These resources can be of different types, providing us with information on their access.	- Webserver Access Logs
- Database Access Logs - Application Access Logs
- API Access Logs
Note: There can be various other types of logs depending on the different applications and the services they provide.

Now that we understand what these logs are and how various types of logs can be helpful in different scenarios, let’s see how we analyze these logs and extract valuable information required from them. Log Analysis is a technique for extracting valuable data from logs. It involves looking for any signs of abnormal or unusual activities. Searching for a specific activity or abnormalities in the logs with the naked eye is impossible. For this reason, we have several manual and automated techniques for log analysis. We will manually carry out log analysis on Windows and Web Server Access Logs in the upcoming tasks.

### Windows Event Logs Analysis
Like other operating systems, Windows OS also logs many of the activities that take place. These are stored in segregated log files, each with a specific log category. Some of the crucial types of logs stored in a Windows Operating System are:

- **Application:** There are many applications running on the operating system. Any information related to those applications is logged into this file. This information includes errors, warnings, compatibility issues, etc.
- **System:** The operating system itself has different running operations. Any information related to these operations is logged in the System log file. This information includes driver issues, hardware issues, system startup and shutdown information, services information, etc.
- **Security:** This is the most important log file in Windows OS in terms of security. It logs all security-related activities, including user authentication, changes in user accounts, security policy changes, etc.

Besides these, several other log files in the Windows operating system are designed for logging activities related to specific actions and applications.

Here is a table of some important Event IDs in Windows Operating System.

Event ID	Description
4624	A user account successfully logged in
4625	A user account failed to login
4634	A user account successfully logged off
4720	A user account was created
4724	An attempt was made to reset an account’s password
4722	A user account was enabled
4725	A user account was disabled
4726	A user account was deleted
There are many more event IDs. It is not necessary to remember all of them, but it is good to remember the crucial event IDs.

