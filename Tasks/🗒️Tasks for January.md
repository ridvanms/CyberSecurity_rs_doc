#task #cybersecurity #walkthrough_task 
## Task 2026-01-10
## For Creating backdoor service  
- Created payload on attacker machine
- added listener on the attacker machine
- and creating server with python3 on the attacker machine
- downloading the payload on the victim machine
- then creating on victim machine service which path leads to the path 
- starting the service 
- we've gained access to the machine with administrator privileges with the listener
- and finding and reviling the flag
FLAG7-THM{SUSPICIOUS_SERVICES}

## WITH Modifying existing services
- same steps as backdoor service but with another payload which is to configure already existed service with which we grained the administration privileges 
FLAG8-THM{IN_PLAIN_SIGHT}

## Task 2026-01-13
- creating reverse shell command for victim machine and using it 
- creating listener on the attacker machine
- checking for task running 
- hiding task from all eyes with deleting sd in security descriptors of all scheduled tasks
- and then navigating to the flag from the listener and gaining the flag
FLAG9 - THM{JUST_A_MATTER_OF_TIME}

## Task 2026-01-14
- using msfvenom to create a payload for reverseshell
- creating local server and opening a nc listener 
- on the victim machine though wget downloading the payload 
- copying it to the C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp 
- then just reconnecting to the victom and we have the revers shell on our machine
- grabbing the flag
FLAG10 - THM{NO_NO_AFTER_YOU}

# TASKS FROM  [[Lateral Movement and Pivoting]]
## Task 2026-01-22
- connecting to THMJMP2 using the credentials assigned to you on Task 1 via ssh
- Using credentials to move laterally to THM-IIS using WMI and MSI packages
- using SMB we copy the payload to the ADMIN$ share that  we created with msfvenom
- starting handler to receive the reverse shell from Metasploit
- starting WMI session against THMIIS from Powershell console.
- Invoking the install method from the Win32_Product class to trigger the payload
FLAG = THM{MOVING_WITH_WMI_4_FUN}

# TASKS FROM [[Data Exfiltration]]
## Task 2026-01-28
*In which case scenario will sending and receiving traffic continue during the connection?*
- tunneling
*In which case scenario will sending and receiving traffic be in one direction*
- traditional data exfiltration
