#task #cybersecurity #walkthrough_task 
# Task 2026-01-10
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

# Task 2026-01-13
- creating reverse shell command for victim machine and using it 
- creating listener on the attacker machine
- checking for task running 
- hiding task from all eyes with deleting sd in security descriptors of all scheduled tasks
- and then navigating to the flag from the listener and gaining the flag
FLAG9 - THM{JUST_A_MATTER_OF_TIME}