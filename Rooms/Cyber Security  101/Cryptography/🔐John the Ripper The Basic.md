[[🔐John the Ripper The Basic]]
John the Ripper is a well-known, well-loved, and versatile *hash-cracking tool*. It combines a fast cracking speed with an extraordinary range of compatible hash types.
Upon the completion of this room, you learn about using John for:

- Cracking Windows authentication hashes
- Crack `/etc/shadow` hashes
- Cracking password-protected Zip files
- Cracking password-protected RAR files
- Cracking SSH keys


> [!Basic Terms] Basic Terms
> ## **What are Hashes**
> A hash is a way of taking a piece of data of any length and representing it in another fixed-length form
> “*polomints*”, a string of 9 characters
> ## **What Makes Hashes Secure**
> Hashing functions are designed as one-way functions. In other words, it is easy to calculate the hash value of a given input; however, it is a hard problem to find the original input given the hash value.
> In computer science, *P* and *NP* are two classes of problems that help us understand the efficiency of algorithms:
>
>- **P (Polynomial Time)**: Class P covers the problems whose solution can be found in polynomial time. Consider sorting a list in increasing order. The longer the list, the longer it would take to sort; however, the increase in time is not exponential.
>- **NP (Non-deterministic Polynomial Time)**: Problems in the class NP are those for which a given solution can be checked quickly, even though finding the solution itself might be hard. In fact, we don’t know if there is a fast algorithm to find the solution in the first place.
>## **Where John Comes in**
>Even though the algorithm is not feasibly reversible, that doesn’t mean cracking the hashes is impossible. If you have the *hashed version of a password*, for example, and you know the *hashing algorithm*, you can use that hashing algorithm to hash a large number of words, called a *dictionary*. You can then compare these hashes to the one you’re trying to crack to see if they match. If they do, you know what word corresponds to that hash- you’ve cracked it!
>
>This process is called a **dictionary attack**, and John the Ripper, or John as it’s commonly shortened, is a tool for conducting fast *brute force attacks on various hash types*.
>
The most popular extended version of John the Ripper, **Jumbo John**.
>


> [!info] Setting up The System
> ## **Installation**
> **Other Linux Distributions**
>
Many Linux distributions have John the Ripper available for installation from their official repositories. For instance, on Fedora Linux, you can install John the Ripper with `sudo dnf install john`, while on Ubuntu, you can install it with `sudo apt install john`. Unfortunately, at the time of writing, these versions provided core functionality and missed some of the tools available through Jumbo John.
>
Consequently, you need to consider building from the source to access all the tools available via Jumbo John. The [official installation guide](https://github.com/openwall/john/blob/bleeding-jumbo/doc/INSTALL) provides detailed installation and build configuration instructions.
>
**Installing on Windows**
>
To install Jumbo John the Ripper on Windows, you need to download and install the zipped binary for either 64-bit systems [here](https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.zip) or for 32-bit systems [here](https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win32.zip).
>
**RockYou**
For all of the tasks in this room, we will use the infamous `rockyou.txt` wordlist, a very large common password wordlist obtained from a data breach on a website called rockyou.com in 2009. If you are not using any of the above distributions, you can get the `rockyou.txt` wordlist from the [SecLists](https://github.com/danielmiessler/SecLists) repository under the `/Passwords/Leaked-Databases` subsection. You may need to extract it from the `.tar.gz` format using `tar xvzf rockyou.txt.tar.gz`.
> 


> [!info] Cracing Basic Hashes
> ## **John Basic Syntax**
> `john [options] [file path]`
>
>- `john`: Invokes the John the Ripper program
>- `[options]`: Specifies the options you want to use
>- `[file path]`: The file containing the hash you’re trying to crack; if it’s in the same directory, you won’t need to name a path, just the file.
>## **Automatic Cracking**
>`john --wordlist=[path to wordlist] [path to file]`
>
>- `--wordlist=`: Specifies using wordlist mode, reading from the file that you supply in the provided path
>- `[path to wordlist]`: The path to the wordlist you’re using, as described in the previous task
>
**Example Usage:**
>
`john --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt`
>## **Identifying Hashes**
>o use hash-identifier, you can use `wget` or `curl` to download the Python file `hash-id.py` from its GitLab [page](https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py). Then, launch it with `python3 hash-id.py` and enter the hash you’re trying to identify. It will give you a list of the most probable formats. These two steps are shown in the terminal below.
>![[Pasted image 20250228175455.png]]
>## **Format-Specific Cracking**
>Once you have identified the hash that you’re dealing with, you can tell John to use it while cracking the provided hash using the following syntax:
>
`john --format=[format] --wordlist=[path to wordlist] [path to file]`
>
>- `--format=`: This is the flag to tell John that you’re giving it a hash of a specific format and to use the following format to crack it
>- `[format]`: The format that the hash is in
>
**Example Usage:**
>
`john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt`
>
**A Note on Formats:**
>
When you tell John to use formats, if you’re dealing with a standard hash type, e.g. md5 as in the example above, you have to prefix it with `raw-` to tell John you’re just dealing with a standard hash type, though this doesn’t always apply. To check if you need to add the prefix or not, you can list all of John’s formats using `john --list=formats` and either check manually or grep for your hash type using something like `john --list=formats | grep -iF "md5"`.



> [!Cracking Windows Authentication hashes] Cracking Windows Authentication Hashes
> ## **NTHash / NTLM**
> NThash is the hash format modern Windows operating system machines use to store user and service passwords. It’s also commonly referred to as NTLM, which references the previous version of Windows format for hashing passwords known as LM, thus NT/LM.
> n Windows, SAM (*Security Account Manager*) is used to store *user account information*, including usernames and hashed passwords. You can acquire NTHash/NTLM hashes by *dumping the SAM database on a Windows machine*, using a tool like Mimikatz, or using the Active Directory database: `NTDS.dit`
> 


> [!Cracking Hashes from /etc/shadow] Cracking Hashes from /etc/shadow
>The `/etc/shadow` file is the file on Linux machines where password hashes are stored.
>## **Unshadowing**
>`unshadow [path to passwd] [path to shadow]`
>- `unshadow`: Invokes the unshadow tool
>- `[path to passwd]`: The file that contains the copy of the `/etc/passwd` file you’ve taken from the target machine
>- `[path to shadow]`: The file that contains the copy of the `/etc/shadow` file you’ve taken from the target machine
>
> **Example usage**:
>  - `unshadow local_passwd local_shadow > unshadowed.txt`
>**Note on the files**
>
When using `unshadow`, you can either use the entire `/etc/passwd` and `/etc/shadow` files, assuming you have them available, or you can use the relevant line from each, for example:
>
**FILE 1 - local_passwd**
>
Contains the `/etc/passwd` line for the root user:
>
`root:x:0:0::/root:/bin/bash`
>
**FILE 2 - local_shadow**
>
Contains the `/etc/shadow` line for the root user: `root:$6$2nwjN454g.dv4HN/$m9Z/r2xVfweYVkrr.v5Ft8Ws3/YYksfNwq96UL1FX0OJjY1L6l.DS3KEVsZ9rOVLB/ldTeEL/OIhJZ4GMFMGA0:18576::::::`
> ## **Cracking**
> We can then feed the output from `unshadow`, in our example use case called `unshadowed.txt`, directly into John. We should not need to specify a mode here as we have made the input specifically for John; however, in some cases, you will need to specify the format as we have done previously using: `--format=sha512crypt`
> 
>  `john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt`
> 


> [!Single crack mode] Single Crack Mode
> John also has another mode, called the **Single Crack** mode. In this mode, John uses only the information provided in the username to try and work out possible passwords heuristically by slightly changing the letters and numbers contained within the username.
> ## **Word Mangling**
> he best way to explain Single Crack mode and word mangling is to go through an example:
>
Consider the username “Markus”.
>
Some possible passwords could be:
>		
>- Markus1, Markus2, Markus3 (etc.)
>- MArkus, MARkus, MARKus (etc.)
>- Markus!, Markus$, Markus* (etc.)
>## **GECOS**  
>(GECOS stands for General Electric Comprehensive Operating System)
> The fifth field in the user account record is the GECOS field. It *stores general information about the user*, such as the user’s full name, office number, and telephone number, among other things.
>## **Using Single Crack Mode**
>`john --single --format=[format] [path to file]`
>
>- `--single`: This flag lets John know you want to use the single hash-cracking mode
>- `--format=[format]`: As always, it is vital to identify the proper format.
>
**Example Usage:**
`john --single --format=raw-sha256 hashes.txt`
>
**A Note on File Formats in Single Crack Mode:**
If you’re cracking hashes in single crack mode, you need to change the file format that you’re feeding John for it to understand what data to create a wordlist from. You do this by prepending the hash with the username that the hash belongs to, so according to the above example, we would change the file `hashes.txt`
>
**From** `1efee03cdcb96d90ad48ccc7b8666033`
>
**To** `mike:1efee03cdcb96d90ad48ccc7b8666033`
>## **Practical**
>
Now that you’re familiar with the Syntax for John’s single crack mode, access the hash and crack it, assuming that the user it belongs to is called “Joker”. The file is located in `~/John-the-Ripper-The-Basics/Task07/`.


> [!Custom Rules] Custom Rules
> ## **What are Custom Rules**
> The good news is that you can define your rules, which John will use to create passwords dynamically. The ability to define such rules is beneficial when you know more information about the password structure of whatever your target is.
> ## **Common Custom Rules**
> Many organisations will require a certain level of password complexity to try and combat dictionary attacks. In other words, when creating a new account or changing your password, if you attempt a password like `polopassword`, it will most likely not work. The reason would be the enforced password complexity. As a result, you may receive a prompt telling you that passwords have to contain at least one character from each of the following:
>
>- Lowercase letter
>- Uppercase letter
>- Number
>- Symbol
>## **How to create Custom Rules**
>Let’s go over the syntax of these custom rules, using the example above as our target pattern. Note that you can define a massive level of granular control in these rules. I suggest looking at the wiki [here](https://www.openwall.com/john/doc/RULES.shtml) to get a full view of the modifiers you can use and more examples of rule implementation.
>`[List.Rules:THMRules]` is used to define the name of your rule; this is what you will use to call your custom rule a John argument.
>We then use a regex style pattern match to define where the word will be modified; again, we will only cover the primary and most common modifiers here:
>
>- `Az`: Takes the word and appends it with the characters you define
>- `A0`: Takes the word and prepends it with the characters you define
>- `c`: Capitalises the character positionally
>Lastly, we must define what characters should be appended, prepended or otherwise included. We do this by adding character sets in square brackets `[ ]` where they should be used. These follow the modifier patterns inside double quotes `" "`. Here are some common examples:
>
>- `[0-9]`: Will include numbers 0-9  
 >   
>- `[0]`: Will include only the number 0
>- `[A-z]`: Will include both upper and lowercase  
 >   
>- `[A-Z]`: Will include only uppercase letters
>- `[a-z]`: Will include only lowercase letters
>## **Using Custom Rules**
>We could then call this custom rule a John argument using the  `--rule=PoloPassword` flag
>As a full command: `john --wordlist=[path to wordlist] --rule=PoloPassword [path to file]`


> [!Cracking Password Protected Zip File] Cracking Password Protected Zip File
> Yes! You read that right. We can use John to crack the password on password-protected Zip files. Again, *we’ll use a separate part of the John suite* of tools to convert the Zip file into a format that John will understand, but we’ll use the syntax you’re already familiar with for all intents and purposes.
> ## **Zip2John**
> Similarly to the `unshadow` tool we used previously, we will use the `zip2john` tool to convert the Zip file into a hash format that John can understand and hopefully crack. The primary usage is like this:
>
`zip2john [options] [zip file] > [output file]`
>
>- `[options]`: Allows you to pass specific checksum options to `zip2john`; this shouldn’t often be necessary
>- `[zip file]`: The path to the Zip file you wish to get the hash of
>- `>`: This redirects the output from this command to another file
>- `[output file]`: This is the file that will store the output
>
**Example Usage**
>
`zip2john zipfile.zip > zip_hash.txt`
> ## **Cracking**
> We’re then able to take the file we output from `zip2john` in our example use case, `zip_hash.txt`, and, as we did with `unshadow`, feed it directly into John as we have made the input specifically for it.
>
`john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash.txt`
>## **Practical**
>
Now, have a go at cracking a “secure” Zip file! The file is located in `~/John-the-Ripper-The-Basics/Task09/`.


> [!Cracking Password Protecting RAR Archive] Cracking Password Protecting RAR Archive
> ## **Cracking a Password-Protected RAR Archive**
> We can use a similar process to the one we used in the last task to obtain the password for RAR archives. If you aren’t familiar, RAR archives are compressed files created by the WinRAR archive manager. Like Zip files, they compress folders and files.
> ## **Rar2John**
> Almost identical to the `zip2john` tool, we will use the `rar2john` tool to convert the RAR file into a hash format that John can understand. The basic syntax is as follows:
> `rar2john [rar file] > [output file]`
> - `rar2john`: Invokes the `rar2john` tool
>- `[rar file]`: The path to the RAR file you wish to get the hash of
>- `>`: This redirects the output of this command to another file
>- `[output file]`: This is the file that will store the output from the command     
>
**Example Usage**
>
`/opt/john/rar2john rarfile.rar > rar_hash.txt`
>## **Cracking**
>Once again, we can take the file we output from `rar2john` in our example use case, `rar_hash.txt`, and feed it directly into John as we did with `zip2john`.
>
`john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt`
>
>## Practical
>
Now, have a go at cracking a “secure” RAR file! The file is located in `~/John-the-Ripper-The-Basics/Task10/`.
> `unrar x secure_rar` : for unraring the file after decrypting the hash 


> [!Cracking SSH Keys with John] Cracking SSH Keys with John
> ## **Cracking SSH Key Password**
> Okay, okay, I hear you. There are no more file archives! Fine! Let’s explore one more use of John that comes up semi-frequently in CTF challenges—using John to crack the SSH private key password of `id_rsa` files. Unless configured otherwise, you authenticate your SSH login using a password. However, you can configure key-based authentication, which lets you use your private key, `id_rsa`, as an authentication key to log in to a remote machine over SSH. However, doing so will often require a password to access the private key; here, we will be using John to crack this password to allow authentication over SSH using the key.
> ## **SSH2John**
> Who could have guessed it, another conversion tool? Well, that’s what working with John is all about. As the name suggests, `ssh2john` converts the `id_rsa` private key, which is used to log in to the SSH session, into a hash format that John can work with. Jokes aside, it’s another beautiful example of John’s versatility. The syntax is about what you’d expect. Note that if you don’t have `ssh2john` installed, you can use `ssh2john.py`, located in the `/opt/john/ssh2john.py`. If you’re doing this on the AttackBox, replace the `ssh2john` command with `python3 /opt/john/ssh2john.py` or on Kali, `python /usr/share/john/ssh2john.py`.
>
`ssh2john [id_rsa private key file] > [output file]`
>
>- `ssh2john`: Invokes the `ssh2john` tool
>- `[id_rsa private key file]`: The path to the id_rsa file you wish to get the hash of
>- `>`: This is the output director. We’re using it to redirect the output from this command to another file.
>- `[output file]`: This is the file that will store the output from
>
**Example Usage**
>
`/opt/john/ssh2john.py id_rsa > id_rsa_hash.txt`
> ## **Cracking**
> For the final time, we’re feeding the file we output from ssh2john, which in our example use case is called `id_rsa_hash.txt` and, as we did with `rar2john`, we can use this seamlessly with John:
>
`john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_hash.txt`
>
>## **Practical**
>
Now, I’d like you to crack the hash of the `id_rsa` file relevant to this task! The file is located in `~/John-the-Ripper-The-Basics/Task11/`
