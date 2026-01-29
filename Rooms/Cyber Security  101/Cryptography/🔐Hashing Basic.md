[[🔐Hashing Basic]]
![[Pasted image 20250225131157.png]]

*A **hash value** is a fixed-size string or characters that is computed by a hash function. A **hash function** takes an input of an arbitrary size and returns an output of fixed length, i.e., a hash value.*

What are:

- Hash functions and collisions
- The role of hashing in authentication systems
- Recognizing stored hash values
- Cracking hash values
- The use of hashing for integrity protection


> [!info] Hash Functions
> Hash functions are different from encryption. There is no key, and it’s meant to be impossible (or computationally impractical) to go from the output back to the input.
>Let’s check an example. In the terminal below, we can see two files; the first contains the letter T, while the second contains the letter U. If you check T and U in an ASCII table or using `hexdump`, you will notice that the two letters differ by a single bit.
>
>- The letter T is `54` in hexadecimal, i.e., `01010100` in binary.
>- The letter U is `55` in hexadecimal, i.e., `01010101` in binary.
>`sha256sum *.txt` 
> e632b7095b0bf32c260fa4c539e9fd7b852d0de454e9be26f24d0d6f91d069d3 file1.txt 
>a25513c7e0f6eaa80a3337ee18081b9e2ed09e00af8531c8f7bb2542764027e7 file2.txt
>### **Why is Hashing Important**
>Hashing plays a vital role in our daily use of the Internet. Like other cryptographic functions, hashing remains hidden from the user. Hashing helps protect data’s integrity and ensure password confidentiality.
>### **What’s a Hash Collision**
>A hash collision is when two different inputs give the same output. **H*ash functions are designed to avoid collisions as best as possible**.* Furthermore, hash functions are designed to prevent an attacker from being able to create, i.e., engineer, a collision intentionally. However, because ***the number of inputs is practically unlimited and the number of possible outputs is limited***, this leads to a pigeonhole effect.
>
>As a *numeric example*, if a hash *function* produces a 4-bit hash value, we only have 16 different hash values. The total number of possible hash values is 2_n__u__m__b__e__r___o__f___b__i__t__s_ = 24 = 16. The probability of a collision is relatively very high.
>
>The **pigeonhole effect** states that the number of items (_pigeons_) is more than the number of containers (_pigeonholes_
>
>
>



> [!Insecure Password Storage for Authentication] **Insecure Password Storage for Authentication**
> Hashing has many uses in Cyber Security.We will focus on two uses:
> - password storage
> - data integrity
> ### **Stories of Insecure Password Storage for Authentication**
> 
> Most web applications need to verify a user’s password at some point. **Storing these passwords in plaintext is a very insecure security practice**. You’ve probably seen news stories about companies that have had their database leaked. Knowing that many people use the same password on their various accounts, including their online banking, leaking the password from one account jeopardises the security of all other accounts.
> 
> We will visit **three insecure practices** when it comes to passwords:
>
>- Storing passwords in plaintext
>- Storing passwords using a deprecated encryption
>- Storing passwords using an insecure hashing algorithm
>#### **Using an Insecure Hash Function**
>
LinkedIn also suffered a data breach in 2012. LinkedIn used an insecure hashing algorithm, the SHA-1, to store user passwords. Furthermore, no password salting was used. **Password salting** refers to adding a **salt**, i.e., a random value, to the password before it is hashed
>
> The 20 values in a text: `head -n 20 rockyou.txt`


> [!### Using Hashing to Store Passwords] **Using Hashing to Store Passwords**
> This is where **hashing** comes in. What if, instead of storing the password, you just stored its **hash value** using a secure **hashing function**? This process means you never have to store the user’s password, and if your database is leaked, an attacker will have to crack each password to find out what the password was.
>
>There’s just one problem with this. What if two users have the same password? As a hash function will always turn the same input into the same output, you will store the same password hash for each user. That means if someone cracks that hash, they gain access to more than one account. It also means someone can create a **Rainbow Table** to break the hashes.
>
>A **Rainbow Table** is a lookup table of hashes to plaintexts, so you can quickly find out what password a user had just from the hash. A rainbow table trades the time to crack a hash for hard disk space, but it takes time to create. Here’s a quick example to get an idea of what a rainbow table looks like.
>### **Protecting Against Rainbow Tables**
>o protect against rainbow tables, we add a salt to the passwords. The salt is a randomly generated value stored in the database and should be unique to each user.
>### **Example of Securely Storing Passwords**
>1. We select a secure hashing function, such as Argon2, Scrypt, Bcrypt, or PBKDF2.
>2. We add a unique salt to the password, such as `Y4UV*^(=go_!` 
>3. Concatenate the password with the unique salt. For example, if the password is `AL4RMc10k`, the result string would be `AL4RMc10kY4UV*^(=go_!`
>4. Calculate the hash value of the combined password and salt. In this example, using the chosen algorithm, you need to calculate the hash value of `AL4RMc10kY4UV*^(=go_!`.
>5. Store the hash value and the unique salt used (`Y4UV*^(=go_!`).
>### **Using Encryption to Store Passwords**
>Considering the problem of saving passwords for authentication, why don’t we encrypt passwords instead of all these cumbersome steps? The reason is that even if we select a secure hashing algorithm to encrypt the passwords before storing them, we still need to store the used key. Consequently, if someone gets the key, they can easily decrypt all the passwords.
>


> [!Recognizing password hashes] **Recognizing password hashes**
> Automated hash recognition tools such as [hashID](https://pypi.org/project/hashID/) exist but are unreliable for many formats. For hashes that have a prefix, the tools are reliable. Use a healthy combination of context and tools.  If you find the hash in a web application database, it’s more likely to be MD5 than NTLM (NT LAN Manager). Automated hash recognition tools often get these hash types mixed up, highlighting the importance of learning yourself.
> ### **Linux Passwords**
> On Linux, password hashes are stored in `/etc/shadow`, which is normally only readable by root. They used to be stored in `/etc/passwd`, which was readable by everyone.
> 
|Prefix|Algorithm|
|---|---|
|`$y$`|yescrypt is a scalable hashing scheme and is the default and recommended choice in new systems|
|`$gy$`|gost-yescrypt uses the GOST R 34.11-2012 hash function and the yescrypt hashing method|
|`$7$`|scrypt is a password-based key derivation function|
|`$2b$`, `$2y$`, `$2a$`, `$2x$`|bcrypt is a hash based on the Blowfish block cipher originally developed for OpenBSD but supported on a recent version of FreeBSD, NetBSD, Solaris 10 and newer, and several Linux distributions|
|`$6$`|sha512crypt is a hash based on SHA-2 with 512-bit output originally developed for GNU libc and commonly used on (older) Linux systems|
|`$md5`|SunMD5 is a hash based on the MD5 algorithm originally developed for Solaris|
|`$1$`|md5crypt is a hash based on the MD5 algorithm originally developed for FreeBSD|
>
>#### **Modern Linux Example**
>`sudo cat /etc/shadow | grep strategos`
>
>`strategos:$y$j9T$76UzfgEM5PnymhQ7TlJey1$/OOSg64dhfF.TigVPdzqiFang6uZA4QA1pzzegKdVm4:19965:0:99999:7:::`
>
>The fields are separated by colons. The important ones are the username and the hash algorithm, salt, and hash value. The second field has the format `$prefix$options$salt$hash`.
>In the example above, we have four parts separated by `$`:
>
>- `y` indicates the hash algorithm used, **yescrypt**
>- `j9T` is a parameter passed to the algorithm
>- `76UzfgEM5PnymhQ7TlJey1` is the salt used
>- `/OOSg64dhfF.TigVPdzqiFang6uZA4QA1pzzegKdVm4` is the hash value
>### **MS Windows Passwords**
>*MS Windows passwords are hashed using NTLM*, a variant of MD4. They’re visually identical to MD4 and MD5 hashes, so it’s very important to use context to determine the hash type.
>
>On *MS Windows, password hashes are stored in the SAM (Security Accounts Manager).* MS Windows tries to prevent normal users from dumping them, but tools like mimikatz exist to circumvent MS Windows security. Notably, the hashes found there are split into NT hashes and LM hashes.
>
>A great place to find more hash formats and password prefixes is the [Hashcat Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) page.
>


> [!Password Cracking] **Password Cracking**
> We’ve already mentioned rainbow tables as a method to crack hashes that don’t use a salt, but what if there’s a salt involved?
> 
>You can’t “decrypt” password hashes. They’re not encrypted. You have to crack the hashes by hashing many different inputs (such as `rockyou.txt` as it covers many possible passwords), potentially adding the *salt* if there is one and comparing it to the target hash. Once it matches, you know what the password was. Tools like [Hashcat](https://hashcat.net/hashcat/) and [John the Ripper](https://www.openwall.com/john/) are commonly used for these purposes.
>
>### **Cracking Passwords with GPUs**
>Modern GPUs (Graphics Processing Units) have thousands of cores. They are *specialised in digital image processing* and *accelerating computer graphics*. Although they can’t do the same sort of work that a CPU can, they are *very good at some mathematical calculations involved in hash functions*. You can use a graphics card to crack many hash types quickly. Some hashing algorithms, such as *Bcrypt*, are designed so that hashing on a GPU does not provide any speed improvement over using a CPU; this helps them resist cracking.
>
>### **Cracking on VMs**?
>It’s worth mentioning that VMs (Virtual Machines) normally don’t have access to the host’s graphics card(s).
>
>If you want to run [Hashcat](https://hashcat.net/hashcat/), it’s best to *run it on your host* to make the most of your GPU, if available. *If you prefer MS Windows, you are in luck*; MS Windows builds are available on the website, and *you can run it from PowerShell*. You can get *Hashcat working with OpenCL in a VM*, but the speeds will likely be worse than cracking on your host.
>
>[John the Ripper](https://www.openwall.com/john/) *uses CPU by default* and works in a VM out of the box, although you may get better speeds running it on the host OS to avoid any virtualisation overhead and make the most of your CPU cores and threads.
>
>### **Time to Crack Some Hashes**
>Hashcat uses the following basic syntax: `hashcat -m <hash_type> -a <attack_mode> hashfile wordlist`, where:
>- `-m <hash_type>` specifies the hash-type in numeric format. For example, `-m 1000` is for NTLM. Check the official documentation (`man hashcat`) and [example page](https://hashcat.net/wiki/doku.php?id=example_hashes) to find the hash type code to use.
>- `-a <attack_mode>` specifies the attack-mode. For example, `-a 0` is for straight, i.e., trying one password from the wordlist after the other.
>- `hashfile` is the file containing the hash you want to crack.
>- `wordlist` is the security word list you want to use in your attack.
>
>For example, `hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt` will treat the hash as Bcrypt and try the passwords in the `rockyou.txt` file.
>


> [!Hashing for integrity checking] **Hashing for integrity checking**
> ### **Integrity Checking**
> Even if a single bit changes, the hash will change significantly.This means you can use it to check that files haven’t been modified or to ensure that the file you downloaded is identical to the file on the web server.
> 
> he text file listed below shows the SHA256 hash of two Fedora Workstation ISO files.
> `head Fedora-Workstation-40-1.14-x86_64-CHECKSUM`
> ### **HMACs**
> **HMAC (Keyed-Hash Message Authentication Code)** is a type of message authentication code (MAC) that uses a cryptographic hash function in combination with a secret key to verify the authenticity and integrity of data.
> The following steps give you a fair idea of how HMAC works.
>
>1. The secret key is padded to the block size of the hash function.
>2. The padded key is XORed with a constant (usually a block of zeros or ones).
>3. The message is hashed using the hash function with the XORed key.
>4. The result from Step 3 is then hashed again with the same hash function but using the padded key XORed with another constant.
>5. The final output is the HMAC value, typically a fixed-size string.
> 
![[5f04259cf9bf5b57aed2c476-1725294564965.svg]]


> [!Conclution] Conclution
> **Hashing**, as already stated, is a process that *takes input data and produces a hash value*, a fixed-size string of characters, also referred to as digest. This hash value uniquely represents the data, and any change in the data, no matter how small, should lead to a change in the hash value. *Hashing should not be confused with encryption or encoding*; *hashing is one-way, and you can’t reverse the process to get the original data*.
> **Encoding** converts data from one form to another to make it compatible with a specific system. *ASCII*, *UTF-8*, *UTF-16*, *UTF-32*, *ISO-8859-1*, and *Windows-1252* are valid *encoding methods* for the English language. *Note that UTF-8, UTF-16, and UTF-32 are Unicode encodings*, and they can represent characters from other languages, such as Arabic and Japanese
> 
> Another type of encoding commonly used when sending or saving data is not for any specific language. Examples include *Base32* and *Base64* encoding. Consider the following example of using `base64` to encode and decode.
> 
>*Encoding should not be confused with encryption*, as using a specific encoding does not protect the confidentiality of the message. *Encoding is reversible; anyone can change the data encoding with the right tools*.
>
>Use `base64` to decode `RU5jb2RlREVjb2RlCg==`, saved as `decode-this.txt` in `~/Hashing-Basics/Task-8`. What is the original word?
>
>`cat decode-this.txt | base64 -d`

