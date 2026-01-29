[[🔐Public Key Cryptography Basics]]
![[Pasted image 20250223104052.png]]

---
- You can see and hear the other person. Consequently, it is easy to be sure of their identity. That’s ***==authentication==***, i.e., you are confirming the identity of who you are talking with.
- You can also confirm that what you are “hearing” is coming from your business partner. You can tell what words and sentences are coming from your business partner and what is coming from others. That’s **==authenticity==**, i.e., you verify that the message genuinely comes from a specific sender. Moreover, you know that what they are saying is reaching you, and there is no chance of anything changing the other party’s words across the table. That’s **==integrity==**, i.e., ensuring that the data has not been altered or tampered with.
- Finally, you can pick a seat away from the other customers and keep your voice low so that only your business partner can hear you. That’s **==confidentiality==**, i.e., only the authorised parties can access the data.


> [!Common Use of Asymmetric Encryption] Common Use of Asymmetric Encryption
> ### Analogy
>
Imagine you have a secret code for communicating and instructions for using the secret code. The question is how you can send these instructions to your friend without anyone else being able to read them. The answer is more straightforward than it seems; you could ask your friend for a lock. Only your friend has the key for this lock, and we’ll assume you have an indestructible box you can lock with it.
>
>If you send the instructions in a locked box to your friend, they can unlock it once it reaches them and read the instructions. After that, you can communicate using the secret code without the risk of people snooping.
>
In this metaphor, the secret code represents a symmetric encryption cipher and key, the lock represents the server’s public key, and the key represents the server’s private key.


> [!RSA] RSA
> *RSA is a public-key encryption algorithm that enables secure data transmission over insecure channels. With an insecure channel, we expect adversaries to eavesdrop on it.*
> ### The Math That Makes RSA Secure
> RSA is based on the mathematically difficult problem of factoring a large number. Multiplying two large prime numbers is a straightforward operation; however, finding the factors of a huge number takes much more computing power.
> ### Numerical Example
> Let’s revisit encryption, decryption, and key usage in asymmetric encryption. The public key is known to all correspondents and is used for encryption, while the private key is protected and used for decryption, as shown in the figure below.
>
![[5f04259cf9bf5b57aed2c476-1725294065881.svg]]
>1. Bob chooses two prime numbers: _p_ = 157 and _q_ = 199. He calculates _n_ = _p_ × _q_ = 31243.
>2. With _ϕ_(_n_) = _n_ − _p_ − _q_ + 1 = 31243 − 157 − 199 + 1 = 30888, Bob selects _e_ = 163 such that _e_ is relatively prime to _ϕ_(_n_); moreover, he selects _d_ = 379, where _e_ × _d_ = 1 mod _ϕ_(_n_), i.e., _e_ × _d_ = 163 × 379 = 61777 and 61777 mod 30888 = 1. The public key is (_n_,_e_), i.e., (31243,163) and the private key is $(n,d), i.e., (31243,379).
>3. Let’s say that the value they want to encrypt is _x_ = 13, then Alice would calculate and send _y_ = _x__e_ mod _n_ = 13163 mod 31243 = 16341.
>4. Bob will decrypt the received value by calculating _x_ = _y__d_ mod _n_ = 16341379 mod 31243 = 13. This way, Bob recovers the value that Alice sent.
>### RSA in CTFs



> [!### Diffie-Hellman Key Exchange] ### Diffie-Hellman Key Exchange
> **Key exchange** aims to establish a shared secret between two parties. It is a method that allows two parties to establish a shared secret over an insecure communication channel without requiring a pre-existing shared secret and without an observer being able to get this key. Consequently, this shared key can be used for symmetric encryption in subsequent communications
> 
![[5f04259cf9bf5b57aed2c476-1728439878360.svg]]
>Diffie-Hellman Key Exchange is often used alongside RSA public key cryptography


> [!SSH] SSH
> ### Authenticating the Server
> `ssh 10.10.244.173`
> n the above interaction, the SSH client confirms whether we recognise the server’s public key fingerprint. ED25519 is the public-key algorithm used for digital signature generation
> ### Authenticating the Client
> Now that we have confirmed that we are talking with the correct server, we need to identify ourselves and get authenticated. In many cases, SSH users are authenticated using usernames and passwords like you would log in to a physical machine. However, considering the inherent issues with passwords, this does not fall within the best security practices.
> 
> `ssh-keygen` is the program usually used to generate key pairs. It supports various algorithms, as shown on its manual page below.
> `man ssh-keygen`
> 
>Let’s generate a key pair with the default options:
>`ssh-keygen -t ed25519`
>#### SSH Private Keys
>Using tools like John the Ripper, you can attack an encrypted SSH key to attempt to find the passphrase, highlighting the importance of using a complex passphrase and keeping your private key private.
>
>The permissions must be set up correctly to use a private SSH key; otherwise, your SSH client will ignore the file with a warning. Only the owner should be able to read or write to the private key (`600` or stricter). `ssh -i privateKeyFileName user@host` is how you specify a key for the standard Linux OpenSSH client.
>
>The `~/.ssh` folder is the default place to store these keys for OpenSSH. The `authorized_keys` (note the US English spelling) file in this directory holds public keys that are allowed access to the server if key authentication is enabled


> [!Digital Signatures and Certificates ] Digital Signatures and Certificates 
> ### What’s a Digital Signature
> Digital signature is a way of to verify the authenticity and integrity of digital message or document.
> https://www.youtube.com/shorts/cisWTAA_Y0w
> ### Certificates: Prove Who You Are
> The web server has a certificate that says it is the real tryhackme.com. The certificates have a chain of trust, starting with a root CA (Certificate Authority). From install time, your device, operating system, and web browser automatically trust various root CAs. Certificates are trusted only when the Root CAs say they trust the organisation that signed them.


> [!PGP and GPG] PGP and GPG
> **PGP** stands for Pretty Good Privacy. It’s software that implements encryption for encrypting files, performing digital signing, and more. [GnuPG or GPG](https://gnupg.org/) is an open-source implementation of the OpenPGP standard
> *GPG is commonly used in email to protect the confidentiality of the email messages. Furthermore, it can be used to sign an email message and confirm its integrity.*
> 
> Below is an example of generating GPG.
> `gpg --full-gen-key`
> 
> You may need to use GPG to decrypt files in CTFs. With PGP/GPG, private keys can be protected with passphrases in a similar way that we protect SSH private keys. If the key is passphrase protected, you can attempt to crack it using John the Ripper and `gpg2john`
> ### Practi﻿cal Example
> Now that you have your GPG key pair, you can share the public key with your contacts. Whenever your contacts want to communicate securely, they encrypt their messages to you using your public key. To decrypt the message, you will have to use your private key. Due to the importance of the GPG keys, it is vital that you keep a backup copy in a secure location.
>
Let’s say you got a new computer. All you need to do is import your key, and you can start decrypting your received messages again:
>
>- You would use `gpg --import backup.key` to import your key from backup.key
>- To decrypt your messages, you need to issue `gpg --decrypt confidential_message.gpg`

---
## **Conclusion**
###### We have defined ***cryptography*** as the science of securing communication in the presence of adversaries. Another important science that studies how to break or bypass cryptographic systems is ***cryptanalysis***. As for trying every possible password combination, we call that a ***brute-force attack***. However, when we know that the password is most likely a dictionary word, it will make more sense to try words from a dictionary instead of every possible password combination; this is called a ***dictionary attack***.

###### - **Cryptography** is the science of securing communication and data using codes and ciphers.
###### - **Cryptanalysis** is the study of methods to break or bypass cryptographic security systems without knowing the key.
###### - **Brute-Force Attack** is an attack method that involves trying every possible key or password to decrypt a message.
###### - **Dictionary Attack** is an attack method where the attacker tries dictionary words or combinations of them.

###### This room focused on public key cryptography, asymmetric cryptography, and key exchange. It gave you an essential understanding of RSA, Diffie-Hellman, SSH key pairs, digital signatures and certificates, and OpenPGP. Now, it is time to learn about hashing.

