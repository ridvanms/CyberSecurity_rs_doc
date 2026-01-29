[[🔐Cryptography Basic]]
> [!Introduction] Introduction
> ## Learning Objectives
>
Upon completing this room, you will learn the following:
>- Cryptography key terms
>- Importance of cryptography
>- Caesar Cipher
>- Standard symmetric ciphers
>- Common asymmetric ciphers
>- Basic mathematics commonly used in cryptography


> [!Importance of Cryptography ] Importance of Cryptography
> Cryptography is used to protect confidentiality, integrity, and authenticity. In this age, you use cryptography daily, and you’re almost certainly reading this over an encrypted connection. Consider the following scenarios where you would use cryptography:
>
>- When you log in to TryHackMe, your credentials are encrypted and sent to the server so that no one can retrieve them by snooping on your connection.
>- When you connect over SSH, your SSH client and the server establish an encrypted tunnel so no one can eavesdrop on your session.
>- When you conduct online banking, your browser checks the remote server’s certificate to confirm that you are communicating with your bank’s server and not an attacker’s.
>- When you download a file, how do you check if it was downloaded correctly? Cryptography provides a solution through hash functions to confirm that your file is identical to the original one.
>
>##### *When handling credit cards, the company must follow and enforce the Payment Card Industry Data Security Standard (PCI DSS)*
> [PCI DSS for Large Organizations](https://www.pcisecuritystandards.org/documents/PCI_DSS_for_Large_Organizations_v1.pdf)


> [!Plaintext to Cliphertext] Plaintext to Clliphertext
> The plaintext is passed through the encryption function along with a proper key; the encryption function returns a ciphertext. The encryption function is part of the cipher; a cipher is an algorithm to convert a plaintext into a ciphertext and vice versa.
![[5f04259cf9bf5b57aed2c476-1725293744539.svg]]
To recover the plaintext, we must pass the ciphertext along with the proper key via the decryption function, which would give us the original plaintext. This is shown in the illustration below.
![[5f04259cf9bf5b57aed2c476-1725293763258.svg]]
>- **Plaintext** is the original, readable message or data before it’s encrypted. It can be a document, an image, a multimedia file, or any other binary data.
>- **Ciphertext** is the scrambled, unreadable version of the message after encryption. Ideally, we cannot get any information about the original plaintext except its approximate size.
>- **Cipher** is an algorithm or method to convert plaintext into ciphertext and back again. A cipher is usually developed by a mathematician.
>- **Key** is a string of bits the cipher uses to encrypt or decrypt data. In general, the used cipher is public knowledge; however, the key must remain secret unless it is the public key in asymmetric encryption. We will visit asymmetric encryption in a later task.
>- **Encryption** is the process of converting plaintext into ciphertext using a cipher and a key. Unlike the key, the choice of the cipher is disclosed.
>- **Decryption** is the reverse process of encryption, converting ciphertext back into plaintext using a cipher and a key. Although the cipher would be public knowledge, recovering the plaintext without knowledge of the key should be impossible (infeasible).


> [!Historical Ciphers] Historical Ciphers
> However, one of the simplest historical ciphers is the Caesar Cipher from the first century BCE. The idea is simple: shift each letter by a certain number to encrypt the message.
> You would come across many more historical ciphers in movies and cryptography books. Examples include:
>
>- The Vigenère cipher from the 16th century
>- The Enigma machine from World War II
>- The one-time pad from the Cold War


> [!Types of encryption] Types of encryption
> ***The two main categories of encryption are symmetric and asymmetric***
> ## Symmetric Encryption
> **Symmetric encryption**, also known as **symmetric cryptography**, uses the same key to encrypt and decrypt the data
> 
> **Examples of symmetric encryption are DES (Data Encryption Standard), 3DES (Triple DES) and AES (Advanced Encryption Standard).**
>- **DES** was adopted as a standard in 1977 and uses a 56-bit key. With the advancement in computing power, in 1999, a DES key was successfully broken in less than 24 hours, motivating the shift to 3DES.
>- **3DES** is DES applied three times; consequently, the key size is 168 bits, though the effective security is 112 bits. 3DES was more of an ad-hoc solution when DES was no longer considered secure. 3DES was deprecated in 2019 and should be replaced by AES; however, it may still be found in some legacy systems.
>- **AES** was adopted as a standard in 2001. Its key size can be 128, 192, or 256 bits.
> ## Asymmetric Encryption
>  **asymmetric encryption** uses a pair of keys, one to encrypt and the other to decrypt, as shown in the illustration below. To protect confidentiality, asymmetric encryption or **asymmetric cryptography** encrypts the data using the public key; hence, it is also called **public key cryptography**.
>  
>  Examples are RSA, Diffie-Hellman, and Elliptic Curve cryptography (ECC). The two keys involved in the process are referred to as a **public key** and a **private key**. Data encrypted with the public key can be decrypted with the private key. Your private key needs to be kept private, hence the name.
> ## Summary of New Terms
>  - **Alice and Bob** are fictional characters commonly used in cryptography examples to represent two parties trying to communicate securely. **Symmetric encryption** is a method in which the same key is used for both encryption and decryption. Consequently, this key must remain secure and never be disclosed to anyone except the intended party. **Asymmetric encryption** is a method that uses two different keys: a public key for encryption and a private key for decryption.


> [!Basic math] Basic math
> ## XOR Operation
> XOR, short for “exclusive OR”, is a logical operation in binary arithmetic that plays a crucial role in various computing and cryptographic applications.
> 
|A|B|A ⊕ B|
|---|---|---|
|0|0|0|
|0|1|1|
|1|0|1|
|1|1|0|
>## Modulo Operation
>Another mathematical operation we often encounter in cryptography is the modulo operator, commonly written as % or as _m__o__d_. The modulo operator, _X_%_Y_, is the **remainder** when X is divided by Y. In our daily life calculations, we focus more on the result of division than on the remainder. The remainder plays a significant role in cryptography
>Let’s consider a few examples.
>
>- 25%5 = 0 because 25 divided by 5 is 5, with a remainder of 0, i.e., 25 = 5 × 5 + 0
>- 23%6 = 5 because 23 divided by 6 is 3, with a remainder of 5, i.e., 23 = 3 × 6 + 5
>- 23%7 = 2 because 23 divided by 7 is 3 with a remainder of 2, i.e., 23 = 3 × 7 + 2
>
An important thing to remember about modulo is that it’s not reversible. If we are given the equation _x_%5 = 4, infinite values of _x_ would satisfy this equation.
>
>The modulo operation always returns a non-negative result less than the divisor. This means that for any integer _a_ and positive integer _n_, the result of _a_%_n_ will always be in the range 0 to _n_ − 1.
