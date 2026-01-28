What is Data Exfiltration

Data Exfiltration is the process of taking an unauthorized copy of sensitive data and moving it from the inside of an organization's network to the outside. It is important to note that Data Exfiltration is a post-compromised process where a threat actor has already gained access to a network and performed various activities to get hands on sensitive data. Data Exfiltration often happens at the last stage of the Cyber Kill Chain model, Actions on Objectives.

![Cyber Kill Chain](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/5ed5961c6276df568891c3ea-1721309536895.png)  

Data exfiltration is also used to hide an adversary's malicious activities and bypass security products. For example, the DNS exfiltration technique can evade security products, such as a firewall.  

Sensitive data can be in various types and forms, and it may contain the following:

- Usernames and passwords or any authentication information.
- Bank accounts details
- Business strategic decisions.
- Cryptographic keys.
- Employee and personnel information.
- Project code data.

How to use Data Exfiltration

There are three primary use case scenarios of data exfiltration, including:

1. Exfiltrate data
2. Command and control communications.
3. Tunneling

**Traditional Data Exfiltration**

![Traditional Data Exifltration](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/0c3438995ccff35a5589b9abd3703b14.png)

The traditional Data Exfiltration scenario is moving sensitive data out of the organization's network. An attacker can make one or more network requests to transfer the data, depending on the data size and the protocol used. Note that a threat actor does not care about the reply or response to his request. Thus, all traffic will be in one direction, from inside the network to outside. Once the data is stored on the attacker's server, he logs into it and grabs the data.

**C2 Communications**

![C2 Communications](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/49ad248f2506a5a749dbb70732c32072.png)

Many C2 frameworks provide options to establish a communication channel, including standard and non-traditional protocols to send commands and receive responses from a victim machine. In C2 communications a limited number of requests where an attacker sends a request to execute a command in the victim's machine. Then, the agent's client executes the command and sends a reply with the result over a non-traditional protocol. The communications will go in two directions: into and out of the network.

**Tunneling**

![Tunneling communication](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/b4c99b2aba13eac24379fee2d20ffbf6.png)  

In the Tunneling scenario, an attacker uses this data exfiltration technique to establish a communication channel between a victim and an attacker's machine. The communication channel acts as a bridge to let the attacker machine access the entire internal network. There will be continuous traffic sent and received while establishing the connection.

In the coming tasks, we will discuss the following techniques and use cases:

- Exfiltrate using TCP socket and Base64
- Exfiltrate using SSH
- Exfiltrate using HTTPS (POST request)
- ICMP
- DNS