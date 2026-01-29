Within this room, we will look at [OWASP's TOP 10 vulnerabilities](https://owasp.org/www-project-top-ten/) in web applications. You will find these in all types of web applications. But for today we will be looking at OWASP's own creation, Juice Shop!

![](https://assets.tryhackme.com/additional/imgur/vjfcwid.png)

_The **FREE** Burpsuite rooms '[Burpsuite Basics](https://tryhackme.com/room/burpsuitebasics)'  and '[Burpsuite Repeater](https://tryhackme.com/room/burpsuiterepeater)'  are recommended before completing this room!  
__~_

Juice Shop is a large application so we will not be covering every topic from the top 10.

We will, however, cover the following topics which we recommend you take a look at as you progress through this room.

<------------------------------------------------->

[Injection](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)

[Broken Authentication](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication)

[Sensitive Data Exposure](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)

[Broken Access Control](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A5-Broken_Access_Control)

[Cross-Site Scripting XSS](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_\(XSS\))

<------------------------------------------------->

**PLEASE NOTE!**

# Inject the juice

![](https://assets.tryhackme.com/additional/imgur/uwXqDdH.png)  

This task will be focusing on injection vulnerabilities. Injection vulnerabilities are quite dangerous to a company as they can potentially cause downtime and/or loss of data. Identifying injection points within a web application is usually quite simple, as most of them will return an error. There are many types of injection attacks, some of them are:

|   |   |
|---|---|
|SQL Injection|SQL Injection is when an attacker enters a malicious or malformed query to either retrieve or tamper data from a database. And in some cases, log into accounts.|
|Command Injection|Command Injection is when web applications take input or user-controlled data and run them as system commands. An attacker may tamper with this data to execute their own system commands. This can be seen in applications that perform misconfigured ping tests.|
|Email Injection|Email injection is a security vulnerability that allows malicious users to send email messages without prior authorization by the email server. These occur when the attacker adds extra data to fields, which are not interpreted by the server correctly.|

  

But in our case, we will be using **SQL Injection**.

For more information: [Injection](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)

Answer the questions below

Question #1: Log into the administrator account!

After we navigate to the login page, enter some data into the email and password fields.

![](https://assets.tryhackme.com/additional/imgur/4XHHSof.png)

 Before clicking submit, make sure Intercept mode is on.

This will allow us to see the data been sent to the server!

![](https://assets.tryhackme.com/additional/imgur/6gyZ7Vr.png)  

We will now change the "**a**" next to the email to: ' or 1=1-- and forward it to the server.

![](https://assets.tryhackme.com/additional/imgur/tPFJnmC.png)

**Why does this work?**

1. The character **'** will close the brackets in the SQL query
2. '**OR**' in a SQL statement will return true if either side of it is true. As 1=1 is always true, the whole statement is true. Thus it will tell the server that the email is valid, and log us into user id 0, which happens to be the administrator account.
3. The -- character is used in SQL to comment out data, any restrictions on the login will no longer work as they are interpreted as a comment. This is like the # and // comment in python and javascript respectively.


# Who broke my lock?
In this task, we will look at exploiting authentication through different flaws. When talking about flaws within authentication, we include mechanisms that are vulnerable to manipulation. These mechanisms, listed below, are what we will be exploiting. 

Weak passwords in high privileged accounts

Forgotten password pages

 More information: [Broken Authentication](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication)

Answer the questions below

Question #1: Bruteforce the Administrator account's password!

We have used SQL Injection to log into the Administrator account but we still don't know the password. Let's try a brute-force attack! We will once again capture a login request, but instead of sending it through the proxy, we will send it to Intruder.

Go to Positions and then select the Clear § button. In the password field place two § inside the quotes. To clarify, the § § is not two sperate inputs but rather Burp's implementation of quotations e.g. "". The request should look like the image below. 

![](https://assets.tryhackme.com/additional/imgur/I96sO28.png)  

For the payload, we will be using the best1050.txt from Seclists. (Which can be installed via: **apt-get install seclists**)

_You can load the list from:_ _/usr/share/wordlists/SecLists/Passwords/Common-Credentials/best1050.txt_

Once the file is loaded into Burp, start the attack. You will want to filter for the request by status.

A failed request will receive a 401 Unauthorized   

Whereas a successful request will return a 200 OK. 

Once completed, login to the account with the password.

# AH! Don't look!
We will now go back to the path folder and try to download package.json.bak. But it seems we are met with a 403 which says that only .md and .pdf files can be downloaded. 

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/654be36872552158be01f92f/room-content/654be36872552158be01f92f-1750888802937.png)  

To get around this, we will use a character bypass called "Poison Null Byte". A Poison Null Byte looks like this: _%00_. 

Note: as we can download it using the url, we will need to encode this into a url encoded format.

The Poison Null Byte will now look like this: _%2500._ Adding this and then a **.md** to the end will bypass the 403 error!

![](https://assets.tryhackme.com/additional/imgur/2qugsl5.png)

**Why does this work?** 

A Poison Null Byte is actually a NULL terminator. By placing a NULL character in the string at a certain byte, the string will tell the server to terminate at that point, nulling the rest of the string.

# Who's flying this thing?
Modern-day systems will allow for multiple users to have access to different pages. Administrators most commonly use an administration page to edit, add and remove different elements of a website. You might use these when you are building a website with programs such as Weebly or Wix.  

When Broken Access Control exploits or bugs are found, it will be categorised into one of **two types**:

|   |   |
|---|---|
|**Horizontal** Privilege Escalation|Occurs when a user can perform an action or access data of another user with the **same** level of permissions.|
|**Vertical** Privilege Escalation|Occurs when a user can perform an action or access data of another user with a higher level of permissions.|

  

![](https://assets.tryhackme.com/additional/imgur/bJ9WKY4.png)

_Credits: Packetlabs.net_

More information: [Broken Access Control](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A5-Broken_Access_Control)

# Where did that come from?
     
XSS or Cross-site scripting is a vulnerability that allows attackers to run javascript in web applications. These are one of the most found bugs in web applications. Their complexity ranges from easy to extremely hard, as each web application parses the queries in a different way. 

**There are three major types of XSS attacks:**

|   |   |
|---|---|
|DOM (Special)|DOM XSS _(Document Object Model-based Cross-site Scripting)_ uses the HTML environment to execute malicious javascript. This type of attack commonly uses the _<script></script>_ HTML tag.|
|Persistent (Server-side)|Persistent XSS is javascript that is run when the server loads the page containing it. These can occur when the server does not sanitise the user data when it is **uploaded** to a page. These are commonly found on blog posts.|
|Reflected (Client-side)|Reflected XSS is javascript that is run on the client-side end of the web application. These are most commonly found when the server doesn't sanitise **search** data.|

More information: [Cross-Site Scripting XSS](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_\(XSS\))

Question #1: Perform a DOM XSS!

![](https://assets.tryhackme.com/additional/imgur/AMz9jps.png)

We will be using the iframe element with a javascript alert tag: 
#### xss command:
`<iframe src="javascript:alert(`xss`)"> `

Inputting this into the **search bar** will trigger the alert.

![](https://assets.tryhackme.com/additional/imgur/rKEx3aR.png)

Note that we are using **iframe** which is a common HTML element found in many web applications, there are others which also produce the same result. 

This type of XSS is also called XFS (Cross-Frame Scripting), is one of the most common forms of detecting XSS within web applications.

Websites that allow the user to modify the iframe or other DOM elements will most likely be vulnerable to XSS.   

**Why does this work?**

It is common practice that the search bar will send a request to the server in which it will then send back the related information, but this is where the flaw lies. Without correct input sanitation, we are able to perform an XSS attack against the search bar. 

Correct Answer

Question #2: Perform a persistent XSS!  

First, login to the **admin** account.

We are going to navigate to the "**Last Login IP**" page for this attack.

It should say the last IP Address is 0.0.0.0 or 10.x.x.x 

As it logs the 'last' login IP we will now logout so that it logs the 'new' IP.

Make sure that Burp **intercept is on**, so it will catch the logout request.

We will then head over to the Headers tab where we will add a new header:

|_True-Client-IP_|_<iframe src="javascript:alert(`xss`)">_|

Then forward the request to the server!  
When **signing back into the admin account** and navigating to the Last Login IP page again, we will see the XSS alert!

**Why do we have to send this Header?**

The _True-Client-IP_  header is similar to the _X-Forwarded-For_ header, both tell the server or proxy what the IP of the client is. Due to there being no sanitation in the header we are able to perform an XSS attack. 

Question #3: Perform a reflected XSS!

First, we are going to need to be on the right page to perform the reflected XSS!

**Login** into the **admin account** and navigate to the 'Order History' page. 
                       

From there you will see a "Truck" icon, clicking on that will bring you to the track result page. You will also see that there is an id paired with the order.   ![](https://assets.tryhackme.com/additional/imgur/kQdIKyL.png)

We will use the iframe XSS, <iframe src="javascript:alert(`xss`)">, in the place of the _5267-f73dcd000abcc353_

After submitting the URL, refresh the page and you will then get an alert saying XSS!


**Why does this work?**

The server will have a lookup table or database (depending on the type of server) for each tracking ID. As the 'id' parameter is not sanitised before it is sent to the server, we are able to perform an XSS attack.