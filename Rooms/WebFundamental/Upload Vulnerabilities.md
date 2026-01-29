# Introduction 
The ability to upload files to a server has become an integral part of how we interact with web applications. Be it a profile picture for a social media website, a report being uploaded to cloud storage, or saving a project on Github; the applications for file upload features are limitless.

Unfortunately, when handled badly, file uploads can also open up severe vulnerabilities in the server. This can lead to anything from relatively minor, nuisance problems; all the way up to full Remote Code Execution (RCE) if an attacker manages to upload and execute a shell. With unrestricted upload access to a server (and the ability to retrieve data at will), an attacker could deface or otherwise alter existing content -- up to and including injecting malicious webpages, which lead to further vulnerabilities such as XSS or CSRF. By uploading arbitrary files, an attacker could potentially also use the server to host and/or serve illegal content, or to leak sensitive information. Realistically speaking, an attacker with the ability to upload a file of their choice to your server -- with no restrictions -- is very dangerous indeed.  

The purpose of this room is to explore some of the vulnerabilities resulting from improper (or inadequate) handling of file uploads. Specifically, we will be looking at:

- Overwriting existing files on a server
- Uploading and Executing Shells on a server  
    
- Bypassing Client-Side filtering
- Bypassing various kinds of Server-Side filtering
- Fooling content type validation checks

Completing the [web enumeration](https://tryhackme.com/room/webenumerationv2) (or at least the Gobuster section) and [What the Shell](https://tryhackme.com/room/introtoshells) rooms would be a good idea before attempting the content in this room.  

Let's begin!

# General Metrology 
So, we have a file upload point on a site. How would we go about exploiting it?

As with any kind of hacking, enumeration is key. The more we understand about our environment, the more we're able to _do_ with it. Looking at the source code for the page is good to see if any kind of client-side filtering is being applied. Scanning with a directory bruteforcer such as Gobuster is usually helpful in web attacks, and may reveal where files are being uploaded to; Gobuster is no longer installed by default on Kali, but can be installed with `sudo apt install gobuster`. Intercepting upload requests with [Burpsuite](https://tryhackme.com/room/burpsuitebasics) will also come in handy. Browser extensions such as [Wappalyser](https://www.wappalyzer.com/download) can provide valuable information at a glance about the site you're targetting.  

With a basic understanding of how the website might be handling our input, we can then try to poke around and see what we can and can't upload. If the website is employing client-side filtering then we can easily look at the code for the filter and look to bypass it (more on this later!). If the website has server-side filtering in place then we may need to take a guess at what the filter is looking for, upload a file, then try something slightly different based on the error message if the upload fails. Uploading files designed to provoke errors can help with this. Tools like Burpsuite or OWASP Zap can be very helpful at this stage.

We'll go into a lot more detail about bypassing filters in later tasks.

# Overwriting Existing Files
When files are uploaded to the server, a range of checks should be carried out to ensure that the file will not overwrite anything which already exists on the server. Common practice is to assign the file with a new name -- often either random, or with the date and time of upload added to the start or end of the original filename. Alternatively, checks may be applied to see if the filename already exists on the server; if a file with the same name already exists then the server will return an error message asking the user to pick a different file name. File permissions also come into play when protecting existing files from being overwritten. Web pages, for example, should not be writeable to the web user, thus preventing them from being overwritten with a malicious version uploaded by an attacker.

If, however, no such precautions are taken, then we might potentially be able to overwrite existing files on the server. Realistically speaking, the chances are that file permissions on the server will prevent this from being a serious vulnerability. That said, it could still be quite the nuisance, and is worth keeping an eye out for in a pentest or bug hunting environment.

Let's go through an example before you try this for yourself.

### ❗❗ Warning ❗❗

_Please note that_ `demo.uploadvulns.thm` _will be used for all demonstrations; however, **this site is not available in the uploaded VM**. It is purely for demonstrative purposes._

_Attempts to access this subdomain will have amusing consequences... you have been warned.  
_

In the following image we have a web page with an upload form:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e86dbbd98fde62929a7e03b/room-content/5e86dbbd98fde62929a7e03b-1759494686706.png)

You may need to enumerate more than this for a real challenge; however, in this instance, let's just take a look at the source code of the page:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e86dbbd98fde62929a7e03b/room-content/5e86dbbd98fde62929a7e03b-1759494769552.png)

Inside the red box, we see the code that's responsible for displaying the image that we saw on the page. It's being sourced from a file called "spaniel.jpg", inside a directory called "images".

Now we know where the image is being pulled from -- can we overwrite it?

Let's download another image from the internet and call it `spaniel.jpg`. We'll then upload it to the site and see if we can overwrite the existing image:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e86dbbd98fde62929a7e03b/room-content/5e86dbbd98fde62929a7e03b-1759495388389.png)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e86dbbd98fde62929a7e03b/room-content/5e86dbbd98fde62929a7e03b-1759495947155.png)

And our attack was successful! We managed to overwrite the original `images/spaniel.jpg` with our own copy.

---

Now, let's put this into practice.

Open your web browser and navigate to `overwrite.uploadvulns.thm`. Your goal is to overwrite a file on the server with an upload of your own.

# Remote Code Execution

_web Shells_

Where do we go from here? Well, let's start with a gobuster scan:![](https://assets.tryhackme.com/additional/imgur/OftwAIE.png)

Looks like we've got two directories here -- `uploads` and `assets`. Of these, it seems likely that any files we upload will be placed in the "uploads" directory. We'll try uploading a legitimate image file first. Here I am choosing our cute dog photo from the previous task:

_Reverse Shells:_

The process for uploading a reverse shell is almost identical to that of uploading a webshell, so this section will be shorter. We'll be using the ubiquitous Pentest Monkey reverse shell, which comes by default on Kali Linux, but can also be downloaded [here](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php). You will need to edit line 49 of the shell. It will currently say `$ip = '127.0.0.1';  // CHANGE THIS   ` -- as it instructs, change `127.0.0.1` to your TryHackMe tun0 IP address, which can be found on the [access page](https://tryhackme.com/access). You can ignore the following line, which also asks to be changed. With the shell edited, the next thing we need to do is start a Netcat listener to receive the connection. `nc -lvnp 1234`:

![](https://assets.tryhackme.com/additional/imgur/ysY306E.png)

Now, let's upload the shell, then activate it by navigating to `http://demo.uploadvulns.thm/uploads/shell.php`. The name of the shell will obviously be whatever you called it (`php-reverse-shell.php` by default).

The website should hang and not load properly -- however, if we switch back to our terminal, we have a hit!

![](https://assets.tryhackme.com/additional/imgur/he0hbiR.png)

Once again, we have obtained RCE on this webserver. From here we would want to stabilise our shell and escalate our privileges, but those are tasks for another time. For now, it's time you tried this for yourself!

# Filtering
Up until now we have largely been ignoring the counter-defences employed by web developers to defend against file upload vulnerabilities. Every website that you've successfully attacked so far in this room has been completely insecure. It's time that changed. From here on out, we'll be looking at some of the defence mechanisms used to prevent malicious file uploads, and how to circumvent them.

---

First up, let's discuss the differences between _client_-side filtering and _server_-side filtering.

When we talk about a script being "Client-Side", in the context of web applications, we mean that it's running in the user's browser as opposed to on the web server itself. JavaScript is pretty much ubiquitous as the client-side scripting language, although alternatives do exist.  Regardless of the language being used, a client-side script will be run in your web browser. In the context of file-uploads, this means that the filtering occurs before the file is even uploaded to the server. Theoretically, this would seem like a good thing, right? In an ideal world, it would be; however, because the filtering is happening on _our_ computer, it is trivially easy to bypass. As such client-side filtering by itself is a highly insecure method of verifying that an uploaded file is not malicious.

Conversely, as you may have guessed, a _server_-side script will be run on the server. Traditionally PHP was the predominant server-side language (with Microsoft's ASP for IIS coming in close second); however, in recent years, other options (C#, Node.js, Python, Ruby on Rails, and a variety of others) have become more widely used. Server-side filtering tends to be more difficult to bypass, as you don't have the code in front of you. As the code is executed on the server, in most cases it will also be impossible to bypass the filter completely; instead we have to form a payload which conforms to the filters in place, but still allows us to execute our code.

---

With that in mind, let's take a look at some different kinds of filtering.

_Extension Validation:_

File extensions are used (in theory) to identify the contents of a file. In practice they are very easy to change, so actually don't mean much; however, MS Windows still uses them to identify file types, although Unix based systems tend to rely on other methods, which we'll cover in a bit. Filters that check for extensions work in one of two ways. They either _blacklist_ extensions (i.e. have a list of extensions which are **not** allowed) or they _whitelist_ extensions (i.e. have a list of extensions which **are** allowed, and reject everything else).

_File Type Filtering:_

Similar to Extension validation, but more intensive, file type filtering looks, once again, to verify that the contents of a file are acceptable to upload. We'll be looking at two types of file type validation:

- _MIME validation:_ MIME (**M**ultipurpose **I**nternet **M**ail **E**xtension) types are used as an identifier for files -- originally when transfered as attachments over email, but now also when files are being transferred over HTTP(S). The MIME type for a file upload is attached in the header of the request, and looks something like this:  
    ![](https://assets.tryhackme.com/additional/imgur/uptWRKW.png)  
      
    MIME types follow the format <type>/<subtype>. In the request above, you can see that the image "spaniel.jpg" was uploaded to the server. As a legitimate JPEG image, the MIME type for this upload was "image/jpeg". The MIME type for a file can be checked client-side and/or server-side; however, as MIME is based on the extension of the file, this is extremely easy to bypass.  
      
    
- _Magic Number validation**:**_ Magic numbers are the more accurate way of determining the contents of a file; although, they are by no means impossible to fake. The "magic number" of a file is a string of bytes at the very beginning of the file content which identify the content. For example, a PNG file would have these bytes at the very top of the file: `89 50 4E 47 0D 0A 1A 0A`.  
    ![](https://assets.tryhackme.com/additional/imgur/vHQWOgi.png)  
    Unlike Windows, Unix systems use magic numbers for identifying files; however, when dealing with file uploads, it is possible to check the magic number of the uploaded file to ensure that it is safe to accept. This is by no means a guaranteed solution, but it's more effective than checking the extension of a file.

_File Length Filtering:_

- File length filters are used to prevent huge files from being uploaded to the server via an upload form (as this can potentially starve the server of resources). In most cases this will not cause us any issues when we upload shells; however, it's worth bearing in mind that if an upload form only expects a very small file to be uploaded, there may be a length filter in place to ensure that the file length requirement is adhered to. As an example, our fully fledged PHP reverse shell from the previous task is 5.4Kb big -- relatively tiny, but if the form expects a maximum of 2Kb then we would need to find an alternative shell to upload.

_File Name Filtering:_

As touched upon previously, files uploaded to a server should be unique. Usually this would mean adding a random aspect to the file name, however, an alternative strategy would be to check if a file with the same name already exists on the server, and give the user an error if so. Additionally, file names should be sanitised on upload to ensure that they don't contain any "bad characters", which could potentially cause problems on the file system when uploaded (e.g. null bytes or forward slashes on Linux, as well as control characters such as `;` and potentially unicode characters). What this means for us is that, on a well administered system, our uploaded files are unlikely to have the same name we gave them before uploading, so be aware that you may have to go hunting for your shell in the event that you manage to bypass the content filtering.

_File Content Filtering:_

More complicated filtering systems may scan the full contents of an uploaded file to ensure that it's not spoofing its extension, MIME type and Magic Number. This is a significantly more complex process than the majority of basic filtration systems employ, and thus will not be covered in this room.

---

It's worth noting that none of these filters are perfect by themselves -- they will usually be used in conjunction with each other, providing a multi-layered filter, thus increasing the security of the upload significantly. Any of these filters can all be applied client-side, server-side, or both.

Similarly, different frameworks and languages come with their own inherent methods of filtering and validating uploaded files. As a result, it is possible for language specific exploits to appear; for example, until PHP major version five, it was possible to bypass an extension filter by appending a null byte, followed by a valid extension, to the malicious `.php` file. More recently it was also possible to inject PHP code into the exif data of an otherwise valid image file, then force the server to execute it. These are things that you are welcome to research further, should you be interested.

Time to turn things up another notch!

Client-side filters are easy to bypass -- you can see the code for them, even if it's been obfuscated and needs processed before you can read it; but what happens when you _can't_ see or manipulate the code? Well, that's a server-side filter. In short, we have to perform a lot of testing to build up an idea of what is or is not allowed through the filter, then gradually put together a payload which conforms to the restrictions.

For the first part of this task we'll take a look at a website that's using a blacklist for file extensions as a server side filter. There are a variety of different ways that this could be coded, and the bypass we use is dependent on that. In the real world we wouldn't be able to see the code for this, but for this example, it will be included here:

`<?php       
//Get the extension      
$extension = pathinfo($_FILES["fileToUpload"]["name"])["extension"];   
//Check the extension against the blacklist -- .php and .phtml     
switch($extension){       
	case "php":       
	case "phtml":      
	case NULL:            
	$uploadFail = True;         
	break;        
	default:       
	$uploadFail = False;     
}?>`

In this instance, the code is looking for the last period (`.`) in the file name and uses that to confirm the extension, so that is what we'll be trying to bypass here. Other ways the code could be working include: searching for the first period in the file name, or splitting the file name at each period and checking to see if any blacklisted extensions show up. We'll cover this latter case later on, but in the meantime, let's focus on the code we've got here.

We can see that the code is filtering out the `.php` and `.phtml` extensions, so if we want to upload a PHP script we're going to have to find another extension. The [wikipedia page](https://en.wikipedia.org/wiki/PHP) for PHP gives us a few common extensions that we can try; however, there are actually a variety of other more rarely used extensions available that webservers may nonetheless still recognise. These include: `.php3`, `.php4`, `.php5`, `.php7`, `.phps`, `.php-s`, `.pht` and `.phar`. Many of these bypass the filter (which only blocks`.php` and `.phtml`), but it appears that the server is configured not to recognise them as PHP files, as in the below example:

![](https://assets.tryhackme.com/additional/imgur/yzOGVob.png)

This is actually the default for Apache2 servers, at the time of writing; however, the sysadmin may have changed the default configuration (or the server may be out of date), so it's well worth trying.

Eventually we find that the `.phar` extension bypasses the filter -- and works -- thus giving us our shell:

![](https://assets.tryhackme.com/additional/imgur/Aigaz4R.png)

---

Let's have a look at another example, with a different filter. This time we'll do it completely black-box: i.e. without the source code.

Once again, we have our upload form:

![](https://assets.tryhackme.com/additional/imgur/STsI51E.png)

Ok, we'll start by scoping this out with a completely legitimate upload. Let's try uploading the `spaniel.jpg` image from before:

![](https://assets.tryhackme.com/additional/imgur/tp6T2WH.png)

Well, that tells us that JPEGS are accepted at least. Let's go for one that we can be pretty sure will be rejected (`shell.php`):

![](https://assets.tryhackme.com/additional/imgur/hk4inJ2.png)

Can't say that was unexpected.

From here we enumerate further, trying the techniques from above and just generally trying to get an idea of what the filter will accept or reject.

In this case we find that there are no shell extensions that both execute, and are not filtered, so it's back to the drawing board.

In the previous example we saw that the code was using the `pathinfo()` PHP function to get the last few characters after the `.`, but what happens if it filters the input slightly differently?

Let's try uploading a file called `shell.jpg.php`. We already know that JPEG files are accepted, so what if the filter is just checking to see if the `.jpg` file extension is somewhere within the input?

Pseudocode for this kind of filter may look something like this:

`ACCEPT FILE FROM THE USER -- SAVE FILENAME IN VARIABLE userInput   IF STRING ".jpg" IS IN VARIABLE userInput:       SAVE THE FILE   ELSE:       RETURN ERROR MESSAGE   `    

When we try to upload our file we get a success message. Navigating to the `/uploads` directory confirms that the payload was successfully uploaded:

![](https://assets.tryhackme.com/additional/imgur/K55eu9o.png)

Activating it, we receive our shell:

![](https://assets.tryhackme.com/additional/imgur/VVAKZfw.png)

---

This is by no means an exhaustive list of upload vulnerabilities related to file extensions. As with everything in hacking, we are looking to exploit flaws in code that others have written; this code may very well be uniquely written for the task at hand. This is the really important point to take away from this task: there are a million different ways to implement the same feature when it comes to programming -- your exploitation must be tailored to the filter at hand. The key to bypassing any kind of server side filter is to enumerate and see what is allowed, as well as what is blocked; then try to craft a payload which can pass the criteria the filter is looking for.

---

Now your turn. You know the drill by now -- figure out and bypass the filter to upload and activate a shell. Your flag is in `/var/www/`. The site you're accessing is `annex.uploadvulns.thm`.

Be aware that this task has also implemented a randomised naming scheme for the first time. For now you shouldn't have any trouble finding your shell, but be aware that directories will not always be indexable...

Answer the questions below

What is the flag in /var/www/?  

SubmitHint
------------------------------------------------------------------------------
Bypassing Server-Side Filtering: Magic Numbers

We've already had a look at server-side extension filtering, but let's also take the opportunity to see how magic number checking could be implemented as a server-side filter.

As mentioned previously, magic numbers are used as a more accurate identifier of files. The magic number of a file is a string of hex digits, and is always the very first thing in a file. Knowing this, it's possible to use magic numbers to validate file uploads, simply by reading those first few bytes and comparing them against either a whitelist or a blacklist. Bear in mind that this technique can be very effective against a PHP based webserver; however, it can sometimes fail against other types of webserver (hint hint).

Let's take a look at an example. As per usual, we have an upload page:

![](https://assets.tryhackme.com/additional/imgur/yQnQGsn.png)

As expected, if we upload our standard shell.php file, we get an error; however, if we upload a JPEG, the website is fine with it. All running as per expected so far.

From the previous attempt at an upload, we know that JPEG files are accepted, so let's try adding the JPEG magic number to the top of our `shell.php` file. A quick look at the [list of file signatures on Wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures) shows us that there are several possible magic numbers of JPEG files. It shouldn't matter which we use here, so let's just pick one (`FF D8 FF DB`). We could add the ASCII representation of these digits (ÿØÿÛ) directly to the top of the file but it's often easier to work directly with the hexadecimal representation, so let's cover that method.

Before we get started, let's use the Linux `file` command to check the file type of our shell:

![](https://assets.tryhackme.com/additional/imgur/2126EHS.png)

As expected, the command tells us that the filetype is PHP. Keep this in mind as we proceed with the explanation.

We can see that the magic number we've chosen is four bytes long, so let's open up the reverse shell script and add four random characters on the first line. These characters do not matter, so for this example we'll just use four "A"s:

![](https://assets.tryhackme.com/additional/imgur/oe434wu.png)

Save the file and exit. Next we're going to reopen the file in `hexeditor` (which comes by default on Kali), or any other tool which allows you to see and edit the shell as hex. In hexeditor the file looks like this:

![](https://assets.tryhackme.com/additional/imgur/otIyN96.png)

Note the four bytes in the red box: they are all `41`, which is the hex code for a capital "A" -- exactly what we added at the top of the file previously.

Change this to the magic number we found earlier for JPEG files: `FF D8 FF DB`

![](https://assets.tryhackme.com/additional/imgur/2OlGKdQ.png)

Now if we save and exit the file (Ctrl + x), we can use `file` once again, and see that we have successfully spoofed the filetype of our shell:

![](https://assets.tryhackme.com/additional/imgur/ldyt88v.png)

Perfect. Now let's try uploading the modified shell and see if it bypasses the filter!

![](https://assets.tryhackme.com/additional/imgur/Coat5LI.png)

There we have it -- we bypassed the server-side magic number filter and received a reverse shell.

Head to `magic.uploadvulns.thm` -- it's time for the last mini-challenge.

---

This will be the final example website you have to hack before the challenge in task eleven; as such, we are once again stepping up the level of basic security. The website in the last task implemented an altered naming scheme, prepending the date and time of upload to the file name. This task will not do so to keep it relatively easy; however, directory indexing has been turned off, so you will not be able to navigate to the directory containing the uploads. Instead you will need to access the shell directly using its URI.

Bypass the magic number filter to upload a shell. Find the location of the uploaded shell and activate it. Your flag is in `/var/www/`.

