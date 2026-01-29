# What is intruder
Intruder is Burp Suite's built-in fuzzing tool that allows for automated request modification and repetitive testing with variations in input values. By using a captured request (often from the Proxy module), Intruder can send multiple requests with slightly altered values based on user-defined configurations. It serves various purposes, such as brute-forcing login forms by substituting username and password fields with values from a wordlist or performing fuzzing attacks using wordlists to test subdirectories, endpoints, or virtual hosts. Intruder's functionality is comparable to command-line tools like **Wfuzz** or **ffuf**.

However, it's important to note that while Intruder can be used with Burp Community Edition, it is rate-limited, significantly reducing its speed compared to Burp Professional. This limitation often leads security practitioners to rely on other tools for fuzzing and brute-forcing. Nonetheless, Intruder remains a valuable tool and is worth learning how to use it effectively.

The initial view of Intruder presents a simple interface where we can select our target. This field will already be populated if a request has been sent from the Proxy (using `Ctrl + I` or right-clicking and selecting "Send to Intruder").

There are four sub-tabs within Intruder:

- **Positions**: This tab allows us to select an attack type (which we will cover in a future task) and configure where we want to insert our payloads in the request template.
- **Payloads**: Here we can select values to insert into the positions defined in the **Positions** tab. We have various payload options, such as loading items from a wordlist. The way these payloads are inserted into the template depends on the attack type chosen in the **Positions** tab. The **Payloads** tab also enables us to modify Intruder's behavior regarding payloads, such as defining pre-processing rules for each payload (e.g., adding a prefix or suffix, performing match and replace, or skipping payloads based on a defined regex).
- **Resource Pool**: This tab is not particularly useful in the Burp Community Edition. It allows for resource allocation among various automated tasks in Burp Professional. Without access to these automated tasks, this tab is of limited importance.
- **Settings**: This tab allows us to configure attack behavior. It primarily deals with how Burp handles results and the attack itself. For instance, we can flag requests containing specific text or define Burp's response to redirect (3xx) responses.

**Note:** The term "fuzzing" refers to the process of testing functionality or existence by applying a set of data to a parameter. For example, fuzzing for endpoints in a web application involves taking each word in a wordlist and appending it to a request URL (e.g., http://10.10.200.40/WORD_GOES_HERE) to observe the server's response.

# Positions

When using Burp Suite Intruder to perform an attack, the first step is to examine the positions within the request where we want to insert our payloads. These positions inform Intruder about the locations where our payloads will be introduced (as we will explore in upcoming tasks).

Notice that Burp Suite automatically attempts to identify the most probable positions where payloads can be inserted. These positions are highlighted in green and enclosed by section marks (`§`).

On the right-hand side of the interface, we find the following buttons: `Add §`, `Clear §`, and `Auto §`:

- The `Add §` button allows us to define new positions manually by highlighting them within the request editor and then clicking the button.
- The `Clear §` button removes all defined positions, providing a blank canvas where we can define our own positions.
- The `Auto §` button automatically attempts to identify the most likely positions based on the request. This feature is helpful if we previously cleared the default positions and want them back.

# Payloads
1. **Payload Sets**:
    - This section allows us to choose the position for which we want to configure a payload set and select the type of payload we want to use.
    - When using attack types that allow only a single payload set (Sniper or Battering Ram), the "Payload Set" dropdown will have only one option, regardless of the number of defined positions.
    - If we use attack types that require multiple payload sets (Pitchfork or Cluster Bomb), there will be one item in the dropdown for each position.
    - **Note:** When assigning numbers in the "Payload Set" dropdown for multiple positions, follow a top-to-bottom, left-to-right order. For example, with two positions (`username=§pentester§&password=§Expl01ted§`), the first item in the payload set dropdown would refer to the username field, and the second item would refer to the password field.
  
2. **Payload settings**:
    - This section provides options specific to the selected payload type for the current payload set.
    - For example, when using the "Simple list" payload type, we can manually add or remove payloads to/from the set using the **Add** text box, **Paste** lines, or **Load** payloads from a file. The **Remove** button removes the currently selected line, and the **Clear** button clears the entire list. Be cautious with loading huge lists, as it may cause Burp to crash.
    - Each payload type will have its own set of options and functionality. Explore the options available to understand the range of possibilities.  
        
        ![Available options](https://tryhackme-images.s3.amazonaws.com/user-uploads/645b19f5d5848d004ab9c9e2/room-content/722a734ac5dd6437211504d3bc7bb6c2.png)
        
  
3. **Payload Processing**:
    - In this section, we can define rules to be applied to each payload in the set before it is sent to the target.
    - For example, we can capitalize every word, skip payloads that match a regex pattern, or apply other transformations or filtering.
    - While you may not use this section frequently, it can be highly valuable when specific payload processing is required for your attack.
  
4. **Payload Encoding**:
    - The section allows us to customize the encoding options for our payloads.
    - By default, Burp Suite applies URL encoding to ensure the safe transmission of payloads. However, there may be cases where we want to adjust the encoding behavior.
    - We can override the default URL encoding options by modifying the list of characters to be encoded or unchecking the "URL-encode these characters" checkbox.

By leveraging these sections, we can create and customise payload sets to suit the specific requirements of our attacks. This level of control allows us to finely tune our payloads for effective testing and exploitation.

# Introduction to Attack Types

The **Positions** tab of Burp Suite Intruder has a dropdown menu for selecting the attack type. Intruder offers four attack types, each serving a specific purpose. Let's explore each of them:

1. **Sniper**: The Sniper attack type is the default and most commonly used option. It cycles through the payloads, inserting one payload at a time into each position defined in the request. Sniper attacks iterate through all the payloads in a linear fashion, allowing for precise and focused testing.
    
2. **Battering ram**: The Battering ram attack type differs from Sniper in that it sends all payloads simultaneously, each payload inserted into its respective position. This attack type is useful when testing for race conditions or when payloads need to be sent concurrently.
    
3. **Pitchfork**: The Pitchfork attack type enables the simultaneous testing of multiple positions with different payloads. It allows the tester to define multiple payload sets, each associated with a specific position in the request. Pitchfork attacks are effective when there are distinct parameters that need separate testing.
    
4. **Cluster bomb**: The Cluster bomb attack type combines the Sniper and Pitchfork approaches. It performs a Sniper-like attack on each position but simultaneously tests all payloads from each set. This attack type is useful when multiple positions have different payloads, and we want to test them all together.
    

Each attack type has its advantages and is suitable for different testing scenarios. Understanding their differences helps us select the appropriate attack type based on the testing objectives.

# Sniper

The **Sniper** attack type is the default and most commonly used attack type in Burp Suite Intruder. It is particularly effective for single-position attacks, such as password brute-force or fuzzing for API endpoints. In a Sniper attack, we provide a set of payloads, which can be a wordlist or a range of numbers, and Intruder inserts each payload into each defined position in the request.

``` Example Position
  
	POST /support/login/ HTTP/1.1
	Host: MACHINE_IP
	User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
	Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
	Accept-Language: en-US,en;q=0.5
	Accept-Encoding: gzip, deflate
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 37
	Origin: http://MACHINE_IP
	Connection: close
	Referer: http://MACHINE_IP/support/login/
	Upgrade-Insecure-Requests: 1
	
	username=§pentester§&password=§Expl01ted§
```

# Battering Ram

The **Battering ram** attack type in Burp Suite Intruder differs from Sniper in that it places the same payload in every position simultaneously, rather than substituting each payload into each position in turn.

Example Positions

```html
  
	POST /support/login/ HTTP/1.1
    Host: MACHINE_IP
    User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 37
    Origin: http://MACHINE_IP
    Connection: close
    Referer: http://MACHINE_IP/support/login/
    Upgrade-Insecure-Requests: 1
    
    username=§pentester§&password=§Expl01ted§
```

# Pitchfork
The **Pitchfork** attack type in Burp Suite Intruder is similar to having multiple Sniper attacks running simultaneously. While Sniper uses one payload set to test all positions simultaneously, Pitchfork utilises one payload set per position (up to a maximum of 20) and iterates through them all simultaneously.

To better understand Pitchfork, let us revisit our brute-force example, but this time with two wordlists:

1. The first wordlist contains usernames: `joel`, `harriet`, and `alex`.
2. The second wordlist contains passwords: `J03l`, `Emma1815`, and `Sk1ll`.

We can use these two lists to perform a Pitchfork attack on the login form. Each request made during the attack would look like this:

|Request Number|Request Body|
|---|---|
|1|`username=joel&password=J03l`|
|2|`username=harriet&password=Emma1815`|
|3|`username=alex&password=Sk1ll`|
As shown in the table, Pitchfork takes the first item from each list and substitutes them into the request, one per position. It then repeats this process for the next request by taking the second item from each list and substituting it into the template. Intruder continues this iteration until one or all of the lists run out of items. It's important to note that Intruder stops testing as soon as one of the lists is complete. Therefore, in Pitchfork attacks, it is ideal for the payload sets to have the same length. If the lengths of the payload sets differ, Intruder will only make requests until the shorter list is exhausted, and the remaining items in the longer list will not be tested.

The Pitchfork attack type is especially useful when conducting credential-stuffing attacks or when multiple positions require separate payload sets. It allows for simultaneous testing of multiple positions with different payloads.

In the upcoming tasks, we will explore further configurations and settings related to Intruder's Pitchfork attack type and explore its applications in different scenarios, including credential-stuffing attacks.

# Cluster Bomb
The **Cluster bomb** attack type in Burp Suite Intruder allows us to choose multiple payload sets, one per position (up to a maximum of 20). Unlike Pitchfork, where all payload sets are tested simultaneously, Cluster bomb iterates through each payload set individually, ensuring that every possible combination of payloads is tested.

To illustrate the Cluster bomb attack type, let's use the same wordlists as before:

- Usernames: `joel`, `harriet`, and `alex`.
- Passwords: `J03l`, `Emma1815`, and `Sk1ll`.

In this example, let's assume that we don't know which password belongs to which user. We have three users and three passwords, but the mappings are unknown. In this case, we can use a Cluster bomb attack to try every combination of values. The request table for our username and password positions would look like this:

|Request Number|Request Body|
|---|---|
|1|`username=joel&password=J03l`|
|2|`username=harriet&password=J03l`|
|3|`username=alex&password=J03l`|
|4|`username=joel&password=Emma1815`|
|5|`username=harriet&password=Emma1815`|
|6|`username=alex&password=Emma1815`|
|7|`username=joel&password=Sk1ll`|
|8|`username=harriet&password=Sk1ll`|
|9|`username=alex&password=Sk1ll`|
As shown in the table, the Cluster bomb attack type iterates through every combination of the provided payload sets. It tests every possibility by substituting each value from each payload set into the corresponding position in the request.

Cluster bomb attacks can generate a significant amount of traffic as it tests every combination. The number of requests made by a Cluster bomb attack can be calculated by multiplying the number of lines in each payload set together. It's important to be cautious when using this attack type, especially when dealing with large payload sets. Additionally, when using Burp Community and its Intruder rate-limiting, the execution of a Cluster bomb attack with a moderately sized payload set can take a significantly longer time.

The Cluster bomb attack type is particularly useful for credential brute-forcing scenarios where the mapping between usernames and passwords is unknown.

In the upcoming tasks, we will explore further configurations and settings related to Intruder's Cluster bomb attack type and examine its applications in different scenarios.

#Credential-stuffing is a type of cyber attack where an attacker uses a list of known username and password combinations to gain unauthorized access to accounts.

In the context of web application testing with Burp Suite, #macros are essential tools for automating repetitive tasks.

# Extra mail 
In this extra-mile exercise, we will tackle a more challenging variant of the credential-stuffing attack we previously performed. However, this time, additional measures have been implemented to make brute-forcing more difficult. If you are comfortable using Burp Macros, you can attempt this challenge without the instructions below. Otherwise, let's proceed with the step-by-step approach.

#### Catching the Request

Begin by capturing a request to `http://10.10.41.87/admin/login/` and reviewing the response. Here is an example of the response:

Example Response

```html

```

In this response, we notice that alongside the username and password fields, there is now a session cookie set, as well as a CSRF (**Cross-Site Request Forgery**) token in the form as a hidden field. Refreshing the page reveals that both the **session** cookie and the **loginToken** change with each request. This means that for every login attempt, we need to extract valid values for both the session cookie and the loginToken.

To accomplish this, we will use **Burp Macros** to define a repeated set of actions (macro) to be executed before each request. This macro will extract unique values for the session cookie and loginToken, replacing them in every subsequent request of our attack.

#### Tutorial

1. Navigate to `http://10.10.41.87/admin/login/`. Activate **Intercept** in the Proxy module and attempt to log in. Capture the request and send it to Intruder.
    
2. Configure the positions the same way as we did for brute-forcing the support login:
    
    - Set the attack type to "Pitchfork".
    - Clear all predefined positions and select only the username and password form fields. Our macro will handle the other two positions.
        
    
    ![Showing the predefined positions](https://tryhackme-images.s3.amazonaws.com/user-uploads/645b19f5d5848d004ab9c9e2/room-content/cdade963a8004b0d9da03e075a60f3aa.png)
    
3. Now switch over to the Payloads tab and load in the same username and password wordlists we used for the support login attack.
    
    Up until this point, we have configured Intruder in almost the same way as our previous credential stuffing attack; this is where things start to get more complicated.
    
4. With the username and password parameters handled, we now need to find a way to grab the ever-changing loginToken and session cookie. Unfortunately, "recursive grep" won't work here due to the redirect response, so we can't do this entirely within Intruder – we will need to build a macro.
    
    Macros allow us to perform the same set of actions repeatedly. In this case, we simply want to send a GET request to `/admin/login/`.
    
    Fortunately, setting this up is a straightforward process.
    
    - Switch over to the main "Settings" tab at the top-right of Burp.
    - Click on the "Sessions" category.
    - Scroll down to the bottom of the category to the "Macros" section and click the **Add** button.
    - The menu that appears will show us our request history. If there isn't a GET request to `http://10.10.41.87/admin/login/` in the list already, navigate to this location in your browser, and you should see a suitable request appear in the list.
    - With the request selected, click **OK**.
    - Finally, give the macro a suitable name, then click **OK** again to finish the process.
    
    There are a lot of steps here, comparatively speaking, so the following GIF shows the entire process:
    
    ![Process showing the addition of the macro](https://tryhackme-images.s3.amazonaws.com/user-uploads/645b19f5d5848d004ab9c9e2/room-content/3b370cfce8a050faf415c7d9a5a8227e.gif)
    
5. Now that we have a macro defined, we need to set Session Handling rules that define how the macro should be used.
    
    - Still in the "Sessions" category of the main settings, scroll up to the "Session Handling Rules" section and choose to **Add** a new rule.
    - A new window will pop up with two tabs in it: "Details" and "Scope". We are in the Details tab by default.
        
    
    ![Window showing the details and scope](https://assets.muirlandoracle.co.uk/thm/modules/burp/38ceffeebf99.png)
    
    - Fill in an appropriate description, then switch to the Scope tab.
    - In the "Tools Scope" section, deselect every checkbox other than Intruder – we do not need this rule to apply anywhere else.
    - In the "URL Scope" section, choose "Use suite scope"; this will set the macro to only operate on sites that have been added to the global scope (as was discussed in [Burp Basics](https://tryhackme.com/room/burpsuitebasics)). If you have not set a global scope, keep the "Use custom scope" option as default and add `http://10.10.41.87/` to the scope in this section.
        
        ![Change the URL scope](https://assets.muirlandoracle.co.uk/thm/modules/burp/4d3fc6d19a12.png)
        
6. Now we need to switch back over to the Details tab and look at the "Rule Actions" section.
    
    - Click the **Add** button – this will cause a dropdown menu to appear with a list of actions we can add.
    - Select "Run a Macro" from this list.
    - In the new window that appears, select the macro we created earlier.
        
    
    As it stands, this macro will now overwrite all of the parameters in our Intruder requests before we send them; this is great, as it means that we will get the loginTokens and session cookies added straight into our requests. That said, we should restrict which parameters and cookies are being updated before we start our attack:
    
    - Select "Update only the following parameters and headers", then click the **Edit** button next to the input box below the radio button.
    - In the "Enter a new item" text field, type "loginToken". Press **Add**, then **Close**.
    - Select "Update only the following cookies", then click the relevant **Edit** button.
    - Enter "session" in the "Enter a new item" text field. Press **Add**, then **Close**.
    - Finally, press **OK** to confirm our action.
        
    
    The following GIF demonstrates this final stage of the process:
    
    ![Showing the added macro](https://tryhackme-images.s3.amazonaws.com/user-uploads/645b19f5d5848d004ab9c9e2/room-content/250c140897e3b470093e7232c70c07cf.gif)
    
7. Click **OK**, and we're done!
    
8. You should now have a macro defined that will substitute in the CSRF token and session cookie. All that's left to do is switch back to Intruder and start the attack!
    
    **Note:** You should be getting 302 status code responses for every request in this attack. If you see 403 errors, then your macro is not working properly.
    
9. As with the support login credential stuffing attack we carried out, the response codes here are all the same (302 Redirects). Once again, order your responses by length to find the valid credentials. Your results won't be quite as clear-cut as last time – you will see quite a few different response lengths: however, the response that indicates a successful login should still stand out as being significantly shorter.
    
10. Use the credentials you just found to log in (you may need to refresh the login page before entering the credentials).