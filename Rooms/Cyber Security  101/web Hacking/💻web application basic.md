

> [!Security headers] Security Headers
> We see the use of:
>
>- **default-src**  
    - which specifies the default policy of self, which means only the current website.  
 >     
>  
>- **script-src**  
    - which specifics the policy for where scripts can be loaded from, which is self along with scripts hosted on `https://cdn.tryhackme.com`  
>      
 >   
>- **style-src**  
    - which specifies the policy for where style CSS style sheets can be loaded from the current website (self)
### Strict-Transport-Security (HSTS)
The HSTS header ensures that web browsers will always connect over HTTPS. Let's look at an example of HSTS:

`Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`

Here’s a breakdown of the example HSTS header by directive:  

- **max-age**  
    - This is the expiry time in seconds for this setting  
      
    
- **includeSubDomains**  
    - An optional setting that instructs the browser to also apply this setting to all subdomains.  
      
    
- **preload  
    **- This optional setting allows the website to be included in preload lists. Browsers can use preload lists to enforce HSTS before even having their first visit to a website.

### X-Content-Type-Options

The X-Content-Type-Options header can be used to instruct browsers not to guess the MIME time of a resource but only use the Content-Type header. Here’s an example:

`X-Content-Type-Options: nosniff`

Here’s a breakdown of the X-Content-Type-Options header by directives:

- **nosniff**  
    - This directive instructs the browser not to sniff or guess the MIME type.


### Referrer-Policy

This header controls the amount of information sent to the destination web server when a user is redirected from the source web server, such as when they click a hyperlink. The header is available to allow a web administrator to control what information is shared.  Here are some examples of Referrer-Policy:

- `Referrer-Policy: no-referrer`
- `Referrer-Policy: same-origin`
- `Referrer-Policy: strict-origin`
- `Referrer-Policy: strict-origin-when-cross-origin`

Here’s a breakdown of the Referrer-Policy header by directives:

- **no-referrer**  
    - This completely disables any information being sent about the referrer  
      
    
- **same-origin**  
    - This policy will only send referrer information when the destination is part of the same origin. This is helpful when you want referrer information passed when hyperlinks are within the same website but not outside to external websites.  
      
    
- **strict-origin**  
    - This policy only sends the referrer as the origin when the protocol stays the same. So, a referrer is sent when an HTTPS connection goes to another HTTPS connection.  
      
    
- **strict-origin-when-cross-origin**  
    - This is similar to strict-origin except for same-origin requests, where it sends the full URL path in the origin header.