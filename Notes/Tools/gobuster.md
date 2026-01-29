# GoBuster Cheatsheet

GoBuster is a tool used to brute-force URIs (directories and files) in web sites, DNS subdomains, and Open S3 buckets.

## Directory and File Brute-Forcing

*   **Basic directory brute-force:**
    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt
    ```

*   **Specify extensions:**
    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -x php,html,txt
    ```

*   **Add HTTP headers:**
    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -H "User-Agent: my-custom-agent"
    ```

*   **Exclude status codes:**
    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -b 404,403
    ```

*   **Include status codes:**
    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -s 200,204,301
    ```

*   **Delay between requests:**
    ```bash
    gobuster dir -u http://example.com -w /path/to/wordlist.txt -d 1s
    ```

## DNS Subdomain Brute-Forcing

*   **Basic subdomain brute-force:**
    ```bash
    gobuster dns -d example.com -w /path/to/wordlist.txt
    ```

*   **Specify a DNS server:**
    ```bash
    gobuster dns -d example.com -w /path/to/wordlist.txt --dns-server 8.8.8.8
    ```

## VHost Brute-Forcing

*   **Basic VHost brute-force:**
    ```bash
    gobuster vhost -u http://example.com -w /path/to/wordlist.txt -H "Host: FUZZ.example.com"
    ```

## S3 Bucket Brute-Forcing

*   **Basic S3 bucket brute-force:**
    ```bash
    gobuster s3 -w /path/to/wordlist.txt
    ```
