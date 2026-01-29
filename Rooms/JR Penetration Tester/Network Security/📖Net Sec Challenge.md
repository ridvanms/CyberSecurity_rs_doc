!TRYHACKME CHALLENGES

# Milestone: Initial Comprehensive Port Scan

#### What you did

nmap -sN [ip-address]

sudo nmap -p 10000-65535 [ip-address] -sV

#### Tips for the future

You successfully initiated a comprehensive port scan using Nmap, which is essential for uncovering all available services. This demonstrates a solid understanding of enumeration techniques.

#### Example approach:

Continue this approach: using Nmap effectively sets a strong foundation for further exploration and exploitation.

# Optimise Nmap Scanning Strategy

#### What you did

sudo nmap -sS -O [ip-address]

sudo nmap -sF [ip-address]

sudo nmap -sX [ip-address]

#### Tips for the future

Using Nmap to scan all TCP ports is crucial for identifying open services. However, scanning with multiple techniques like `-sF` (FIN) and `-sX` (Xmas) may not be necessary if you already have results from a comprehensive scan like `-p-`. This can save time and reduce complexity.

#### Example approach:

Going forward, consider consolidating your scans into a single comprehensive command like `sudo nmap -p- -sV [ip-address]` to quickly identify all services.

# Refine HTTP Request Handling
#### What you did

#### Tips for the future

Receiving a `405 Method Not Allowed` response indicates that the request method is not supported by the server for the specified resource. Ensure you're using the correct HTTP methods for the endpoints you're querying.

#### Example approach:

In future environments, validate the HTTP method against the expected methods for a given endpoint to avoid unnecessary errors.

# Enhance Scanning Efficiency
#### What you did

sudo nmap -p 10000-65535 [ip-address] -sV

sudo nmap -p 1000-65535 [ip-address] -sV

#### Tips for the future

While scanning multiple port ranges is effective, using a more targeted approach can yield quicker results. The second command's range overlaps with the first, leading to redundancy.

#### Example approach:

Consider refining your scan ranges to avoid overlaps, such as using specific known ports first, then expanding as needed.