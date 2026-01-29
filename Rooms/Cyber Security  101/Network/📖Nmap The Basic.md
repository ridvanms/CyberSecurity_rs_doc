

> [!HOST discovery Who is Online] HOST discovery Who is Online
> scan the WiFi network to which we are connected:  `nmap -sn 192.168.66.0/24`
> ❕routers (hops)
> As a final point, Nmap offers a list scan with the option `-sL`. This scan only lists the targets to scan without actually scanning them. For example, `nmap -sL 192.168.0.1/24` will list the 256 targets that will be scanned. This option helps confirm the targets before running the actual scan.
> 

> [!Port Scanning who is Listening] Port Scanning who is Listening
> ### Scanning TCP Ports 
> The easiest and most basic way to know whether a TCP port is open would be to attempt to `telnet` to the port
> #### Connect Scan
> The connect scan can be triggered using `-sT`. It tries to complete the TCP three-way handshake with every target TCP port. If the TCP port turns out to be open and Nmap connects successfully, Nmap will tear down the established connection
> #### SYN Scan (Stealth)
> The advantage is that this is expected to lead to fewer logs as the connection is never established, and hence, it is considered a relatively stealthy scan. You can select the SYN scan using the `-sS` flag
> ### Scanning UDP Ports
>  Nmap offers the option `-sU` to scan for UDP services.
> ### Limiting the Target Ports
> - Nmap scans the most common 1,000 ports by default.
>  `-F` is for Fast mode, which scans the 100 most common ports (instead of the default 1000).
. `-p[range]` allows you to specify a range of ports to scan. For example, `-p10-1024` scans from port 10 to port 1024, while `-p-25` will scan all the ports between 1 and 25. Note that `-p-` scans all the ports and is equivalent to `-p1-65535` and is the best option if you want to be as thorough as possible.
>

| Option      | Explanation                                                   |
| ----------- | ------------------------------------------------------------- |
| `-sT`       | TCP connect scan – complete three-way handshake               |
| `-sS`       | TCP SYN – only first step of the three-way handshake          |
| `-sU`       | UDP scan                                                      |
| `-F`        | Fast mode – scans the 100 most common ports                   |
| `-p[range]` | Specifies a range of port numbers – `-p-` scans all the ports |

> [!Version detection: Extract more information] Version detection: Extract more information
> ### OS Detection
> You can enable OS detection by adding the `-O` option.
> `nmap -sS -O 192.168.124.211`
> ### Service and Version Detection
> You discovered several open ports and want to know what services are listening on them. `-sV` enables version detection.
> `nmap -sS -sV 192.168.124.211`
> 
>  *What if you can have both `-O`, `-sV` and some more in one option? That would be `-A`. This option enables OS detection, version scanning, and traceroute, among other things.*
>### Forcing the Scan
>We can ask Nmap to treat all hosts as online and port scan every host, including those that didn’t respond during the host discovery phase. This choice can be triggered by adding the `-Pn` option.


> [!Timing How Fast is Fast] Timing How Fast is Fast
> Nmap provides various options to control the scan speed and timing
> In the Nmap scans below, we launch a SYN scan targeting the 100 most common TCP ports, `nmap -sS 10.10.219.36 -F`
> We repeated the scan with different timings: T0, T1, T2, T3, and T4.
> 
|Timing|Total Duration|
|---|---|
|T0 (paranoid)|9.8 hours|
|T1 (sneaky)|27.53 minutes|
|T2 (polite)|40.56 seconds|
|T3 (normal)|0.15 seconds|
|T4 (aggressive)|0.13 seconds|
>The number of parallel probes can be controlled with `--min-parallelism <numprobes>` and `--max-parallelism <numprobes>`.
>A similar helpful option is the `--min-rate <number>` and `--max-rate <number>`. As the names indicate, they can control the minimum and maximum rates at which `nmap` sends packets.
>This option specifies the maximum time you are willing to wait, and it is suitable for slow hosts or hosts with slow network connections. `--host-timeout <time>`
>


> [!Output: Controlling What You See] Output: Controlling What You See
> ### Verbosity and Debugging
> The best way to get more updates about what’s happening is to enable verbose output by adding `-v`
> `nmap -sS 192.168.139.1/24`
> Then, we repeated the same scan; however, the second time, we used the `-v` option for verbosity.
> `nmap 192.168.139.1/24 -v`
> ### Saving Scan Report
> - `-oN <filename>` - Normal output
> - `-oX <filename>` - XML output
>- `-oG <filename>` - `grep`-able output (useful for `grep` and `awk`)
>- `-oA <basename>` - Output in all major formats
>
>  It resulted in three reports with the extensions `nmap`, `xml`, and `gnmap` for normal, XML, and `grep`-able output.
> `nmap -sS 192.168.139.1 -oA gateway`


> [!Conclusion and Summary] Conclusion and summary
> In this room, we learned how to use Nmap to discover live hosts on any network. We also explored the common types of port scans and how we can use Nmap to find service version numbers. We also learned how to control the timing of the scan, and finally, we covered the different formats for saving Nmap scan results.
>
>|Option|Explanation|
|---|---|
|`-sL`|List scan – list targets without scanning|
|**_Host Discovery_**||
|`-sn`|Ping scan – host discovery only|
|**_Port Scanning_**||
|`-sT`|TCP connect scan – complete three-way handshake|
|`-sS`|TCP SYN – only first step of the three-way handshake|
|`-sU`|UDP Scan|
|`-F`|Fast mode – scans the 100 most common ports|
|`-p[range]`|Specifies a range of port numbers – `-p-` scans all the ports|
|`-Pn`|Treat all hosts as online – scan hosts that appear to be down|
|**_Service Detection_**||
|`-O`|OS detection|
|`-sV`|Service version detection|
|`-A`|OS detection, version detection, and other additions|
|**_Timing_**||
|`-T<0-5>`|Timing template – paranoid (0), sneaky (1), polite (2), normal (3), aggressive (4), and insane (5)|
|`--min-parallelism <numprobes>` and `--max-parallelism <numprobes>`|Minimum and maximum number of parallel probes|
|`--min-rate <number>` and `--max-rate <number>`|Minimum and maximum rate (packets/second)|
|`--host-timeout`|Maximum amount of time to wait for a target host|
|**_Real-time output_**||
|`-v`|Verbosity level – for example, `-vv` and `-v4`|
|`-d`|Debugging level – for example `-d` and `-d9`|
|**_Report_**||
|`-oN <filename>`|Normal output|
|`-oX <filename>`|XML output|
|`-oG <filename>`|`grep`-able output|
|`-oA <basename>`|Output in all major formats|