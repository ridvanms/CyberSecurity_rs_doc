
### *Filtering Expressions*

> [!Filtering by Host] Filtering by Host
> You can easily limit the captured packets to this host using `host IP` or `host HOSTNAME`
>  It is important to note that capturing packets requires you to be logged-in as `root` or to use `sudo`.
>  `sudo tcpdump host example.com -w http.pcap`
>  If you want to limit the packets to those from a particular source IP address or hostname, you must use `src host IP` or `src host HOSTNAME`. Similarly, you can limit packets to those sent to a specific destination using `dst host IP` or `dst host HOSTNAME`

> [!Filtering by Port] Filtering by Port
> 
>  Filtering by Port
>  If you want to capture all DNS traffic, you can limit the captured packets to those on `port 53`. Remember that DNS uses UDP and TCP ports 53 by default 
>  `sudo tcpdump -i ens5 port 53 -n`
>  You can limit the packets to those from a particular source port number or to a particular destination port number using `src port PORT_NUMBER` and `dst port PORT_NUMBER`, respectively


> [!Filtering by Protocol] Filtering by Protocol
> You can limit your packet capture to a specific protocol; examples include: `ip`, `ip6`, `udp`, `tcp`, and `icmp`
> `sudo tcpdump -i ens5 icmp -n`
> Three logical operators that can be handy:
> - `and`: Captures packets where both conditions are true. For example, `tcpdump host 1.1.1.1 and tcp` captures `tcp` traffic with `host 1.1.1.1`.
> - `or`: Captures packets when either one of the conditions is true. For instance, `tcpdump udp or icmp` captures UDP or ICMP traffic.
> - `not`: Captures packets when the condition is not true. For example, `tcpdump not tcp` captures all packets except TCP segments; we expect to find UDP, ICMP, and ARP packets among the results.
> 
> `tcpdump -r traffic.pcap src host 192.168.124.1 -n | wc`

### *Advanced Filtering* 


> [!Binary Operations] Binary Operations
> `&` (And) takes two bits and returns 0 unless both inputs are 1, as shown in the table below.
> `|` (Or) takes two bits and returns 1 unless both inputs are 0. This is shown in the table below.
> `!` (Not) takes one bit and inverts it; an input of 1 gives 0, and an input of 0 gives 1, as shown in the table below.


> [!### Header Bytes]  Header Bytes
> Using pcap-filter, Tcpdump allows you to refer to the contents of any byte in the header using the following syntax `proto[expr:size]`, where:
> - `proto` refers to the protocol. For example, `arp`, `ether`, `icmp`, `ip`, `ip6`, `tcp`, and `udp` refer to ARP, Ethernet, ICMP, IPv4, IPv6, TCP, and UDP respectively.
> -  `expr` indicates the byte offset, where `0` refers to the first byte.
> - `size` indicates the number of bytes that interest us, which can be one, two, or four. It is optional and is one by default.
> 
> `ether[0] & 1 != 0` takes the first byte in the Ethernet header and the decimal number 1 (i.e., `0000 0001` in binary) and applies the `&` (the And binary operation). It will return true if the result is not equal to the number 0 (i.e., `0000 0000`). The purpose of this filter is to show packets sent to a multicast address. A multicast Ethernet address is a particular address that identifies a group of devices intended to receive the same data.
> 
>  `tcpdump "tcp[tcpflags] == tcp-syn"` to capture TCP packets with **only** the SYN (Synchronize) flag set, while all the other flags are unset.
>  `tcpdump "tcp[tcpflags] & tcp-syn != 0"` to capture TCP packets with **at least** the SYN (Synchronize) flag set.
> `tcpdump "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0"` to capture TCP packets with **at least** the SYN (Synchronize) **or** ACK (Acknowledge) flags set.
> 
> - `tcp-syn` TCP SYN (Synchronize)
> - `tcp-ack` TCP ACK (Acknowledge)
> - `tcp-fin` TCP FIN (Finish)
> -  `tcp-rst` TCP RST (Reset)
> - `tcp-push` TCP Push 

### *Displaying Packets*

Tcpdump is a rich program with many options to customize how the packets are printed and displayed. We have selected to cover the following five options:

- `-q`: Quick output; print brief packet information
- `-e`: Print the link-level header
- `-A`: Show packet data in ASCII
- `-xx`: Show packet data in hexadecimal format, referred to as hex
- `-X`: Show packet headers and data in hex and ASCII
###### `tcpdump -r TwoPackets.pcap`

> [!### Brief Packet Information]  Brief Packet Information
> If you prefer shorter output lines, you can opt for “quick” output with `-q`. The following example shows the timestamp, along with the source and destination IP addresses and source and destination port numbers.
> - `tcpdump -r TwoPackets.pcap -q`
> 


> [!### Displaying Link-Level Header] Displaying Link-Level Header
> If you are on an Ethernet or WiFi network and want to include the MAC addresses in Tcpdump output, all you need to do is to add `-e`. This is convenient when you are learning how specific protocols, such as ARP and DHCP function. It can also help you track the source of any unusual packets on your network.
> - `tcpdump -r TwoPackets.pcap -e`


> [!### Displaying Packets as ASCII] Displaying Packets as ASCII
> ASCII stands for American Standart Code for information Interchange; ASCII codes represent text. In other words, you can expect `-A` to display all the bytes mapped to English letters, numbers, and symbols.
>  - `tcpdump -r TwoPackets.pcap -A`


> [!### Displaying Packets in Hexadecimal Format]  Displaying Packets in Hexadecimal Format
> ASCII format works well when the packet contents are plain-text English. It won’t work if the contents have undergone encryption or even compression. Furthermore, it won’t work for languages that don’t use the English alphabet. Hence, we need another way to display the packet contents regardless of format. Being 8 bits, any octet can be displayed as two hexadecimal digits. (Each hexadecimal digit represents 4 bits.) To display the packets in hexadecimal format, we must add `-xx` as shown in the terminal below.
>  - `tcpdump -r TwoPackets.pcap -xx`
>  
> Adding `-xx` lets us see the packet octet by octet. In the example above, we can closely inspect the IP and TCP headers in addition to the packet contents.


> [!### Best of Both Worlds] Best of Both Worlds
> If you would like to display the captured packets in hexadecimal and ASCII formats, Tcpdump makes it easy with the `-X` option.
>  - `tcpdump -r TwoPackets.pcap -X`
>  
|Command|Explanation|
|---|---|
|`tcpdump -q`|Quick and quite: brief packet information|
|`tcpdump -e`|Include MAC addresses|
|`tcpdump -A`|Print packets as ASCII encoding|
|`tcpdump -xx`|Display packets in hexadecimal format|
|`tcpdump -X`|Show packets in both hexadecimal and ASCII formats|




