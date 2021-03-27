# Networking

OSI Model

    - Application: layer 7 (and basically layers 5 & 6) (includes API, HTTP, etc).
    - Presentation: encryption/decryption
    - Session: controls session for system restart or network termination
    - Transport: layer 4 (TCP/UDP for SEGMENTS).
    - Network: layer 3 (Routing of network PACKETS). ICMP
    - Datalink: layer 2 (Error checking CRC and FRAME synchronisation) MAC addresses
    - Physical: layer 1 (BITS over fibre).

Firewalls

    Iptables uses a set of tables which have chains that contain set of built-in or user defined rules. Per iptables manual, there are currently 3 types of tables:
        FILTER – default table, which contains the built in chains for:
            INPUT  – packages destined for local sockets
            FORWARD – packets routed through the system
            OUTPUT – packets generated locally
            
            
        NAT – a table that is consulted when a packet tries to create a new connection. It has the following built-in:
            PREROUTING – used for ALTERING a packet as soon as it’s _received_
            OUTPUT – used for ALTERING _locally generated_ packets
            POSTROUTING – used for ALTERING packets as they are about to _go out_
            
            
        MANGLE – this table is used for packet altering.
            PREROUTING – for ALTERING incoming connections
            OUTPUT – for ALTERING locally generated  packets
            INPUT – for incoming packets
            POSTROUTING – for ALTERING packets as they are about to go out
            FORWARD – for packets routed through the box

NAT

    Useful to understand IPv4 vs IPv6.

DNS

    (53)
    Requests to DNS are usually UDP, unless the server gives a redirect notice asking for a TCP connection.
    TCP is used if the DNS query exceeds the limitations of the UDP datagram size – typically **512 bytes** for DNS
    Look up in cache happens first. DNS exfiltration. Using raw IP addresses means no DNS logs, but there are HTTP logs. 
    **DNS sinkholes**
        - DNS sinkholing helps you to identify infected hosts on the protected network using DNS traffic in situations where the firewall cannot see the infected client's DNS query (that is, the firewall cannot see the originator of the DNS query). 
        - In a typical deployment where the firewall is north of the local DNS server, the threat log will identify the local DNS resolver as the source of the traffic rather than the actual infected host. 
        - Sinkholing malware DNS queries solves this visibility problem by forging responses to the client host queries directed at malicious domains, so that clients attempting to connect to malicious domains (for c2, e.g.) will instead attempt to connect to a default sinkhole IP address
        - Infected hosts can then be easily identified in the traffic logs.
    **Reverse DNS lookup** => PTR might contain- 2.152.80.208.in-addr.arpa which will map to **208.80.152.2**
    DNS lookups start at the end of the string and work backwards, which is why the IP address is backwards in PTR.
    DNS request can be used as a heartbeat(A Record) for checking remote victim is still operational.    

DNS Tunneling

    C2 over DNS
        
        Adversaries leveraging DNS for C2 by putting commands into the domain name fields in DNS lookups, and encoding the commands
        
    DNS exfiltration

        Sending data as subdomains using UDP as long as its encoded and doesn't exceed UDP limits
        26856485f6476a567567c6576e678.badguy.com
        Doesn’t show up in http logs

    DNS Infiltration

        Infiltration of data whether it be code, commands, or a binary file especially using the DNS type of TXT

DNS Cache Poisoning

    Attackers can poison DNS caches by impersonating DNS nameservers => making multiple requests to a DNS resolver => and then forging the reply when the DNS resolver queries a nameserver. 
    This is possible because DNS servers use UDP instead of TCP, and because currently there is no verification for DNS information.
    More secure protocol DNSSEC solves this problem
    With DNSSEC enabled, the authoritative DNS server would respond with **security signatures** that can be fully validated at each delegation level all the way to root, making it extremely difficult or nearly impossible for the attacker to spoof.

DNS configs

    Start of Authority (SOA). Info about Zone/domain
    IP addresses IPv4(A). Domain => IP address
    IP addresses IPv6(AAAA).
    SMTP mail exchangers (MX).
    Name servers (NS).
    Pointers for reverse DNS lookups (PTR). IP address => Domain
    Domain name aliases (CNAME).
    Everything worked fine (NOERROR).
    The NXDOMAIN is a DNS message type received by the DNS resolver (i.e. client) when a request to resolve a domain is sent to the DNS and cannot be resolved to an IP address.  An NXDOMAIN error message means that the domain does not exist.
    
NXDOMAIN Flood DDoS attack

    DNS server cache will be totally filled with NXDOMAIN failure results

ARP

    Pair MAC address with IP Address for IP connections.

Multiplex

    Timeshare, statistical share, just useful to know it exists.

Traceroute

    Usually uses UDP, but might also use ICMP Echo Request or TCP SYN. TTL, or hop-limit.
    Windows tracert => ICMP
    *nix traceroute => UDP
    Initial hop-limit is 128 for windows and 64 for *nix. 
    Destination returns ICMP Echo Reply.

Nmap

    TCP SYN scan (-sS)
        Half-open scanning. Nmap sends SYN packets to the destination, but it does not create any sessions. 

    TCP connect() scan (-sT)
        This is the default scanning technique because the SYN scan requires **root privilege**. 
        Unlike the TCP SYN scan, it completes the normal TCP three-way handshake process and requires the system to call connect(), which is a part of the operating system. 

    UDP scan (-sU)
        Used to find an open UDP port of the target machine.
        -sS ++ –sU => More effective 

    FIN scan (-sF)
        If firewall Blocks SYN packets 
        A FIN scan sends the packet only set with a FIN flag, so it is not required to complete the TCP handshaking.

        The target computer is **not able to create a log of this scan** (again, an advantage of FIN). 

    Xmas scan (-sX) OR Null scan (-sN)
        Null scan does not send any bit on the packet. 
        Xmas sends FIN, PSH and URG flags.

    Version detection (-sV)
        Version detection is the technique used to find out what software version is running on the target computer and on the respective ports. 

    Idle scan (-sI)
        Provides complete anonymity while scanning. 
        Nmap doesn’t send the packets from your real IP address — instead of generating the packets from the attacker machine, Nmap uses another host from the target network to send the packets. 

Intercepts (MiTM)

    Understand PKI (public key infrastructure in relation to this).
    Clients simply have all certificate checks disabled completely if they expect a self-signed certificate instead of expecting a specific self-signed certificate

VPN

    Hide traffic from ISP but expose traffic to VPN provider.

Tor

    Traffic is obvious on a network.
    How do organised crime investigators find people on tor networks. Tor entry and exit nodes

Proxy

    Why 7 proxies won’t help you.

BGP

    Border Gateway Protocol.
    Holds the internet together.
    BGP route manipulation: A malicious device alters the content of the BGP table, preventing traffic from reaching the intended destination.
    BGP route hijacking: A rogue device maliciously announces a victim’s prefixes to reroute traffic to or through itself, which otherwise would not happen. Rerouting traffic can cause instability in some networks with a sudden load increase. This allows attackers to access potentially unencrypted traffic to which they would otherwise not have access or use hijacked BGP to launch spam campaigns, bypassing IP blacklist mitigation.
    BGP denial-of-service (DoS): A malicious device sends unexpected or undesirable BGP traffic to a victim, exhausting all resources and rendering the target system incapable of processing valid BGP traffic.
    2008, when a BGP hijack caused a global **YouTube** outage.
    In November 2017, a router misconfiguration at internet backbone provider Level 3 resulted in a widespread, global BGP route leak.
    In October 2017, services such as **Twitter and Google** in Brazil were unreachable due to a BGP leak incident.
    In August 2017, **Japan** experienced a countrywide internet outage due to leaked BGP advertisements.
    In April 2017, a possible BGP hijack led to concerns about rerouted financial network traffic.

Network traffic tools

    Wireshark - PACKET sniffer
    Tcpdump
    Burp suite - It operates as a web proxy server between your browser and target applications, and lets you intercept, inspect, and modify the raw traffic passing in both directions

HTTP/S

    (80, 443)

SSL/TLS

    (443)
    Super important to learn this, includes learning about handshakes, encryption, signing, certificate authorities, trust systems. A good primer on all these concepts and algorithms is made available by the Dutch cybersecurity center.
    Various attacks against older versions of SSL/TLS (with catchy names) on Wikipedia.
    
    Renegotiation attack - An attacker who can hijack an https connection to splice their own requests into the beginning of the conversation the client has with the web server. 
    BEAST attacks - An attacker observing 2 consecutive ciphertext blocks C0, C1 can test if the plaintext block P1 is equal to x by choosing the next plaintext block P2 as per CBC operation. The vulnerability of the attack had been fixed with TLS 1.1 in 2006
    RC4 attacks - Researchers discovered statistical biases in the RC4 key table to recover parts of the plaintext with a large number of TLS encryptions.
    TLS Compression (CRIME attack) - Allows an attacker to recover the content of web cookies when data compression is used along with TLS.
    Heartbleed - Allows anyone on the Internet to read the memory of the systems protected by the vulnerable versions of the OpenSSL 
    ChangeCipherSpec injection attack - 
    DROWN attack - Sservers supporting contemporary SSL/TLS protocol suites by exploiting their support for the obsolete, insecure, SSLv2 protocol to leverage an attack on connections using up-to-date protocols that would otherwise be secure
    POODLE attack against TLS - Attackers only need to make 256 SSL 3.0 requests to reveal one byte of encrypted messages. A variant of POODLE was announced that impacts TLS implementations that do not properly enforce padding byte requirements
    Protocol downgrade
        FREAK - Attack involved tricking servers into negotiating a TLS connection using cryptographically weak 512 bit encryption keys.
        LOGJAM - Logjam is a security exploit discovered in May 2015 that exploits the option of using legacy "export-grade" 512-bit Diffie–Hellman groups dating back to the 1990s.[21] It forces susceptible servers to downgrade to cryptographically weak 512-bit Diffie–Hellman groups

TCP/UDP

    Web traffic, chat, voip, traceroute.
    TCP will throttle back if packets are lost but UDP doesn't.
    Streaming can slow network TCP connections sharing the same network.

ICMP

    Ping and traceroute.

Mail

    SMTP (25, 587, 465)
    IMAP (143, 993)
    POP3 (110, 995)

SSH

    (22)
    Handshake uses asymmetric encryption to exchange symmetric key.

Telnet

    (23, 992)
    Allows remote communication with hosts.

ARP

    Who is 0.0.0.0? Tell 0.0.0.1.
    Linking IP address to MAC, Looks at cache first.

DHCP

    (67, 68) (546, 547)
    Dynamic (leases IP address, not persistent).
    Automatic (leases IP address and remembers MAC and IP pairing in a table).
    Manual (static IP set by administrator).

IRC

    Understand use by hackers (botnets).

FTP/SFTP

    (21, 22)

RPC

    Predefined set of tasks that remote clients can execute.
    Used inside orgs.

Service ports

    0 - 1023: Reserved for common services - sudo required.
    1024 - 49151: Registered ports used for IANA-registered services.
    49152 - 65535: Dynamic ports that can be used for anything.

HTTP Header

    | Verb | Path | HTTP version |
    Domain
    Accept
    Accept-language
    Accept-charset
    Accept-encoding(compression type)
    Connection- close or keep-alive
    Referrer
    Return address
    Expected Size?

HTTP Response Header

    HTTP version
    Status Codes:
        1xx: Informational Response
        2xx: Successful
        3xx: Redirection
        4xx: Client Error
        5xx: Server Error
    Type of data in response
    Type of encoding
    Language
    Charset

UDP Header

    Source port
    Destination port
    Length
    Checksum

Broadcast domains and collision domains.

Root stores

CAM table overflow
