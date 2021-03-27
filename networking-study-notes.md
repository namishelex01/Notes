Networking

OSI Model

    - Application; layer 7 (and basically layers 5 & 6) (includes API, HTTP, etc).
    - Presentation; encryption/decryption
    - Session; controls session for system restart or network termination
    - Transport; layer 4 (TCP/UDP for SEGMENTS).
    - Network; layer 3 (Routing of network PACKETS).
    - Datalink; layer 2 (Error checking CRC and FRAME synchronisation) MAC addresses
    - Physical; layer 1 (BITS over fibre).

Firewalls

    Rules to prevent incoming and outgoing connections.
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
    Look up in cache happens first. DNS exfiltration. Using raw IP addresses means no DNS logs, but there are HTTP logs. 
    DNS sinkholes
        - DNS sinkholing helps you to identify infected hosts on the protected network using DNS traffic in situations where the firewall cannot see the infected client's DNS query (that is, the firewall cannot see the originator of the DNS query). 
        - In a typical deployment where the firewall is north of the local DNS server, the threat log will identify the local DNS resolver as the source of the traffic rather than the actual infected host. 
        - Sinkholing malware DNS queries solves this visibility problem by forging responses to the client host queries directed at malicious domains, so that clients attempting to connect to malicious domains (for c2, e.g.) will instead attempt to connect to a default sinkhole IP address
        - Infected hosts can then be easily identified in the traffic logs.
    In a reverse DNS lookup, PTR might contain- 2.152.80.208.in-addr.arpa, which will map to 208.80.152.2
    DNS lookups start at the end of the string and work backwards, which is why the IP address is backwards in PTR.

DNS exfiltration

    Sending data as subdomains.
    26856485f6476a567567c6576e678.badguy.com
    Doesn’t show up in http logs.

DNS configs

    Start of Authority (SOA).
    IP addresses (A and AAAA).
    SMTP mail exchangers (MX).
    Name servers (NS).
    Pointers for reverse DNS lookups (PTR).
    Domain name aliases (CNAME).

ARP

    Pair MAC address with IP Address for IP connections.

DHCP

    UDP (67 - Server, 68 - Client)
    Dynamic address allocation (allocated by router).
    DHCPDISCOVER -> DHCPOFFER -> DHCPREQUEST -> DHCPACK

Multiplex

    Timeshare, statistical share, just useful to know it exists.

Traceroute

    Usually uses UDP, but might also use ICMP Echo Request or TCP SYN. TTL, or hop-limit.
    Initial hop-limit is 128 for windows and 64 for *nix. Destination returns ICMP Echo Reply.

Nmap

    Network scanning tool.

Intercepts (MiTM)

    Understand PKI (public key infrastructure in relation to this).

VPN

    Hide traffic from ISP but expose traffic to VPN provider.

Tor

    Traffic is obvious on a network.
    How do organised crime investigators find people on tor networks.

Proxy

    Why 7 proxies won’t help you.

BGP

    Border Gateway Protocol.
    Holds the internet together.

Network traffic tools

    Wireshark
    Tcpdump
    Burp suite

HTTP/S

    (80, 443)

SSL/TLS

    (443)
    Super important to learn this, includes learning about handshakes, encryption, signing, certificate authorities, trust systems. A good primer on all these concepts and algorithms is made available by the Dutch cybersecurity center.
    Various attacks against older versions of SSL/TLS (with catchy names) on Wikipedia.

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
