Networking

    OSI Model
        Application; layer 7 (and basically layers 5 & 6) (includes API, HTTP, etc).
        Transport; layer 4 (TCP/UDP).
        Network; layer 3 (Routing).
        Datalink; layer 2 (Error checking and frame synchronisation).
        Physical; layer 1 (Bits over fibre).

    Firewalls
        Rules to prevent incoming and outgoing connections.

    NAT
        Useful to understand IPv4 vs IPv6.

    DNS
        (53)
        Requests to DNS are usually UDP, unless the server gives a redirect notice asking for a TCP connection. Look up in cache happens first. DNS exfiltration. Using raw IP addresses means no DNS logs, but there are HTTP logs. DNS sinkholes.
        In a reverse DNS lookup, PTR might contain- 2.152.80.208.in-addr.arpa, which will map to 208.80.152.2. DNS lookups start at the end of the string and work backwards, which is why the IP address is backwards in PTR.

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
