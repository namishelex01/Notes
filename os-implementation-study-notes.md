# OS implementation and systems

Privilege escalation techniques, and prevention.

Buffer Overflows.

Directory traversal (prevention).

Remote Code Execution / getting shells.

Local databases

    Some messaging apps use sqlite for storing messages
    Useful for digital forensics, especially on phones.

Windows

    Windows registry and group policy.
    Windows SMB.
    Samba (with SMB).
    Buffer Overflows.
    ROP.

*nix

    SELinux.
    Kernel, userspace, permissions.
    MAC vs DAC.
    /proc
    /tmp - code can be saved here and executed.
    /shadow
        $6$sTgBhfj0$pkzz/JpVTl8ZAmk./d4SDarRyWsGSZHguljywUHQMP4DWo8/TgNzL5rMpejqNWuyxtFlISxdyIqPmpsIsyi.i1
         - -------- --------------------------------------------------------------------------------------
         1    2                                             3
         
        1 = hash_algorithm (MD5, Blowfish, Eksblowfish, NT hashing, SHA-256, SHA-512 Algorithm)
        2 = hash_salt
        3 = hash_data

    LDAP - Lightweight Directory Browsing Protocol. Lets users have one password for many services. This is similar to Active Directory in windows.

MacOS

    Gotofail error (SSL)
        An attacker with a privileged network position may capture or modify data in sessions protected by SSL/TLS
    MacSweeper
        rogue application that misleads users by exaggerating reports about spyware, adware or viruses
    Research Mac vulnerabilities.
