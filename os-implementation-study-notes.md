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

    GateKeeper
        When a user downloads and opens an app, a plug-in or an installer package from outside the App Store, Gatekeeper verifies that the software is from an identified developer, is notarised by Apple to be free of known malicious content, and hasn’t been altered. Gatekeeper also requests user approval before opening downloaded software for the first time to make sure the user hasn’t been tricked into running executable code they believed to simply be a data file.
    Gotofail error (SSL)
        An attacker with a privileged network position may capture or modify data in sessions protected by SSL/TLS
    MacSweeper
        rogue application that misleads users by exaggerating reports about spyware, adware or viruses
    Research Mac vulnerabilities.
