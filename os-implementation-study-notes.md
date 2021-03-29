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
    MAC vs DAC
        Discretionary Access Control - The owner of the resource has the complete control over who can have access to a specific resource
        Mandatory Access Control - Access is determined by the system, not by the owner
            Systems that contain highly sensitive data such as government or military based systems use this access control type.
        DAC is more flexible than MAC
        MAC is more secure than DAC
        DAC is easier to implement than MAC
    /proc
        
        /proc/cmdline – Kernel command line information.
        /proc/console – Information about current consoles including tty.
        /proc/devices – Device drivers currently configured for the running kernel.
        /proc/dma – Info about current DMA channels.
        /proc/fb – Framebuffer devices.
        /proc/filesystems – Current filesystems supported by the kernel.
        /proc/iomem – Current system memory map for devices.
        /proc/ioports – Registered port regions for input output communication with device.
        /proc/loadavg – System load average.
        /proc/locks – Files currently locked by kernel.
        /proc/meminfo – Info about system memory (see above example).
        /proc/misc – Miscellaneous drivers registered for miscellaneous major device.
        /proc/modules – Currently loaded kernel modules.
        /proc/mounts – List of all mounts in use by system.
        /proc/partitions – Detailed info about partitions available to the system.
        /proc/pci – Information about every PCI device.
        /proc/stat – Record or various statistics kept from last reboot.
        /proc/swap – Information about swap space.
        /proc/uptime – Uptime information (in seconds).
        /proc/version – Kernel version, gcc version, and Linux distribution installed
        
    /proc’s numbered directories are PIDs. Inside that it has =>        
        cmdline – command line of the process
        environ – environmental variables
        fd – file descriptors
        limits – contains information about the limits of the process
        mounts – related information


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
