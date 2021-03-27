# Mitigations

Patching

Data Execution Prevention

Address space layout randomisation

    To make it harder for buffer overruns to execute privileged instructions at known addresses in memory.

Principle of least privilege

    Eg running Internet Explorer with the Administrator SID disabled in the process token. Reduces the ability of buffer overrun exploits to run as elevated user.

Code signing

    Requiring kernel mode code to be digitally signed.

Compiler security features

    Use of compilers that trap buffer overruns.

Encryption

    Of software and/or firmware components.

Mandatory Access Controls

    (MACs)
    Operating systems with Mandatory Access Controls - eg. SELinux.

"Insecure by exception"

    When to allow people to do certain things for their job, and how to improve everything else. Don't try to "fix" security, just improve it by 99%.

Do not blame the user

    Security is about protecting people, we should build technology that people can trust, not constantly blame users.
