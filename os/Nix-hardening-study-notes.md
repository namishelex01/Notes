# \*NIX

## Hardening

### Partitioning
    
    Separate /boot
    Separate /home
    Separate /usr
    Separate /var
    Separate /var/log and /var/log/audit
    Separate /tmp and /var/tmp
    Restrict /usr mount options
    Restrict /var mount options
    Restrict /var/log and /var/log/audit mount options
    Restrict /proc mount options
    Restrict /boot mount options
    Restrict /home mount options
    Restrict /tmp/ and /var/tmp mount options
    Restrict /dev/shm mount options
    Polyinstantiated /tmp and /var/tmp
    Set group for /dev/shm
    Encrypt swap
    
### Password for Single User Mode
    
    # Edit /etc/sysconfig/init.
    SINGLE=/sbin/sulogin
    
### Protect bootloader config files

    # Set the owner and group of /etc/grub.conf to the root user:
    chown root:root /etc/grub.conf
    chown -R root:root /etc/grub.d

    # Set permissions on the /etc/grub.conf or /etc/grub.d file to read and write for root only:
    chmod og-rwx /etc/grub.conf
    chmod -R og-rwx /etc/grub.d
    
### Restricting access to kernel logs

    echo "kernel.dmesg_restrict = 1" > /etc/sysctl.d/50-dmesg-restrict.conf

### Restricting access to kernel pointers

    echo "kernel.kptr_restrict = 1" > /etc/sysctl.d/50-kptr-restrict.conf

### ExecShield protection

    echo "kernel.exec-shield = 2" > /etc/sysctl.d/50-exec-shield.conf

### Randomise memory space

    echo "kernel.randomize_va_space=2" > /etc/sysctl.d/50-rand-va-space.conf
    
### Ensure syslog service is enabled and running

    systemctl enable rsyslog
    systemctl start rsyslog

### Update password policy

    authconfig --passalgo=sha512 \
    --passminlen=14 \
    --passminclass=4 \
    --passmaxrepeat=2 \
    --passmaxclassrepeat=2 \
    --enablereqlower \
    --enablerequpper \
    --enablereqdigit \
    --enablereqother \
    --update

### Limit password reuse

    # Edit /etc/pam.d/system-auth

    # For the pam_unix.so case:
    password sufficient pam_unix.so ... remember=5

    # For the pam_pwhistory.so case:
    password requisite pam_pwhistory.so ... remember=5

### Secure /etc/login.defs password policy

    # Edit /etc/login.defs
    PASS_MIN_LEN 14
    PASS_MIN_DAYS 1
    PASS_MAX_DAYS 60
    PASS_WARN_AGE 14

### Set auto logout inactive users

    echo "readonly TMOUT=900" >> /etc/profile.d/idle-users.sh
    echo "readonly HISTFILE" >> /etc/profile.d/idle-users.sh
    chmod +x /etc/profile.d/idle-users.sh
    
### Set last logon/access notification

    # Edit /etc/pam.d/system-auth
    session required pam_lastlog.so showfailed
    
### Lock out accounts after a number of incorrect login

    # Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth

    # Add the following line immediately before the pam_unix.so statement in the AUTH section:
    auth required pam_faillock.so preauth silent deny=3 unlock_time=never fail_interval=900

    # Add the following line immediately after the pam_unix.so statement in the AUTH section:
    auth [default=die] pam_faillock.so authfail deny=3 unlock_time=never fail_interval=900

    # Add the following line immediately before the pam_unix.so statement in the ACCOUNT section:
    account required pam_faillock.so
    
### Enable hard/soft link protection

    echo "fs.protected_hardlinks = 1" > /etc/sysctl.d/50-fs-hardening.conf
    echo "fs.protected_symlinks = 1" >> /etc/sysctl.d/50-fs-hardening.conf

### Disable uncommon filesystems

    echo "install cramfs /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install freevxfs /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install jffs2 /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install hfs /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install hfsplus /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install squashfs /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install udf /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install fat /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install vfat /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install nfs /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install nfsv3 /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install gfs2 /bin/false" > /etc/modprobe.d/uncommon-fs.conf

### Set SELinux Enforcing mode

    # Edit /etc/selinux/config.
    SELINUXTYPE=enforcing

### Enable TCP SYN Cookie protection

    echo "net.ipv4.tcp_syncookies = 1" > /etc/sysctl.d/50-net-stack.conf

### Disable IP source routing

    echo "net.ipv4.conf.all.accept_source_route = 0" > /etc/sysctl.d/50-net-stack.conf

### Disable ICMP redirect acceptance

    echo "net.ipv4.conf.all.accept_redirects = 0" > /etc/sysctl.d/50-net-stack.conf
    
### Enable ignoring to ICMP requests

    echo "net.ipv4.icmp_echo_ignore_all = 1" > /etc/sysctl.d/50-net-stack.conf

### Enable ignoring broadcasts request

    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" > /etc/sysctl.d/50-net-stack.conf
