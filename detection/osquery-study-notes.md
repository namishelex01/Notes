# OSQuery threat hunt queries from IR pack




Identify malware that uses this persistence mechanism to launch at system boot

    select * from launchd;
    # Retrieves all the daemons that will run in the start of the target OSX system.


Identify malware that uses this persistence mechanism to launch at a given interval
    
    select * from startup_items;
    # Retrieve all the items that will load when the target OSX system starts.


Identify malware that uses this persistence mechanism to launch at a given interval
    
    select * from crontab;
    # Retrieves all the jobs scheduled in crontab in the target system.


Identify malware that uses this persistence mechanism to launch at system boot

    select key, subkey, value from plist where path = '/Library/Preferences/com.apple.loginwindow.plist';
    # Retrieves all the values for the loginwindow process in the target OSX system.


Identify malware that uses this persistence mechanism to launch at system boot

    select key, subkey, value from plist where path = '/Library/Preferences/loginwindow.plist';
    # Retrieves all the values for the loginwindow process in the target OSX system.



Identify malware that uses this persistence mechanism to launch at system boot

    select username, key, subkey, value from plist p, (select * from users where directory like '/Users/%') u where p.path = u.directory || '/Library/Preferences/com.apple.loginwindow.plist';
    # Retrieves all the values for the loginwindow process in the target OSX system.



Identify malware that uses this persistence mechanism to launch at system boot

    select username, key, subkey, value from plist p, (select * from users where directory like '/Users/%') u where p.path = u.directory || '/Library/Preferences/loginwindow.plist';
    # Retrieves all the values for the loginwindow process in the target OSX system.



Verify firewall settings are as restrictive as you need. Identify unwanted firewall holes made by malware or humans

    select * from alf;
    # Retrieves the configuration values for the Application Layer Firewall for OSX.



Verify firewall settings are as restrictive as you need. Identify unwanted firewall holes made by malware or humans

    select * from alf_exceptions;
    # Retrieves the exceptions for the Application Layer Firewall in OSX.



Verify firewall settings are as restrictive as you need. Identify unwanted firewall holes made by malware or humans

    select * from alf_services;
    # Retrieves the services for the Application Layer Firewall in OSX.



Verify firewall settings are as restrictive as you need. Identify unwanted firewall holes made by malware or humans

    select * from alf_explicit_auths;
    # Retrieves the list of processes with explicit authorization for the Application Layer Firewall.




Identify network communications that are being redirected. Example

    select * from etc_hosts;
    # Retrieves all the entries in the target system /etc/hosts file.



Identify malware that has a kernel extension component.

    select * from kernel_extensions;
    # Retrieves all the information about the current kernel extensions for the target OSX system.


Identify malware that has a kernel module component.

    select * from kernel_modules;
    # Retrieves all the information for the current kernel modules in the target Linux system.



Useful for intrusion detection and incident response. Verify assumptions of what accounts should be accessing what systems and identify machines accessed during a compromise.

    select * from last;
    # Retrieves the list of the latest logins with PID, username and timestamp.



Identify malware, adware, or vulnerable packages that are installed as an application.

    select * from apps;
    # Retrieves all the currently installed applications in the target OSX system.



Identify malware via connections to known bad IP addresses as well as odd local or remote port bindings

    select distinct pid, family, protocol, local_address, local_port, remote_address, remote_port, path from process_open_sockets where path <> '' or remote_address <> '';
    # Retrieves all the open sockets per process in the target system.




Identify processes accessing sensitive files they shouldn't

    select distinct pid, path from process_open_files where path not like '/private/var/folders%' and path not like '/System/Library/%' and path not in ('/dev/null', '/dev/urandom', '/dev/random');
    # Retrieves all the open files per process in the target system.



Useful for intrusion detection and incident response. Verify assumptions of what accounts should be accessing what systems and identify machines accessed during a compromise.

    select liu.*, p.name, p.cmdline, p.cwd, p.root from logged_in_users liu, processes p where liu.pid = p.pid;
    # Retrieves the list of all the currently logged in users in the target system.



Identify if a machine is being used as relay.

    select * from system_controls where oid = '4.30.41.1' union select * from system_controls where oid = '4.2.0.1';
    # Retrieves the current status of IP/IPv6 forwarding.



Insight into the process data

    select * from process_envs;
    # Retrieves all the environment variables per process in the target system.



Scope for lateral movement. Potential exfiltration locations. Potential dormant backdoors.

    select * from mounts;
    # Retrieves the current list of mounted drives in the target system.



Scope for lateral movement. Potential exfiltration locations. Potential dormant backdoors.

    select * from nfs_shares;
    # Retrieves the current list of Network File System mounted shares.


Identify actions taken. Useful for compromised hosts.

    select * from users join shell_history using (uid);
    # Retrieves the command history, per user, by parsing the shell history files.




Identify recently accessed items. Useful for compromised hosts.

    select username, key, value from plist p, (select * from users where directory like '/Users/%') u where p.path = u.directory || '/Library/Preferences/com.apple.recentitems.plist';
    # Retrieves the list of recent items opened in OSX by parsing the plist per user.



Identify if an attacker is using temporary, memory storage to avoid touching disk for anti-forensics purposes

    select * from block_devices where type = 'Virtual Interface';
    # Retrieves all the ramdisk currently mounted in the target system.



Detect if a listening port iis not mapped to a known process. Find backdoors.

    select * from listening_ports;
    # Retrieves all the listening ports in the target system.



Detect backdoor binaries (attacker may drop a copy of /bin/sh). Find potential elevation points / vulnerabilities in the standard build.

    select * from suid_bin;
    # Retrieves all the files in the target system that are setuid enabled.



Ability to compare with known good. Identify mapped regions corresponding with or containing injected code.

    select * from process_memory_map;
    # Retrieves the memory map per process in the target Linux system.



Determine if MITM in progress.

    select * from arp_cache;
    # Retrieves the ARP cache values in the target system.



Identifies connections to rogue access points.

    select ssid, network_name, security_type, last_connected, captive_portal, possibly_hidden, roaming, roaming_profile from wifi_networks;
    # Retrieves all the remembered wireless network that the target machine has connected to.



Identifies a system potentially vulnerable to disk cloning.

    select * from disk_encryption;
    # Retrieves the current disk encryption status for the target system.



Verify firewall settings are as restrictive as you need. Identify unwanted firewall holes made by malware or humans

    select * from iptables;
    # Retrieves the current filters and chains per filter in the target system.



Post-priori hijack detection, detect potential sensitive information leakage.

    select * from app_schemes;
    # Retrieves the list of application scheme/protocol-based IPC handlers.



Post-priori hijack detection, detect potential sensitive information leakage.

    select * from sandboxes;
    # Lists the application bundle that owns a sandbox label.

