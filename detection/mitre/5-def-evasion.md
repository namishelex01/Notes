# Defense Evasion

`PATH => '/etc/ld.so.preload'`

Modification of ld.so.preload for shared object injection and load arbitrary code into processes.
    
`PATH => "/etc/audit/*" OR "/etc/libaudit.conf" OR "/etc/audisp/*" OR "/etc/syslog.conf" OR "/etc/rsyslog.conf" OR "/etc/syslog-ng/syslog-ng.conf"`

Detect changes in auditd or syslog daemon configuration files

`'execve' => 'cp' + '-i' + '/bin/sh' + '/crond'`

Masquerading occurs when the name or location of an executable, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation

