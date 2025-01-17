# Execution


```
'SYSCALL' => 
# Temporary folder
- '/tmp/'
# Web server 
- '/var/www/'              # Standard
- '/home/*/public_html/'   # Per-user
- '/usr/local/apache2/'    # Classical Apache
- '/usr/local/httpd/'      # Old SuSE Linux 6.* Apache
- '/var/apache/'           # Solaris Apache
- '/srv/www/'              # SuSE Linux 9.*
- '/home/httpd/html/'      # Redhat 6 or older Apache
- '/srv/http/'             # ArchLinux standard
- '/usr/share/nginx/html/' # ArchLinux nginx
# Data dirs of typically exploited services (incomplete list)
- '/var/lib/pgsql/data/'
- '/usr/local/mysql/data/'
- '/var/lib/mysql/'
- '/var/vsftpd/'
- '/etc/bind/'
- '/var/named/'
```

Detects program executions in suspicious non-program folders related to malware or hacking activity

`'EXECVE' => ['chmod'] + ['777'] OR ['chmod'] + ['u+s'] OR ['cp'] + ['/bin/ksh'] OR ['cp'] + ['/bin/sh']`

Detects relevant commands often related to malware or hacking activity
