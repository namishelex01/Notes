# Priv Esc

`'execve' => '/usr/bin/sudoedit'`

Detects exploitation attempt of vulnerability described in CVE-2021-3156. Alternative approach might be to look for flooding of auditd logs due to bruteforcing required to trigger the heap-based buffer overflow.

