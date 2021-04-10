# Persistence

`SYSCALL => '/useradd'`

Detects the creation of a new user account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system.

`PATH => '/home/*/.bashrc' OR '/home/*/.bash_profile' OR '/home/*/.profile' OR '/etc/profile' OR '/etc/shells' OR '/etc/bashrc' OR '/etc/csh.cshrc' OR '/etc/csh.login'`

Detects change of user environment. Adversaries can insert code into these files to gain persistence each time a user logs in or opens a new shell.

`'execve' => 'detect_execve_www'`

Detects possible command execution by web application/web shell

