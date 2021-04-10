# Containers Security

| Exploit | Prevention |
|---|---|
| `mknod` linux syscall to escalate privileges in host machine if user has root access in container. This syscall creates a filesystem node (file, device special file, or named pipe) named pathname, with attributes specified by mode and dev. <br> If a block device is created within the container it can be accessed through the /proc/PID/root/ folder by someone outside the container, the limitation being that the process must be owned by the same user outside and inside the container. | Following best practice of ensuring nobody is root within the container. <br><br> Running Docker with the parameter `–cap-drop=MKNOD` |

---

| Exploit | Prevention |
|---|---|
| Abuse of the /proc/PID/root link into mount namespaces is that it can aid in the abuse of symlink vulnerabilities.
