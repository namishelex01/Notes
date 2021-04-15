# Securing Docker

### Docker Concepts

| Start container with interactive shell | List all containers | Listing docker images | Run container in background | Looking at the logs (stdout) of a container |
|:---:|:---:|:---:|:---:|:---:|
| `docker run --name samplecontainer -it ubuntu:latest /bin/bash` | `docker ps -a` | `docker images` | `docker run --name pingcontainer -d alpine:latest ping 127.0.0.1 -c 5` | `docker logs -f pingcontainer` |

| Inspecting container or image | Docker history | Stopping and removing container | Build docker container | Run the container |
|:---:|:---:|:---:|:---:|:---:|
| `docker inspect <container name>` <br> `docker inspect <image name>` | `docker history jess/htop` | `docker stop somecontainer` <br> `docker rm somecontainer` | `cd somefolder` <br> `vi DockerFile` <br> `docker build -t abh1sek/htop:1.0 .` | `docker run --rm -it abh1sek/htop:1.0` |

| Docker volumes | Docker networks | Starting new service in docker swarm cluster | Inspecting a service | Leaving the swarm cluster |
|:---:|:---:|:---:|:---:|:---:|
| `docker volume ls` <br> `docker volume create c0c0n` | `docker network ls` <br> `docker network create c0c0n` | `docker service create --replicas 1 --publish 5555:80 --name nginxservice nginx:alpine` | `docker service inspect --pretty nginxservice` | `docker swarm leave` <br> `docker swarm leave --force` |

### Docker Namespaces, capabilities and control groups

Docker uses namespaces to provide the isolated workspace called the container. When you run a container, Docker creates a set of namespaces for that container.

- `pid` namespace: Process isolation (PID: Process ID)
- `net` namespace: Managing network interfaces (NET: Networking)
- `ipc` namespace: Managing access to IPC resources (IPC: InterProcess Communication)
- `mnt` namespace: Managing filesystem mount points (MNT: Mount)
- `uts` namespace: Different host and domain names (UTS: Unix Timesharing System)
- `user` namespace: Isolate security-related identifiers (USER: userid, groupid)

**Capabilities** turn the binary "root/non-root" into a fine-grained access control system. Processes (like web servers) that just need to bind on a port below 1024 do not have to run as root, they can just be granted the net_bind_service capability instead.

Checking for the list of capabilities

    capsh --print
    
It is possible to access the host devices from the privileged containers using more `/dev/kmsg`. The `/dev/kmsg` character device node provides userspace access to the kernel's printk buffer.

The kernel uses **cgroups** also known as control groups to group processes for the purpose of system resource management. Cgroups allocate CPU time, system memory, network bandwidth, or combinations of these among user-defined groups of tasks.

### Attacking insecure volume mounts

- If we have shell inside the docker container and `ls -l /var/run/docker.sock` is available and mounted from the host system.
- This allows attacker to access the host docker service using host option with docker client by using the UNIX socket
- The docker client is already downloaded into the container and is at `/root/docker`
To access the host resource using the `docker.sock` UNIX socket

    ./docker -H unix:///var/run/docker.sock ps
    ./docker -H unix:///var/run/docker.sock images

Mitigation:-
- Use the `2376` port for exposing if required to expose the Docker API. Otherwise use `fd` or `socket` to expose the docker runtime daemon

### Attacking docker misconfigurations

The Docker daemon can listen for Docker Engine API requests via three different types of Socket unix, tcp, and fd. 

To access remotely we have to enable tcp socket. The default setup provides un-encrypted and un-authenticated direct access to the Docker daemon. It is conventional to use port 2375 for un-encrypted, and port 2376 for encrypted communication with the daemon.

    nmap -p 2375,2376 -n 192.168.56.4 -v
    
    # Query docker API using curl
    curl 192.168.56.4:2375/images/json | jq .
    
    # Attacker can abuse this by using the docker daemon configuration to access the host system's docker runtime
    docker -H tcp://<IP>:2375 ps
    docker -H tcp://<IP>:2375 images

### Auditing docker images and containers

Show the history of a docker image. It will list the commands that were used for creating the image

    docker history custom-htop
    
### Auditing docker networks and volumes

Inspecting docker volumes

    docker volume inspect 1e030154f4952361cec6c21e838a0fb617c7b7cc6359570407eb9f697b229b67

Looking for sensitive data 

    sudo -i
    cd /var/lib/docker/volumes/1e030154f4952361cec6c21e838a0fb617c7b7cc6359570407eb9f697b229b67/_data
    ls
    grep -i 'flag' wp-config.php
    grep -i 'password' wp-config.php

### Docker integrity checks

We can list the changed files and directories in a containers filesystem => `docker diff checkintegriy`
There are 3 events that are listed in the diff
    
    A - Add
    D - Delete
    C - Change

### Auditing docker runtime

Checking for the docker daemon configuration

    docker system info
    
Checking for the docker API exposed on 0.0.0.0

    sudo cat /lib/systemd/system/docker.service

Checking if the docker socket is mounted to any running container

    docker inspect | grep -i '/var/run/'

Checking other files and data related to docker

    sudo ls -l /var/lib/docker/

### Auditing docker registries

Check if the docker registry is up

    curl -s http://localhost:5000/v2/_catalog | jq .

Get the list of tags and versions of a docker image from the registry

    curl -s http://localhost:5000/v2/devcode/tags/list | jq .
    
Downloading a registry image locally

    docker pull localhost:5000/devcode:latest
    
Reviewing the container for sensitive data and hard-coded secrets

    docker run --rm -it localhost:5000/devcode:latest sh
    cat /.aws/credentials

Prints the default username and registry used by the docker runtime

    docker system info
    
Lets look for the configured registries from the host. The credentials may authorize us to pull and/or push images to the registry

    cat ~/.docker/config.json

### Attacking container capabilities

Check for existing capabilities by running `capsh --print`

Container has enabled `--pid=host` so we can access then host process using top command

Since an attacker can list host processes and has the `sys_ptrace` capability. Attacker can exploit this scenario to inject and execute code from the address space of any host process. This effectively results in a docker escape as the attacker can execute code outside the container.

### Linux security module : Apparmor

The Linux Security Module (LSM) framework provides a mechanism for various security checks to be hooked by new kernel extensions.

    docker run --rm -it --name lsm-after \
        --security-opt="apparmor:docker-nginx-sample" -p 4320:80 nginx bash


### Attacking swarm cluster secrets

### Attacking private registry images

### Docker bench security audit

### Container security monitoring

Reference:- [Attacking Docker by Madhu Akula](https://madhuakula.com/content/attacking-and-auditing-docker-containers-and-kubernetes-clusters/index.html)
