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


### Attacking insecure volume mounts

- If we have shell inside the docker container and `ls -l /var/run/docker.sock` is available and mounted from the host system.
- This allows attacker to access the host docker service using host option with docker client by using the UNIX socket
- The docker client is already downloaded into the container and is at `/root/docker`
- To access the host resource using the `docker.sock` UNIX socket
    
    ./docker -H unix:///var/run/docker.sock ps
    ./docker -H unix:///var/run/docker.sock images


### Attacking docker misconfigurations

### Auditing docker images and containers

### Auditing docker networks and volumes

### Docker integrity checks

### Auditing docker runtime and registries

### Attacking container capabilities

### Linux security module : Apparmor

### Attacking swarm cluster secrets

### Attacking private registry images

### Docker bench security audit

### Container security monitoring

Reference:- [Attacking Docker by Madhu Akula](https://madhuakula.com/content/attacking-and-auditing-docker-containers-and-kubernetes-clusters/index.html)
