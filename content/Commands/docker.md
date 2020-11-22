---
title: "Docker"
date: 2020-07-16T13:41:37+02:00
draft: false
---

#### Docker
##### Show active docker containers
```docker ps```
##### Show all docker containers
```docker ps -a```
##### List all pulled Docker images
```docker images```
##### Attach to a docker container
```docker attach <container id>```
##### Detach from a running container
User CTRL+P, CTRL+Q to detach from the container while keeping it running

#### Dockerfile

##### Dockerfile

##### Build command
```$ docker build -t example --build-arg ssh_prv_key="$(cat ~/.ssh/id_rsa)" .```
I ran in to issues where the private key could not be copied to the docker container while keeping a correct format due to the newlines. The following commands converts the key into a single-line file.
```awk -v ORS='\\n' '1' key > key_singleline```

##### Run command
```docker run -it -d -p 1313:1313 --name hugo hugo```

##### Stop Command
```docker container stop hugo```