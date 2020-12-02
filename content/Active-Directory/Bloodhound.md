---
title: "Bloodhound"
date: 2020-07-16T13:41:37+02:00
draft: false
---

#### Run Bloodhound from a non-domain joined system

```
runas /netonly /user:DOMAIN\USER powershell.exe cd C:\Users\user\Desktop\BloodHound-master\BloodHound-master\Ingestors Import-Module .\SharpHound.ps1
```

Alternatively: join a computer to the domain. Many domains allow the additions of a certain number of computers for every authorized user.


#### Run NEO4J in a docker container
Running NEO4j in a docker container lets you easily run the database without having to install all the dependancies on your host. Moreover, you can easility switch out the databases with every engagement and keep running the same local BloodHound app.

```
docker run \
--name Rijkevoort \
-p7474:7474 -p7687:7687 \
-d \
--user="$(id -u):$(id -g)" \
-v "$(pwd)/neo4j/data:/data" \
-v "$(pwd)/neo4j/logs:/logs" \
-v "$(pwd)/neo4j/import:/var/lib/neo4j/import" \
-v "$(pwd)/neo4j/plugins:/plugins" \
--env NEO4J_AUTH=neo4j/test \
neo4j:latest
```