---
title: "Cobalt Strike"
date: 2020-07-17T20:59:33+02:00
draft: false
---

#### Installing Cobalt Strike
Before installing make sure your system has its firewall enabled and only allow necessary connections.
```
sudo ufw allow ssh
sudo ufw enable
```

Install OpenJDK11.
```
sudo apt update && sudo apt upgrade -y
sudo apt-get install openjdk-11-jdk
sudo update-java-alternatives -s java-1.11.0-openjdk-amd64
```

Download Cobalt Strike from https://www.cobaltstrike.com/download and upload it to the server into /opt/.
Then extract the acrchive, chown the directories/files and update Cobalt Strike.

```
tar zxvf cobaltstrike-dist.tgz
chown -R root:root cobaltstrike
cd /opt/cobaltstrike
./update
```

Fill in the license key. Now the latest version of Cobalt Strike will be downloaded and installed. Run the teamserver as follows:

```
screen -d -m -S teamserver sh -c 'while true; do /opt/cobaltstrike/teamserver <ip> "<password>" /opt/cobaltstrike/<profile>.profile; sleep 10; done'
```

Add firewall exception to access Cobalt Strike from a specific IP
```
ufw allow from <ip> to any port 50050
```

Add firewall exception for a listener
```
ufw allow 443
```


#### Check validity of Cobalt Strike profile
```
./c2lint <profile_path>
```











references:
 * Installing OpenJDK: https://www.cobaltstrike.com/help-java-dependency