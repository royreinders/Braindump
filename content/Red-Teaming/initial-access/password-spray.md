---
title: "Password Spray"
date: 2020-07-17T20:59:33+02:00
draft: false
---

#### Checking louckout policies

#### Discovering Password spraying endpoints

##### Logging in through office.com
When you login to https://office.com using a (nonexistent) e-mail address, with the targets domainname you'll be redirected to either ADFS (in a hybrid environment) or the microsft login page (in an O365 setup).

##### Running Amass with Aquatone
Amass (or other domain-enum tools) can be used to get domainnames, which in turn can be used as input for aquatone. Aquatone can run screenshot scans on a predefined ports for the discovered domains:

```
$ amass -active -brute -o hosts.txt -d yahoo.com
$ cat hosts.txt | aquatone
```
***

#### Password spraying OWA or LYNC using Sprayingtoolkit ToDo


#### Password spraying ADFS using Burp ToDo
In the intruder attack window, inverse search for 'incorrect' to filter valid (or expired) login attempts.