---
title: "Recon"
date: 2020-07-16T13:41:37+02:00
draft: true
---
asdas

#### Get list of enabled AD-users
```
wmic
```

#### Discover Domain Controller from blackbox perspective
1. Open CMD or PowerShell.
2. Type nslookup, and then press ENTER.
3. Type set type=all, and then press ENTER.
4. Type _ldap._tcp.dc._msdcs.<domainname>, where Domain_Name is the name of your domain, and then press ENTER.


#### Enumerate AD users form an unauthenticated perspective
```
$ python3 samrdump.py <DC.Domain.local>
```