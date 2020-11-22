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