---
title: "adsisearcher"
date: 2020-07-16T13:41:37+02:00
draft: false
---
ADSIsearcher is a builtin on almost all Windows Operation systems, supporting as far back as PowerShell 2. It allows you to query the Active Directory using several commands and filters.

#### List of userfull adsisearcher commands
##### Get all users
Get users using one (giant, depending on the environment) LDAP query
```
([adsisearcher]"objectClass=user").findall()
```

