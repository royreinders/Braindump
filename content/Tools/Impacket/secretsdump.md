---
title: "Secretsdump"
date: 2020-07-16T13:41:37+02:00
draft: true
---
asdas

#### Living Off The Land Binaries (LOLBINS)
Reference: https://lolbas-project.github.io/

#### Windows syscalls (Work Out)
Reference: https://j00ru.vexillium.org/syscalls/nt/64/

#### Password sniffing (Work Out)
Use the LanMan-old NPLogonNotify() function to sniff every single password used to logon to Windows. 
Cleartext. No reboot required. 
NPLogonNotify() - https://docs.microsoft.com/en-us/windows/win32/api/npapi/nf-npapi-nplogonnotify
The C source, and fully working DLL - https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy

Reference: https://carnal0wnage.attackresearch.com/2013/09/stealing-passwords-every-time-they.html
Reference: https://clymb3r.wordpress.com/2013/09/15/intercepting-password-changes-with-function-hooking/
Reference: https://sensepost.com/blog/2016/intercepting-passwords-with-empire-and-winning/
Reference: https://sensepost.com/blog/2019/recreating-known-universal-windows-password-backdoors-with-frida/
