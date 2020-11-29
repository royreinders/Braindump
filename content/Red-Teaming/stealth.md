---
title: "Stealth"
date: 2020-07-16T13:41:37+02:00
draft: false
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

#### Powershell downgrade
Current systems with modern versions of PowerShell have several defensive (and logging) mechanisms built in. To mitigate; downgrade the PowerShell version when issueing a command:

```powershell
powershell -version 2 <command>
```
This bypasses transcript logging, but might not be effective against all mitigations (logging with sysmon for example).
***

#### Decoupling execution of a program to prevent parent-child analysis. ToDo
A lot of modern detection mechanisms rely on identifying execution chains that look suspicious. Excel spawning a Powershell process, which in turn executes psexec for example, is very suspicious. There are multiple methods to spawn malicious programs from another process, so a possible suspicious looking chains is broken.

* Execution via WMI
* Execution via COM objects
    https://github.com/christophetd/spoofing-office-macro/blob/master/macro.vba
* Parent PID Spoofing

***



