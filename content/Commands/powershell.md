---
title: "PowerShell"
date: 2020-07-16T13:41:37+02:00
draft: false
---

#### Quick script to validate domain credentials
```
$cred = Get-Credential #Read credentials
$username = $cred.username
$password = $cred.GetNetworkCredential().password

# Get current domain using logged-on user's credentials
$CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
$domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$UserName,$Password)

if ($domain.name -eq $null)
{
 write-host "Authentication failed - please verify your username and password."
}
else
{
 write-host "Successfully authenticated with domain $domain.name"
}
```
***