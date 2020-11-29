---
title: "Hashcat"
date: 2020-07-16T13:41:37+02:00
draft: false
---

#### Hashcat sessions
When using hashcat with the session flag you can specify a session file (by default the hashcat.restore file). Every restore point will be saved to this file, so cracking can be quit and resumed.

```
sudo hashcat -m 10000 -w3 hashes.txt wordlist.txt --session cracking_session1
```

To resume the session, issue the same command while adding the '--restore'-flag.

```
sudo hashcat -m 10000 -w3 hashes.txt wordlist.txt --session cracking_session1 --restore
```

#### Hashcat common modes
```
1000 - NTLM
1100 - Domain Cached Credentials (DCC), MS Cache
2100 - Domain Cached Credentials 2 (DCC2), MS Cache 2
13100 - Kerberos TGS-REP
18200 - Kerberos AS-REP
22000 - WPA-PBKDF2-PMKID+EAPOL
22001 - WPA-PMK-PMKID+EAPOL
16800 - WPA-PMKID-PBKDF2
16801 - WPA-PMKID-PMK
```

Full list of options / modes: https://hashcat.net/wiki/doku.php?id=hashcat#options