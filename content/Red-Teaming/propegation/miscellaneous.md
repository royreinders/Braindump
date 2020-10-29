---
title: "Internal Password Spray"
date: 2020-07-17T20:59:33+02:00
draft: true
---

#### Search for cpassword entries in group policies

```findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml'```


