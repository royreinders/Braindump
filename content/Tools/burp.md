---
title: "Burp Suite"
date: 2020-07-16T13:41:37+02:00
draft: false
---
#### Turn off telemetry and captive portal in firefox
Browse to 'about:'config' in Firefox and change the following settings"
```
network.captive-portal-service.enabled
toolkit.telemetry.archive.enabled = false
toolkit.telemetry.enabled = false
toolkit.telemetry.rejected = true
toolkit.telemetry.server = <clear value>
toolkit.telemetry.unified = false
toolkit.telemetry.unifiedIsOptIn = false
toolkit.telemetry.prompted",2);
toolkit.telemetry.rejected",true);
```
***