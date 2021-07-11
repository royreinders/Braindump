---
title: "detectionlab"
date: 2020-07-16T13:41:37+02:00
draft: false
---

### Detectionlab notes

##### Re-create a single VM (e.g. logger, dc, etc)

From DetectionLab/ESXi run:
```
terraform taint esxi_guest.<hostname> && terraform apply
```
Once completed, run: 
```
cd DetectionLab/ESXi/ansible && ansible-playbook -v detectionlab.yml --tags "<hostname>"
```

##### Re-create the entire lab (all 4 instances)

From DetectionLab/ESXi run:
```
terraform destroy 
```
After it fininshes, run:
```
cd DetectionLab/ESXi/ansible && ansible-playbook -v detectionlab.yml
```


DetectionLab instructions
* https://www.detectionlab.network/deployment/esxi/
* https://clo.ng/blog/detectionlab-on-esxi/

Layout and credentials: https://www.detectionlab.network/introduction/

