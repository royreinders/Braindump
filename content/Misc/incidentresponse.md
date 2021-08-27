---
title: "Incident Response"
date: 2020-07-16T13:41:37+02:00
draft: false
---

##### Create ISO From folder on Mac
Create an ISO disk to mount in hypervisors

* Open the Disk Utility. File > New Image > Image From Folder.
* Select the folder that you want to make an ISO of
* As "Image Format" choose CD/DVD Master and create the image.

This will generate a .cdr file. Now make the image hybrid using the following command:

```
hdiutil makehybrid -iso -joliet -o <Outputfile>.iso <inputfile>.cdr
```
