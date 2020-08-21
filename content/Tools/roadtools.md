---
title: "ROADtools"
date: 2020-07-16T13:41:37+02:00
draft: true
---

#### Installation
```
pip3 install roadrecon
```

#### Usage
1. Authenticate to Azure AD
```
roadrecon auth -u roy.reinders@domain.com
Password: 
```
2. Gather all information and create database file
```
roadrecon dump
```
3. Explore the data or export it to a specific format using a plugin
```
roadrecon gui
```
Now the GUI will be started on http://127.0.0.1:5000/