---
title: "Recon"
date: 2020-07-16T13:41:37+02:00
draft: true
---
asdas

#### Identify O365 Usage
asdasd

```js
This is some code
```
***

#### Harvesting e-mail addresses using BridgeKeeper
BridgeKeeper will search Google, Yahoo and Bing for LinkedIn profiles of employees of the given company to harvest names. Knowing an e-mail naming convention, an educated guess can be made of their e-mail addresses.
First collect the names of employees;
```
$ python3 bridgekeeper.py -c "Ministerie van Financien"  --domain minfin.nl --output folder --depth 15
```
Then convert the names to e-mail addresses:
```
$ python3 bridgekeeper.py --file names.txt --format {f}{last}@example.com --output example-employees/ --debug
```
Or do everything at once:
```
$ python3 bridgekeeper.py --company "Example Ltd." --format {f}{last}@example.com --depth 10 --output example-employees/ --debug
```
Username format examples (BridgeKeeper supports middle names as well as character limited usernames - e.g. only 4 characters of a last name is used):
BridgeKeeper has
```
Name: John Adams Smith
{f}{last}                   > jsmith
{f}{m}.{last}               > ja.smith
{f}{last}[4]@example.com    > jsmit@example.com
```