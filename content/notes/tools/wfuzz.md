---
title: Wfuzz 🐙
tags:
  - Tool
---
![](Pasted%20image%2020241113101003.png)

> *Content extracted from the [Official Wfuzz documentation](https://wfuzz.readthedocs.io/)*

## Fuzzing paths and files

### Directory fuzzing

```shell
wfuzz -w wordlist/general/common.txt http://testphp.vulnweb.com/FUZZ
```

### File fuzzing

```shell
wfuzz -w wordlist/general/common.txt http://testphp.vulnweb.com/FUZZ.php
```

## Fuzzing parameters in URLs

```shell
wfuzz -z range,0-10 --hl 97 http://testphp.vulnweb.com/listproducts.php?cat=FUZZ
```

## Vhost enumeration

```shell
wfuzz -H "Host: FUZZ.vulnweb.web" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 30587 https://vulnweb.web
```