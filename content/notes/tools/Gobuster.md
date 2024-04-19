---
title: Gobuster 🐦
---
## Basic commands

````shell
gobuster dir -u http://10.10.70.124/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 60

gobuster dir -u http://10.10.110.8/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 -x txt,py,sh,php

gobuster dir -u http://10.10.110.8/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60
````

## Blocking a status code specifically

- If you find something like this:

![](Pasted%20image%2020240419111932.png)

- Add the option `--exclude-length LENGTH` or `-b STATUS_CODE`
	- Check the meanings of the codes in [HTTP status codes complete list 💨](http_status_codes)

```shell
gobuster dir -u http://10.10.110.8/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 --exclude-length 472
```

## Analyze https webs

```shell
gobuster dir -u https://brickbybrick.thm -w /usr/share/wordlists/dirb/big.txt -x txt -k

gobuster dir -u https://brickbybrick.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k
```