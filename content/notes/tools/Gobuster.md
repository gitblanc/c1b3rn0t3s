---
title: Gobuster 🐦
tags:
  - Tool
---
*Alternative to [dirsearch 📁](dirsearch.md)*
## Basic commands

````shell
gobuster dir -u http://10.10.70.124/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 60

gobuster dir -u http://10.10.110.8/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 -x txt,py,sh,php

gobuster dir -u http://10.10.110.8/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60

# 3 letter formats
gobuster dir -u http://10.10.70.124/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak,old,tar,zip -t 60

````

## Blocking a status code specifically

- If you find something like this:

![](Pasted%20image%2020240419111932.png)

- Add the option `--exclude-length LENGTH` or `-b STATUS_CODE`
	- Check the meanings of the codes in [HTTP status codes complete list 💨](http_status_codes.md)

```shell
gobuster dir -u http://10.10.110.8/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 --exclude-length 472
```

## Analyze https webs

```shell
gobuster dir -u https://brickbybrick.thm -w /usr/share/wordlists/dirb/big.txt -x txt -k

gobuster dir -u https://brickbybrick.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k
```

## Directories

```shell
gobuster dir -u http://vulnnet.thm/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 25 -q -x php,aspx,txt,asp
```

## Subdomains

```shell
gobuster vhost -u http://vulnnet.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -t 60 -q

gobuster vhost -u team.thm -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

## VHosts

```shell
gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
```

- Consider using the `-t` flag to increase the number of threads for faster scanning.
- The `-k` flag can ignore SSL/TLS certificate errors.
- You can use the `-o` flag to save the output to a file for later analysis.

```shell
gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```


