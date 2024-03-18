---
title: Gobuster 🐦
---
## Basic commands

````shell
gobuster dir -u http://10.10.70.124/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 60

gobuster dir -u http://10.10.110.8/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 -x txt,py,sh,php

gobuster dir -u http://10.10.110.8/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60
````