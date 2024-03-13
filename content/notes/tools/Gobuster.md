---
title: Gobuster 🐦
---
## Basic command

````shell
gobuster dir -u http://10.10.70.124/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 60
````