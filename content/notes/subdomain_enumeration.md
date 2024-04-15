---
title: Subdomain enumeration 🌞
---

1.  Use the tool **assetfinder**

```shell
assetfinder --subs-only domain.com

# then what is found, add it to your /etc/hosts file like
# IP_HOST domain1 domain2 domain3...
```

- Now, search for the vhosts:

```shell
wfuzz -c -z file,'/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt' -u "http://domain/" -H "Host:FUZZ.domain.com" --hw 65

# The try with ffuf
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "Host:FUZZ.domain.com" -u "http://domain.com" -fw 125
```

- Now enumerate the found subdomains with **dirsearch**:

```shell
dirsearch -u "http://domain.com" -i200 -w '/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt'

# You can also use gobuster:
gobuster dir -u http://domain.com/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```
