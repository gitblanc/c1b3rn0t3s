---
title: Subdomain enumeration 🌞
---
 - Find all `dev` subdomains on `facebook.com` using curl and jq (using `crt.sh` API):

```shell
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u
 
*.dev.facebook.com
*.newdev.facebook.com
*.secure.dev.facebook.com
dev.facebook.com
devvm1958.ftw3.facebook.com
facebook-amex-dev.facebook.com
facebook-amex-sign-enc-dev.facebook.com
newdev.facebook.com
secure.dev.facebook.com
```

 - Use the tool **assetfinder**

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

> Now you can perform [Fingerprinting 🫐](fingerprinting.md)

