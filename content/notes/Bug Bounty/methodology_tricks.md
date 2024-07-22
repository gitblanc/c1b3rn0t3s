---
title: Bug Bounty Methodology tricks 🍥
tags:
  - Bug-Bounty
---
- Credits to [gotr00t?](https://www.youtube.com/watch?v=TykKSvKYPz0) && [gotr00t?](https://www.youtube.com/watch?v=WJt8Y5UVVRo)

## Hacking programs

- [HackerOne](https://www.hackerone.com/) (Worldwide)
- [Intigrity](https://www.intigriti.com/) (Europe)

### Tools

- Wordlists
	- [SecLists](https://github.com/danielmiessler/SecLists)
- [Spyhunt](https://github.com/gotr00t0day/spyhunt.git)
- [httpX](https://github.com/projectdiscovery/httpx)
- [feroxbuster](https://github.com/epi052/feroxbuster)
- [Wappalyzer](https://chromewebstore.google.com/detail/wappalyzer-technology-pro/gppongmhjkpfnbhagpmjfkannfbllamg?hl=en-US)
- Snov.io
	- [Email Finder](https://chromewebstore.google.com/detail/email-finder-by-snovio/einnffiilpmgldkapbikhkeicohlaapj?hl=en-US)
	- [Email Verifier](https://chromewebstore.google.com/detail/email-verifier-by-snovio/hlbhaaegomldlibkeiiifaejlciaifmj?hl=en-US)
	- [Website Technology Checker](https://chromewebstore.google.com/detail/website-technology-checke/phealodnoblgkcfbhpdebpihdbfmggpi?hl=en-US)
- [ParamSpider](https://github.com/devanshbatham/ParamSpider)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
	- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)

## Recon Methodology

### Subdomain enumeration

```shell
python3 spyhunt.py -s DOMAIN --save subdomains.txt
```

### Probe subdomains to find valid ones

```shell
python3 spyhunt.py -p subdomains.txt
```

### Enumerate subdomains to check for status codes, web servers, etc

```shell
cat subdomains.txt | httpx -sc -td -ip
# search for the 200,302 Status code
```

### Start fuzzing subdomains that you find interesting

- Basics:

```shell
dirsearch -u https://DOMAIN -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -x 404,403,500,429,301,302

feroxbuster -u https://DOMAIN -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt -C 404,403,429,400,401,405,302

feroxbuster -u https://DOMAIN -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt -C 404,403,429,400,401,405,302

gobuster dir -u https://DOMAIN -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt -b 403,404 -n
```

- For api endpoints:

```shell
dirsearch -u https://DOMAIN -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt -x 404,403,500,429,301,302

dirsearch -u https://DOMAIN -w /usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt -x 404,403,500,429,301,302
```

- More info in [dirsearch 📁](notes/tools/dirsearch.md)
- More info in [Gobuster 🐦](/notes/tools/Gobuster.md)

### Using Nmap to find additional open ports on the system

```shell
nmap -sV -sC -p- --min-rate 5000 -T4 DOMAIN -Pn > scan.txt
```

More commands in [Nmap 👁️‍🗨️](/notes/tools/Nmap.md)

### Checking we technologies using Wappalyzer and Snov.io

> Just use them

### Check the website for any user input (for injections)

```shell
paramspider -d DOMAIN
# Now search for the saved URLs the program outputed
nuclei -l /path/to/results/DOMAIN.txt -tags lfi,rfi,sqli
```

### Extract Javascript  files to find hidden endpoints

```shell
python3 spyhunt.py -j https://DOMAIN
```

### Use The Wayback Machine and others to find old links that might be exposing endpoints

```shell
python3 spyhunt.py -w htps://DOMAIN > old_endpoints.txt
```

For manual check: more info in [OSINT 👻](/notes/OSINT.md)

==Now you are able to check for basic vulnerabilities like information disclosure, any type of injections and more :D==

## Gather information with BurpSuite or ZAP

> Search for anything interesting capturing requests

- More info on [BurpSuite 📙](/notes/tools/BurpSuite.md)
- More info on [ZAP 🦈](/notes/tools/OWASP_ZAP.md)
