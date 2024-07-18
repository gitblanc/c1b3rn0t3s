---
title: dirsearch 📁
tags:
  - Tool
---
- *Alternative to [Gobuster 🐦](Gobuster.md)*

![](Pasted%20image%2020240501184927.png)

## Installation

- Link to the [official repo](https://github.com/maurosoria/dirsearch)

## Basic commands

```shell
python3 dirsearch.py -u https://target -e*

python3 dirsearch.py -u https://target

python3 dirsearch.py -e php,html,js -u https://target

python3 dirsearch.py -e php,html,js -u https://target -w /path/to/wordlist
```

## Recursion

```shell
python3 dirsearch.py -e php,html,js -u https://target -r

python3 dirsearch.py -e php,html,js -u https://target -r --max-recursion-depth 3 --recursion-status 200-399
```
