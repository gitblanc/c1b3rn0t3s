---
title: John The Ripper 🐈‍⬛
tags:
  - Tool
---
## Crack keepass2 passwords with:

```shell
keepass2john dataset.kdbx > dataset.john
john dataset.john
```

## Crack shadow files:

```shell
# First obtain the passwd and shadow files
unshadow passwd shadow > file_to_crack
john --wordlist=/usr/share/wordlists/rockyou.txt file_to_crack --users=USER
```

## List available formats

```shell
john --list=formats | grep <KEYWORD>
#example
john --list=formats | grep bcrypt
```