---
title: Linux file permissions 🐵
---
![](Pasted%20image%2020240301141710.png)

## Interesting command

- With this command you can see the Octal format of the permissions:

```shell
stat -c "%a %U:%G %n" .suid_bash 

6755 root:root .suid_bash
```

- Then you can search for its meaning

## Interesting website

- [Chmod Calculator](https://chmod-calculator.com/)

## SUID, SGID and Sticky Bits

![](Pasted%20image%2020240512165621.png)

| **Permission** | **On Files**                                                     | **On Directories**                                        |
| -------------- | ---------------------------------------------------------------- | --------------------------------------------------------- |
| SUID Bit       | User executes the file with permissions of the _file_ owner      | -                                                         |
| SGID Bit       | User executes the file with the permission of the _group_ owner. | File created in directory gets the same group owner.      |
| Sticky Bit     | No meaning                                                       | Users are prevented from deleting files from other users. |

- Search for these types of files

```shell
find / -perm -u=s -type f 2>/dev/null
```