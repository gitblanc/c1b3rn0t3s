---
title: Linux file permissions 🐵
---

![](Pasted%20image%2020240301141710.png)

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