---
title: SMB 🐿
---

- List SMB shares with `smbclient -L IP_HOST`
- Connect to a Disk by using `smbclient \\\\IP_HOST\\DISK`
  - This will connect you without credentials
- Once there connect to the target machine using **Psexec**

```shell
impacket-psexec 'bob:!P@$$W0rD!123Bill@10.10.166.94'
```

- Check for shared files with:

```shell
smbclient -L IP_HOST
```
