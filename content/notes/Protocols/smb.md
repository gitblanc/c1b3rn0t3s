---
title: SMB 🐿
---
- You must see the contents of [SAMBA shares 🗂️](/notes/samba.md)

## SMB ports

![](Pasted%20image%2020240512162818.png)
## List shares and disks

- List SMB shares with `smbclient -L //IP_HOST`
- Connect to a Disk by using `smbclient //IP_HOST/DISK`
	-  This will connect you without credentials

## Connect with credentials

- Once there connect to the target machine using **Psexec**

```shell
impacket-psexec 'bob:!P@$$W0rD!123Bill@10.10.166.94'
```