---
title: Samba shares 🗂️
---
![](Pasted%20image%2020240512162510.png)

You must see the content of [SMB🐿](/notes/Protocols/smb.md)
## What is SAMBA

Samba is the standard Windows interoperability suite of programs for Linux and Unix. It allows end users to access and use files, printers and other commonly shared resources on a companies intranet or internet. Its often referred to as a network file system.

Samba is based on the common client/server protocol of Server Message Block (SMB). SMB is developed only for Windows, without Samba, other computer platforms would be isolated from Windows machines, even if they were part of the same network.

## Use nmap to enumerate SMB shares

```shell
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse HOST
```

## Inspect shares

```shell
smbclient //HOST/SHARE
```

## Download recursively the SMB share

```shell
smbget -R smb://HOST/SHARE
```

## Port 111

This is just a server that converts remote procedure call (RPC) program number into universal addresses. When an RPC service is started, it tells rpcbind the address at which it is listening and the RPC program number its prepared to serve. 

In our case, port 111 is access to a network file system. Lets use nmap to enumerate this.

```shell
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount HOST
```

- Then you can mount the directory in your local machine (if found)
	- More info in [Cheatsheet Commands Linux 👾](/notes/Linux%20things/cheatsheet_commands_linux)

