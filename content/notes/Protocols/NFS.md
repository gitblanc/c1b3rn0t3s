---
title: NFS 🌻
tags:
  - Protocol
---
>[!Note]
>*It typically runs on ports `119` (NFSv3) and `2049` (NFSv4).*

## Nmap scan

```shell
# Just to get a footprint
nmap 10.129.14.128 -p111,2049 -sV -sC
# To get all the info
nmap --script "nfs*" 10.129.14.128 -sV -p111,2049
	[redacted]
	nfs-ls: Volume /mnt/nfs
	nfs-showmount:
	  /mnt/nfs 10.129.14.0/24
```

# HTB Cheatsheet (basic commands)

| **Command**                                                    | **Description**                              |
| -------------------------------------------------------------- | -------------------------------------------- |
| `showmount -e <FQDN/IP>`                                       | Show available NFS shares.                   |
| `sudo mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock` | Mount the specific NFS share to ./target-NFS |
| `sudo umount ./target-NFS`                                     | Unmount the specific NFS share.              |

## Mount a share (detailed)

```shell
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS

tree . # to list the contents
ls -n /mnt/nfs/ # to list the contents with UIDs & GUIDs
```

> You should check [Footprinting Theory 🌚](/notes/Info/HTB%20Academy/footprinting_theory.md) to get further knowledge.