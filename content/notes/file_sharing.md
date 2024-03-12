---
title: File Sharing 🌶️
---

- If we find the port 139 or 445 use (like Samba):

```shell
enum4linux IP_HOST
```

---

- If there is a NFS server running on a port like 2049, check the remote shares:

```shell
showmount -e IP_HOST
```

- Now mount:

```shell
sudo mkdir /mnt/nfs
sudo mount -t nfs IP_HOST:DIRECTORY /mnt/nfs
ls -la /mnt/nfs/
```

---
