---
title: Php things 🐘
---
## Viewing files on the source code

- If you have a link like this: `http://vulnnet.thm/index.php?referer=` you can try to search for internal files on the victim machine like: `http://vulnnet.thm/index.php?referer=/etc/passwd`

![](Pasted%20image%2020240422001700.png)

### Apache is running

- If an Apache is running on the server, you can search the `/etc/apache2/.htpasswd` file and try to get the password hash

```shell
developers:$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0
```