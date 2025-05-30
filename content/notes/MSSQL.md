---
title: MSSQL 📬
tags:
  - Database
---
>[!Note]
>*It typically runs on port `1433`.*

## Namp Scan

```shell
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```

# HTB Cheatsheet

| **Command**                                           | **Description**                                          |
| ----------------------------------------------------- | -------------------------------------------------------- |
| `impacket-mssqlclient <user>@<FQDN/IP> -windows-auth` | Log in to the MSSQL server using Windows authentication. |
| `select name from sys.databases`                      | Query to get the name of available databases.            |