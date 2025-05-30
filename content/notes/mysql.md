---
title: Mysql 💟
tags:
  - Database
---
>[!Note]
>*It typically runs on port `3306`*

## Nmap scan

```shell
nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```

# HTB Cheatsheet

| **Command**                                          | **Description**                                                                                       |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `mysql -u <user> -p<password> -h <IP address>`       | Connect to the MySQL server. There should **not** be a space between the '-p' flag, and the password. |
| `show databases;`                                    | Show all databases.                                                                                   |
| `use <database>;`                                    | Select one of the existing databases.                                                                 |
| `show tables;`                                       | Show all available tables in the selected database.                                                   |
| `show columns from <table>;`                         | Show all columns in the selected table.                                                               |
| `select * from <table>;`                             | Show everything in the desired table.                                                                 |
| `select * from <table> where <column> = "<string>";` | Search for needed `string` in the desired table.                                                      |

You should check [Footprinting Theory 🌚](/notes/Info/HTB%20Academy/footprinting_theory.md) to get further knowledge.

## Where to find credentials

- Most of the times **root creds** will be stored under the `/var/www` directory, maybe in a `.php` file or something like that. Always deeply check all the files inside
	- Inside the directory there are always the `html` directory and maybe others (where it is located the real sugar)

![](Pasted%20image%2020240417220426.png)

## Basic commands

- To connect to a mysql database run:

```shell
mysql -u root -h IP -p
# or directly enumerate
mysql -h db -u root -proot database -e 'show tables;'
```

- To see databases: `show databases;`
- To use one database: `use DATABASE_NAME;`
- To see tables of database: `show tables;`
- To modify a value: `update runcheck set run = 1;`
- Now (when you inside a table) you can do: `select * from TABLE_NAME`
- To quit run: `quit`

- In web browser, if you find a cookie, try adding a the end of its value a `'` like:

![](Pasted%20image%2020240322155742.png)

- If so, you can try some sql injections with sqlmap or by yourself

