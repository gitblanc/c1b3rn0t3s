---
title: Mysql 💟
---
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