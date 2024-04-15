---
title: Mysql 💟
---

- To connect to a mysql database run:

```shell
mysql -u root -h IP -p
```

- To see databases: `show databases;`
- To use one database: `use DATABASE_NAME;`
- To see tables of database: `show tables;`
- To modify a value: `update runcheck set run = 1;`
- Now (when you inside a table) you can do: `select * from TABLE_NAME`


- In web browser, if you find a cookie, try adding a the end of its value a `'` like:

![](Pasted%20image%2020240322155742.png)
- If so, you can try some sql injections with sqlmap or by yourself