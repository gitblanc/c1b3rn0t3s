---
title: Postgresql 🧭
tags:
  - Database
---
 ![](postgresql.svg)

## Connection

```shell
# psql -h <hostname or ip address> -p <port number of remote machine> -d <database name which you want to connect> -U <username of the database server>
psql -h 127.0.0.1 -p 5432 -U admin
```

## List databases

List the databases using `\l`:

```shell
\l
```

## Switch database

Switched to the `supersecret` database:

```shell
\c supersecret
```

## List database tables

List database tables with `\dt`:

```shell
\dt
```

## Describe a table

See the table's structure. As example, there is a table called `users`:

```shell
\d users
```

## Get info from a table

As example, there is a table called `users`:

```sql
select * from users
```