---
title: Greenbone (OpenVAS) 🌶️
tags:
  - Tool
---
![](Pasted%20image%2020240723094053.png)

> Extracted from [Official Guide](https://greenbone.github.io/docs/latest/22.4/container/index.html)

*This tool is useful for automated reports*

## Setting up community container

- Download  the Docker Compose File:

```shell
curl -f -L https://greenbone.github.io/docs/latest/_static/docker-compose-22.4.yml -o docker-compose.yml
```

- Download the container:

```shell
docker compose -f docker-compose.yml -p greenbone-community-edition pull
```

- Start the container:

```shell
docker compose -f docker-compose.yml -p greenbone-community-edition up -d
```

## Setting up an Admin User

```shell
docker compose -f docker-compose.yml -p greenbone-community-edition \
    exec -u gvmd gvmd gvmd --user=admin --new-password='<password>'
```

## Start the Vulnerability Management

```shell
xdg-open "http://127.0.0.1:9392" 2>/dev/null >/dev/null &
```