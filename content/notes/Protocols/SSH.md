---
title: SSH 🔓
tags:
  - Protocol
---
>[!Note]
>*It typically runs on port `22`.*

# HTB Cheatsheet

| **Command**                                                 | **Description**                                       |
| ----------------------------------------------------------- | ----------------------------------------------------- |
| `ssh-audit.py <FQDN/IP>`                                    | Remote security audit against the target SSH service. |
| `ssh <user>@<FQDN/IP>`                                      | Log in to the SSH server using the SSH client.        |
| `ssh -i private.key <user>@<FQDN/IP>`                       | Log in to the SSH server using private key.           |
| `ssh <user>@<FQDN/IP> -o PreferredAuthentications=password` | Enforce password-based authentication.                |

> You should check [Footprinting Theory 🌚](/notes/Info/HTB%20Academy/footprinting_theory.md) to get further knowledge.

## Crack SSH keys

- If you have a key like this one:

```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,9F85D92F34F42626F13A7493AB48F337

LNu5wQBBz7pKZ3cc4TWlxIUuD/opJi1DVpPa06pwiHHhe8Zjw3/v+xnmtS3O+qiN
JHnLS8oUVR6Smosw4pqLGcP3AwKvrzDWtw2ycO7mNdNszwLp3uto7ENdTIbzvJal
73/eUN9kYF0ua9rZC6mwoI2iG6sdlNL4ZqsYY7rrvDxeCZJkgzQGzkB9wKgw1ljT
WDyy8qncljugOIf8QrHoo30Gv+dAMfipTSR43FGBZ/Hha4jDykUXP0PvuFyTbVdv
BMXmr3xuKkB6I6k/jLjqWcLrhPWS0qRJ718G/u8cqYX3oJmM0Oo3jgoXYXxewGSZ
AL5bLQFhZJNGoZ+N5nHOll1OBl1tmsUIRwYK7wT/9kvUiL3rhkBURhVIbj2qiHxR
3KwmS4Dm4AOtoPTIAmVyaKmCWopf6le1+wzZ/UprNCAgeGTlZKX/joruW7ZJuAUf
ABbRLLwFVPMgahrBp6vRfNECSxztbFmXPoVwvWRQ98Z+p8MiOoReb7Jfusy6GvZk
VfW2gpmkAr8yDQynUukoWexPeDHWiSlg1kRJKrQP7GCupvW/r/Yc1RmNTfzT5eeR
OkUOTMqmd3Lj07yELyavlBHrz5FJvzPM3rimRwEsl8GH111D4L5rAKVcusdFcg8P
9BQukWbzVZHbaQtAGVGy0FKJv1WhA+pjTLqwU+c15WF7ENb3Dm5qdUoSSlPzRjze
eaPG5O4U9Fq0ZaYPkMlyJCzRVp43De4KKkyO5FQ+xSxce3FW0b63+8REgYirOGcZ
4TBApY+uz34JXe8jElhrKV9xw/7zG2LokKMnljG2YFIApr99nZFVZs1XOFCCkcM8
GFheoT4yFwrXhU1fjQjW/cR0kbhOv7RfV5x7L36x3ZuCfBdlWkt/h2M5nowjcbYn
exxOuOdqdazTjrXOyRNyOtYF9WPLhLRHapBAkXzvNSOERB3TJca8ydbKsyasdCGy
AIPX52bioBlDhg8DmPApR1C1zRYwT1LEFKt7KKAaogbw3G5raSzB54MQpX6WL+wk
6p7/wOX6WMo1MlkF95M3C7dxPFEspLHfpBxf2qys9MqBsd0rLkXoYR6gpbGbAW58
dPm51MekHD+WeP8oTYGI4PVCS/WF+U90Gty0UmgyI9qfxMVIu1BcmJhzh8gdtT0i
n0Lz5pKY+rLxdUaAA9KVwFsdiXnXjHEE1UwnDqqrvgBuvX6Nux+hfgXi9Bsy68qT
8HiUKTEsukcv/IYHK1s+Uw/H5AWtJsFmWQs3bw+Y4iw+YLZomXA4E7yxPXyfWm4K
4FMg3ng0e4/7HRYJSaXLQOKeNwcf/LW5dipO7DmBjVLsC8eyJ8ujeutP/GcA5l6z
ylqilOgj4+yiS813kNTjCJOwKRsXg2jKbnRa8b7dSRz7aDZVLpJnEy9bhn6a7WtS
49TxToi53ZB14+ougkL4svJyYYIRuQjrUmierXAdmbYF9wimhmLfelrMcofOHRW2
+hL1kHlTtJZU8Zj2Y2Y3hd6yRNJcIgCDrmLbn9C5M0d7g0h2BlFaJIZOYDS6J6Yk
2cWk/Mln7+OhAApAvDBKVM7/LGR9/sVPceEos6HTfBXbmsiV+eoFzUtujtymv8U7
-----END RSA PRIVATE KEY-----
```

- Crack its passphrase like this:

```shell
# First save it to a file
vim id_rsa

# Create a hash file from the id_rsa file to use it with john
ssh2john id_rsa > id_rsa.hash

# Crack it with a wordlist
john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

## Connect to ssh using a ssh key

- To connect to shh using a ssh key:
  - `chmod 600 id_rsa`
  - `ssh -i id_rsa username@host_ip`
- If you got this error: `sign_and_send_pubkey: no mutual signature supported`
  - Paste this on `~/.ssh/config`:

```bash
Host *
    PubkeyAcceptedKeyTypes=+ssh-rsa
    HostKeyAlgorithms=+ssh-rsa
```

## Decrypt RSA keys

- [RSA Calculator](https://www.cs.drexel.edu/~popyack/Courses/CSP/Fa17/notes/10.1_Cryptography/RSA_Express_EncryptDecrypt_v2.html)

![](Pasted%20image%2020240220233429.png)

![](Pasted%20image%2020240220233613.png)

## Adding your public key to connect remotely without password

If you find a crontab that for examples realizes a backup of a public key of a current user like: `*  *    * * *   root    /bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys` and you can modify the file which is being backed up, you can add your public key:

- Create a public key dedicated:
	- `ssh-keygen rsa`
	- Select a location (I prefer to create a separate public key)
	- Add a passphrase
- Now modify the content of the original backup by your `.pub` file you've just created:

```shell
echo "YOUR .PUB FILE BLABLABLA" > /opt/.backups/jake_id_rsa.pub.backup
```

- Now connect by using:

```shell
ssh -i file.pub USER@VICTIM_MACHINE
```

## Brute force SSH by password

If you know a password and want to guess the user use **crackmapexec**:

```shell
crackmapexec ssh wifinetic.htb -u users.txt -p 'VeRyUniUqWiFIPasswrd1!' --continue-on-success
```
