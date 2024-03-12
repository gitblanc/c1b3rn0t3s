---
title: Import a .asc key ♻️
---

```shell
gpg --import key.asc

# If you don't have the creds, you can brute force it using gpg2john
gpg2john key.asc > hash.txt
# Then you crack it with john
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
# Now you do the import step, introduce the creds and after that do the decrypt step
gpg --decrypt credential.pgp
```
