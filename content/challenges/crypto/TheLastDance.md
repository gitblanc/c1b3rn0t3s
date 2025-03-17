---
title: The Last Dance
tags:
  - HackTheBox
  - Challenge
  - Very-Easy
  - Crypto
  - ChaCha20
date: 2025-03-17T00:00:00Z
---
![](Pasted%20image%2020250317143818.png)

The code is using **ChaCha20** but is using the same key and nonce. So I'll perform the following:

- Get the encoded data from `out.txt`
- Calculate the XOR between both texts

```python
from binascii import unhexlify

# Known original message (M1)
known_message = (b"Our counter agencies have intercepted your messages and a lot "
                 b"of your agent's identities have been exposed. In a matter of "
                 b"days all of them will be captured")

# Load data from "out.txt"
with open("out.txt", "r") as f:
    iv = unhexlify(f.readline().strip())  # Convert IV from hex to bytes
    ciphertext1 = unhexlify(f.readline().strip())  # Encrypted message
    ciphertext2 = unhexlify(f.readline().strip())  # Encrypted FLAG

# Compute the keystream XOR between both ciphertexts
keystream_xor = bytes(a ^ b for a, b in zip(ciphertext1, known_message))

# Decrypt the FLAG
flag = bytes(a ^ b for a, b in zip(ciphertext2, keystream_xor))

print("FLAG:", flag.decode(errors="ignore"))  # Decode while ignoring errors
```

```shell
python3 decryptor.py

#HTB{und3r57AnD1n9_57R3aM_C1PH3R5_15_51mPl3_a5_7Ha7}
```