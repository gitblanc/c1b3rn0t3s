---
title: BabyEncription
tags:
  - HackTheBox
  - Challenge
  - Very-Easy
  - Crypto
date: 2025-03-13T00:00:00Z
---
We get the following code:

![](Pasted%20image%2020250313235444.png)

So basically we can invert the encryption and create a decryptor:

```python
from sympy import mod_inverse

# Obtain modular inverse of 123 % 256
INV_123 = mod_inverse(123, 256)  # Calculate 123^(-1) % 256

def decrypt(ciphertext):
    pt = []
    for char in bytes.fromhex(ciphertext.strip()):  # Convert from hex to bytes
        pt.append(chr((INV_123 * (char - 18)) % 256))  # Apply ecuation
    return ''.join(pt)  # Convert list in string

# Read the encrypted flag
with open('./msg.enc', 'r') as f:
    ciphertext = f.read()

# Decrypt and show flag
print(decrypt(ciphertext))

# HTB{l00k_47_y0u_r3v3rs1ng_3qu4710n5_c0ngr475}
```

==Challenge completed!==