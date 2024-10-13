---
title: Stop, Drop & Roll
tags:
  - CTF
  - Misc
---
![](Pasted%20image%2020241013144336.png)

So we can automate this with a python script:

```python
from pwn import *

def repeat_test(p, i):
    try:
        rcv = str(p.recvuntil(b'What do you do? '))
        question = rcv[2:].split("\\n")[0]
        moves = question.split(",")
        answer = []
        for move in moves:
            answer.append(actions[move.strip()])
        info(f"[{i}] Question is {question}")
        answer="-".join(answer)
        info(f"[{i}]Answered with {answer}")
        p.sendline(answer)
    except:
        rcv = str(p.recvuntil(b'}'))
        success("Flag is : %s", rcv)
        sys.exit(0)


actions = {"GORGE":"STOP","PHREAK":"DROP","FIRE":"ROLL"}
p = remote('94.237.62.10', '49597')

print(p.recvuntil(b'Are you ready? (y/n)'))
p.sendline("y")

rcv = str(p.recvuntil(b'What do you do? '))
question = rcv.split("\\n")[1]
moves = question.split(",")
answer = []
for move in moves:
    answer.append(actions[move.strip()])
info(f"[0] Question is {question}")
answer="-".join(answer)
info(f"[0] Answered with {answer}")
p.sendline(answer)
for i in range(1000):
    repeat_test(p, i)

p.interactive()
```

![](Pasted%20image%2020241013145219.png)