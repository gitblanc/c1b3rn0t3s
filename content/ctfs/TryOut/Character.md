---
title: Character
tags:
  - CTF
  - Misc
---
![](Pasted%20image%2020241013143822.png)

It seems like you can get all the flag by inputting the length of the current character. It could take a lot, so I crafted this script:

```python
#!/usr/bin/python3.8
from pwn import *

def get_index(p, answer, i):
    p.sendline(f"{i}")
    answers = []
    answer = str(p.recvuntil(b'Which character (index) of the flag do you want? Enter an index: '))
    answer = answer.split("\\n")[0].split(":")[1]
    answers.append(answer)
    return "".join(answers)

p = remote('83.136.254.37', '54611')
rcv = str(p.recvuntil(b'Which character (index) of the flag do you want? Enter an index: '))
answers = []
p.sendline(b'1')
answer = str(p.recvuntil(b'Which character (index) of the flag do you want? Enter an index: '))
answer = answer.split("\\n")[0].split(": ")[1]
answers.append(answer)
answer = ''

try:
    for i in range(180):
        answer += get_index(p, answer, i)

except:
    flag = answer.strip().replace(" ", "")  # Delete spaces
    success(f"Flag: {flag}")
    sys.exit(0)
```

![](Pasted%20image%2020241013143923.png)