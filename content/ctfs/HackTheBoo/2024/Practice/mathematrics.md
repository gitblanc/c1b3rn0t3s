---
title: Mathematrics
tags:
  - CTF
  - HackTheBox
  - Pwn
---
First, we execute once the binary locally:

![](Pasted%20image%2020241023155632.png)

If this is the Buffer Overflow it seems to be, what we must do is to input the maximum integer value to the first variable and assign a 1 to the otherone to create an Integer overflow (i.e. 2147483647 and then 1):

![](Pasted%20image%2020241023160006.png)

BTW, inspecting the binary with Ghidra, we can find the function where the inputted numbers are stored and then search in Google for: "int32_t max value":

![](Pasted%20image%2020241023160546.png)

![](Pasted%20image%2020241023160220.png)