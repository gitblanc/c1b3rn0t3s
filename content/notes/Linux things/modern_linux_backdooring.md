---
title: Modern Linux Backdooring 🦝
tags:
  - Linux
  - RootedCON
  - Backdooring
date: 2025-03-09T00:00:00Z
---
> *Credits to [Yago Jesús](https://x.com/YJesus) and [Aroki cyber security](https://www.arokisecurity.com/)speech in RootedCON 2025*


![](Pasted%20image%2020250309225804.png)

# Post Pwn!

*Once the system is compromised, now what?*
- Keep privileges
- Without trace
- Without being seen
- Ptrace() injections
- Rootkits
- C2C

# Previously used

## Userland R00tkits (2010 / ?)

- Easy to develop
- Stable
- Relatively obvious
- ld.so.preload

Where do they operate?

![](Pasted%20image%2020250309230326.png)

![](Pasted%20image%2020250309230343.png)

## X startup

- Useful for devices with X
- `/home/<user>/.config/autostart`
- Useful for “The year of Linux on the desktop”

==TODO()==