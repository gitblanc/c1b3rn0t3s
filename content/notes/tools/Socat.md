---
title: Socat 🐱
tags:
  - Tool
---
- Firstly, if you run `ss -tulwn` and you find rare ports open like:

![](Pasted%20image%2020240322165018.png)

- Note the port `3000`
- [Find the binaries here](https://github.com/3ndG4me/socat/releases/)
	- To use the binary on the machine, just upload to it by a python server and do a `chmod +x socat.bin`

- Use it with:

```shell
# Forward our traffic from port 8080 to port 3000
/tmp/socat tcp-l:8080,fork,reuseaddr tcp:127.0.0.1:3000 &
```

- Now navigate to the newly opened port in the attackers machine