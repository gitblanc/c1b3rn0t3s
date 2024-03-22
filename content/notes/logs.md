---
title: Logs 🤠
---
- If you find a log, use `head log` to see it:

![](Pasted%20image%2020240322163117.png)

- This log indicates that someone tried a brute force attack via ssh
	- So what if a user logged in between? We've got his/her password
- Do a grep like: `cat log | grep USER`

![](Pasted%20image%2020240322163329.png)