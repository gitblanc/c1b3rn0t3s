---
title: Wordpress 🍔
---
## Basics

- You can try to modify the current theme by changing the code with a reverse shell like **PentestMonkey** one
  - Check [Reverse shells 👾](reverse_shells.md)

- Identify the Wordpress CMS version using the tool **wpscan**: `wpscan --url "http://whatever.com"`

![](Pasted%20image%2020240320111450.png)



## Scan for users

- Obtain all users of a wordpress by the command: `curl http://whatever.com/index.php/wp-json/wp/v2/users/ | grep name`

OR

```shell
wpscan --url "http://whatever.com" --enumerate u
```

- Now bruteforce the username(s) you found by: 

```shell
wpscan --url "http://whatever.com/" -U users.txt -P wordlist.txt
```
## Ignore TLS on https webs

- If you get this error:

![](Pasted%20image%2020240419113548.png)

- Add `--disable-tls-checks`:

```shell
wpscan --url "https://URL" --disable-tls-checks
```