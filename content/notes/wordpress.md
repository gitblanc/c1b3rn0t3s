---
title: Wordpress 🍔
---

- You can try to modify the current theme by changing the code with a reverse shell like **PentestMonkey** one
  - Check [Reverse shells 👾](reverse_shells.md)

- Identify the Wordpress CMS version using the tool **wpscan**: `wpscan --url "http://whatever.com"`

![](Pasted%20image%2020240320111450.png)

- Obtain all users of a wordpress by the command: `curl http://whatever.com/index.php/wp-json/wp/v2/users/ | grep name`
- Now bruteforce the username(s) you found by: `wpscan --url "http://whatever.com/" -U "USERNAME" -P wordlist.txt`

---
