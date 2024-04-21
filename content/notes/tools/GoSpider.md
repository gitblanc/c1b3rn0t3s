---
title: GoSpider 🐚
---
- If you didn't find anything with [Gobuster 🐦](Gobuster.md) you can just go deeper with this

## Basic command

```shell
gospider -s "http://vulnnet.com/" -c 10 -d 0 -w -t 10 -- robots -a -r -v

# Output
[url] - [code-200] - http://vulnnet.com/
[javascript] - http://vulnnet.com/js/index__7ed54732.js
[javascript] - http://vulnnet.com/js/index__d8338055.js
[url] - [code-200] - http://vulnnet.com/login.html
[javascript] - http://vulnnet.com/js/jquery.min.js
[linkfinder] - [from: http://vulnnet.com/js/index__d8338055.js] - http://vulnnet.thm/index.php?referer=
[linkfinder] - [from: http://vulnnet.com/js/index__7ed54732.js] - http://broadcast.vulnnet.thm
[linkfinder] - [from: http://vulnnet.com/js/jquery.min.js] - text/xml
[linkfinder] - [from: http://vulnnet.com/js/jquery.min.js] - text/plain
[linkfinder] - [from: http://vulnnet.com/js/jquery.min.js] - text/html
[linkfinder] - [from: http://vulnnet.com/js/jquery.min.js] - application/x-www-form-urlencoded
```