---
title: Common C2 Frameworks 🏕
tags:
  - TryHackMe
  - Theory
---
### Common C2 Frameworks  

Throughout your journey, you may encounter many different C2 Frameworks; we will discuss a few popular C2 Frameworks that are widely used by Red Teamers and Adversaries alike. We will be dividing this into two sections:

- Free
- Premium/Paid

You may ask some questions like “Why would I use a premium or paid C2 framework?”, and this is an excellent question. Premium/Paid C2 frameworks usually are less likely to be detected by Anti-Virus vendors. This is not to say that it's impossible to be detected, just that open-source C2 projects are generally well understood, and signatures can be easily developed.

Usually, premium C2 frameworks generally have more advanced post-exploitation modules, pivoting features, and even feature requests that open-source software developers may sometimes not fulfill. For example, one feature Cobalt Strike offers that most other C2 frameworks do not is the ability to open a VPN tunnel from a beacon. This can be a fantastic feature if a Proxy does not work well in your specific situation. You must do your research to find out what will work best for your team.

### Free C2 Frameworks

**Metasploit**

The [Metasploit Framework](https://www.metasploit.com/), developed and maintained by Rapid7, is one of the most popular Exploitation and Post Exploitation frameworks (C2) that is publicly available and is installed on most penetration testing distributions.

````c
           
root@kali$ msfconsole
                                                  

      .:okOOOkdc'           'cdkOOOko:.
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'
  oOOOOOOOO.    .oOOOOoOOOOl.    ,OOOOOOOOo
  dOOOOOOOO.      .cOOOOOc.      ,OOOOOOOOx
  lOOOOOOOO.         ;d;         ,OOOOOOOOl
  .OOOOOOOO.   .;           ;    ,OOOOOOOO.
   cOOOOOOO.   .OOc.     'oOO.   ,OOOOOOOc
    oOOOOOO.   .OOOO.   :OOOO.   ,OOOOOOo
     lOOOOO.   .OOOO.   :OOOO.   ,OOOOOl
      ;OOOO'   .OOOO.   :OOOO.   ;OOOO;
       .dOOo   .OOOOocccxOOOO.   xOOd.
         ,kOl  .OOOOOOOOOOOOO. .dOk,
           :kk;.OOOOOOOOOOOOO.cOk:
             ;kOOOOOOOOOOOOOOOk:
               ,xOOOOOOOOOOOx,
                 .lOOOOOOOl.
                    ,dOd,
                      .

       =[ metasploit v6.1.12-dev                          ]
+ -- --=[ 2177 exploits - 1152 auxiliary - 399 post       ]
+ -- --=[ 596 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: View a module's description using 
info, or the enhanced version in your browser with 
info -d

msf6 > 
````

**Armitage**  

[Armitage](https://web.archive.org/web/20211006153158/http://www.fastandeasyhacking.com/) is an extension of the Metasploit Framework - it adds a Graphical user interface and is written in Java, and is incredibly similar to Cobalt Strike. This is because they were both developed by Raphael Mudge. Armitage offers an easy way to enumerate and visualize all of your targets. Aside from looking a lot like Cobalt Strike, it even offers some unique features. One of the most popular can be found in the “Attacks” menu; This feature is known as the Hail Mary attack, which attempts to run all exploits for the services running on a specific workstation. Armitage really is “Fast and Easy Hacking”.

![](Pasted%20image%2020240125175600.png)

**Powershell Empire/Starkiller**

[Powershell Empire](https://bc-security.gitbook.io/empire-wiki/) and [Starkiller](https://github.com/BC-SECURITY/Starkiller) is another incredibly popular C2 originally created by Harmjoy, Sixdub, and Enigma0x3 from Veris Group. Currently, the project has been discontinued and has been picked up by the BC Security team (Cx01N, Hubbl3, and _Vinnybod). Empire features agents written in various languages compatible with multiple platforms, making it an incredibly versatile C2. For more information on Empire, we recommend you take a look at the [Powershell Empire](https://tryhackme.com/room/rppsempire) room.

![](Pasted%20image%2020240125175619.png)

**Covenant**

[Covenant](https://github.com/cobbr/Covenant) by Ryan Cobb is the last free C2 Framework we will be covering - By far, it is one of the most unique C2 Frameworks being written in C#. Unlike Metasploit/Armitage, It’s primarily used for post-exploitation and lateral movement with HTTP, HTTPS, and SMB listeners with highly customizable agents.

![](Pasted%20image%2020240125175638.png)

**Sliver**

[Sliver](https://github.com/BishopFox/sliver) by [Bishop Fox](https://bishopfox.com/) is an advanced, highly customizable multi-user, CLI-based C2 framework. Sliver is written in Go, which makes reverse engineering the C2 "implants" incredibly difficult. It supports various protocols for C2 communications like WireGuard, mTLS, HTTP(S), DNS, and much more. Additionally, it supports BOF files for additional functionality, DNS Canary Domains for masking C2 communications, automatic Let's Encrypt certificate generation for HTTPS beacons, and much more.

### Paid C2 Frameworks

**Cobalt Strike**  

[Cobalt Strike](https://www.cobaltstrike.com/) by Help Systems (Formerly created by Raphael Mudge) is arguably one of the most famous Command and Control frameworks next to Metasploit. Much like Artimage, it is written in Java and designed to be as flexible as possible. For more information, see Cobalt Strike’s [Video Training Page](https://www.youtube.com/playlist?list=PLcjpg2ik7YT6H5l9Jx-1ooRYpfvznAInJ). It offers additional insight into both Red Team Operations and the Framework by Raphael Mudge himself.

![](Pasted%20image%2020240125175716.png)

**Brute Ratel**

[Brute Ratel](https://bruteratel.com/) by Chetan Nayak or Paranoid Ninja is a Command and Control framework marketed as a “Customizable Command and Control Center” or “C4” framework that provides a true adversary simulation-like experience with being a unique C2 framework. For more information about the Framework, the author has provided a [Video Training Page](https://bruteratel.com/tabs/tutorials/) that demonstrates many of the capabilities within the framework.

![](Pasted%20image%2020240125175737.png)

### Other C2 Frameworks

For a more comprehensive list of C2 Frameworks and their capabilities, check out the “[C2 Matrix](https://howto.thec2matrix.com/)”, a project maintained by **Jorge Orchilles** and **Bryson Bort**. It has a far more comprehensive list of almost all C2 Frameworks that are currently available. We highly recommend that after this room, you go check it out and explore some of the other C2 Frameworks that were not discussed in this room.