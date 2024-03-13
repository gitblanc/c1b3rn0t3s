---
title: Command, Control and Conquer 🎥
---
### Sample Exploit

**Host Enumeration with Armitage**

Before letting you go off on your own, we're going to demonstrate how to exploit a sample Virtual Machine. First, we will execute a port scan within Armitage by going to the "Hosts" section, hovering over "Nmap Scan", and selecting "Quick Scan".

![](Pasted%20image%2020240125183716.png)

After selecting "Quick scan", a new option will pop up; this will prompt you to enter the IP Address range you would like to scan. You should enter the IP Address of the deployed Virtual machine in this box.

![](Pasted%20image%2020240125183730.png)

After pressing "Ok", and waiting a moment or two, you should see a new tab open up called "nmap" and a new machine display in the "Workspace" window. In the "nmap" tab, you will see the raw scan results.

![](Pasted%20image%2020240125183744.png)

Now that you have learned how to execute a basic port scan, try to execute various other scans against the target and see what additional information you may retrieve from a host.

_Hint: A Comprehensive Scan will grab banners, enumerate software versions, enumerate OS versions, and much more!_  

**Exploitation with Armitage**

Next up, we're going to show off exploitation with Armitage; our victim in our example is a Windows 7 machine (more specifically, Blue). This machine is vulnerable to the classic exploit "Eternal  Blue".  To find this, we will focus on the far right tab with folders, we will expand the "Exploit" dropdown, then find the "Windows" dropdown, then the "SMB" dropdown, then you will see all of the exploits.

![](Pasted%20image%2020240125183800.png)

Next up, you can double click your exploit of choice, or drag and drop the exploit onto the host, and a new window will open up. Clicking "launch" will fire off the exploit.

![](Pasted%20image%2020240125183817.png)

After clicking "Launch", you will notice a new "Exploit" tab open up. Armitage will run all of the regular checks that Metasploit normally does. In the case of Eternal Blue, it ran the standard check script followed by the exploit script until it got a successful shell. It's worth noting that by default in this Exploit, it chose a Bind shell. Make sure you fully read the exploit information and options to see if a Bind Shell or a Reverse Shell is an option.

![](Pasted%20image%2020240125183834.png)

After you receive your shell, right-click on the host and select "Interact". This will open a standard shell you're familiar with. In order to get a Meterpreter shell, we recommend that you run the multi/manage/shell_to_meterpreter module.

![](Pasted%20image%2020240125183850.png)

# Practice Time  

Now that you have learned how to exploit hosts using Armitage, you will now get to practice your skills by hacking the virtual machine by using Metasploit and Armitage. There are multiple exploit paths that you may be able to follow. We encourage you to explore the various exploit paths you may be able to find in order to gain a better understanding of exploitation and post-exploitation modules in Metasploit and Armitage. As a reminder, Armitage is just Metasploit with a GUI; all the same exploits exist and are categorized the same way.