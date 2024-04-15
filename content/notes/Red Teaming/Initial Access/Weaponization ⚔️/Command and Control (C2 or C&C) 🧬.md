This note introduces the basic concept of Command and Control (C2) frameworks used in Red team operations.

![](Pasted%20image%2020240127180734.png)

# What is Command and Control (C2)?

C2 frameworks are post-exploitation frameworks that allow red teamers to collaborate and control compromised machines. C2 is considered one of the most important tools for red teamers during offensive cyber operations. C2 frameworks provide fast and straightforward approaches to:

- Generate various malicious payloads
- Enumerate the compromised machine/networks
- Perform privilege escalation and pivoting
- Lateral movement 
- And many others

Some popular C2 frameworks that we'll briefly highlight are Cobalt Strike, PowerShell Empire, Metasploit. Most of these frameworks aim to support a convenient environment to share and communicate between red team operations once the initial access is gained to a system.

## Cobalt Strike

Cobalt Strike is a commercial framework that focuses on Adversary Simulations and Red Team Operations. It is a combination of remote access tools, post-exploitation capabilities, and a unique reporting system. It provides an agent with advanced techniques to establish covert communications and perform various operations, including key-logging, files upload and download, VPN deployment, privilege escalation techniques, mimikatz, port scanning, and the most advanced lateral movements.  

## PowerShell Empire

PowerShell Empire is an open-source framework that helps red team operators and pen testers collaborate across multiple servers using keys and shared passwords. It is an exploitation framework based on PowerShell and Python agents. PowerShell Empire focuses on client-side and post-exploitation of Windows and Active Directory environment. If you want to learn more about PowerShell Empire, we suggest trying out this room: [Empire](https://tryhackme.com/room/rppsempire).

## Metasploit 

Metasploit is a widely used exploitation framework that offers various techniques and tools to perform hacking easily. It is an open-source framework and is considered one of the primary tools for pentesting and red team operations. Metasploit is one of the tools we use in this room to generate payload for our weaponization stage. If you want to learn more about the Metasploit framework, we suggest checking the [Metasploit module](https://tryhackme.com/module/metasploit).

Most of the C2 frameworks use the techniques mentioned in this room as preparation for the initial access stage. For more details about the C2 framework, we invite you to check the [Intro to C2](https://tryhackme.com/room/introtoc2) room.