---
title: Active Directory (AD) Environment 📀
---
## What is the Active Directory (AD) environment?

![|200](Pasted%20image%2020240129201220.png)

It is a Windows-based directory service that stores and provides data objects to the internal network environment. It allows for centralized management of authentication and authorization. The AD contains essential information about the network and the environment, including users, computers, printers, etc. For example, AD might have users' details such as job title, phone number, address, passwords, groups, permission, etc.

![](Pasted%20image%2020240129201245.png)

The diagram is one possible example of how Active Directory can be designed. The AD controller is placed in a subnet for servers (shown above as server network), and then the AD clients are on a separate network where they can join the domain and use the AD services via the firewall.

The following is a list of Active Directory components that we need to be familiar with:

- Domain Controllers
- Organizational Units
- AD objects
- AD Domains
- Forest
- AD Service Accounts: Built-in local users, Domain users, Managed service accounts
- Domain Administrators

## Concepts

A **Domain Controller** is a Windows server that provides Active Directory services and controls the entire domain. It is a form of centralized user management that provides encryption of user data as well as controlling access to a network, including users, groups, policies, and computers. It also enables resource access and sharing. These are all reasons why attackers target a domain controller in a domain because it contains a lot of high-value information.

![](Pasted%20image%2020240129201300.png)

**Organizational Units (OU's)** are containers within the AD domain with a hierarchical structure.

**Active Directory Objects** can be a single user or a group, or a hardware component, such as a computer or printer. Each domain holds a database that contains object identity information that creates an AD environment, including:

- Users - A security principal that is allowed to authenticate to machines in the domain
- Computers - A special type of user accounts
- GPOs - Collections of policies that are applied to other AD objects

AD domains are a collection of Microsoft components within an AD network. 

AD Forest is a collection of domains that trust each other.

![](Pasted%20image%2020240129201319.png)

For more information about the basics of Active Directory, we suggest trying the following TryHackMe room: [Active Directory Basics](https://tryhackme.com/room/winadbasics).  


Once Initial Access has been achieved, finding an AD environment in a corporate network is significant as the Active Directory environment provides a lot of information to joined users about the environment. As a red teamer, we take advantage of this by enumerating the AD environment and gaining access to various details, which can then be used in the lateral movement stage.

In order to check whether the Windows machine is part of the AD environment or not, one way, we can use the command prompt `systeminfo` command. The output of the `systeminfo` provides information about the machine, including the operating system name and version, hostname, and other hardware information as well as the AD domain.

Note that if we get WORKGROUP in the domain section, then it means that this machine is part of a local workgroup.