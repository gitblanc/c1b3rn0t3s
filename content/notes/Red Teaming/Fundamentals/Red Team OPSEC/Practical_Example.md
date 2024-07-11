---
title: Practical Example 🧪
tags:
  - TryHackMe
  - Theory
---
In this task, we apply the five elements of the OPSEC process as we focus on different examples of critical information related to red team tasks. We will follow the following steps:

1. Identify critical information
2. Analyse threats
3. Analyse vulnerabilities
4. Assess risk
5. Apply appropriate countermeasures

### Programs/OS/VM used by the red team

- Critical information: We are talking about the programs, the operating system (OS), and the virtual machine (VM) together.
- Threat analysis: The blue team is looking for any malicious or abnormal activity on the network. Depending on the service we're connecting to, it's possible that the name and the version of the program we're using, and the OS version and VM hostname could be logged.
- Vulnerability analysis: If the OS chosen for the given activity is too unique, it could make it easier to link activities back to your operation. The same applies to VMs with hostnames that stand out. For instance, on a network of physical laptops and desktops, if a new host joins with the hostname `kali2021vm`, it should be easy to spot by the blue team. Likewise, if you use various security scanners or for instance you don't use a common user agent for web based activities.
- Risk Assessment: The risk mainly depends on which services we're connecting to. For instance, if we start a VPN connection, the VPN server will log plenty of information about us. The same applies to other services to which we might connect.
- Countermeasures: If the OS we are using is uncommon, it would be worth the effort to make the necessary changes to camouflage our OS as a different one. For VMs and physical hosts, it's worth changing the hostnames to something inconspicuous or consistent with the client's naming convention, as you don’t want a hostname such as `AttackBox` to appear in the DHCP server logs. As for programs and tools, it is worth learning the signatures that each tool leaves on the server logs.

Example: The figure below shows the User-Agent that will be logged by the remote web server when running Nmap scans with the `-sC` option when Nmap probes the web server. If an HTTP user agent isn't set at the time of running the given Nmap script, the logs on the target system could log a user agent containing `Nmap Scripting Engine`. This can be mitigated using the option `--script-args http.useragent="CUSTOM_AGENT"`.

![](Pasted%20image%2020240124113558.png)