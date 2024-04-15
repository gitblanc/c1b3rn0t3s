---
title: Engagement Structure 👨‍🔧
---
A core function of the red team is adversary emulation. While not mandatory, it is commonly used to assess what a real adversary would do in an environment using their tools and methodologies. The red team can use various cyber kill chains to summarize and assess the steps and procedures of an engagement.

The blue team commonly uses cyber kill chains to map behaviors and break down an adversaries movement. The red team can adapt this idea to map adversary TTPs (**T**actics, **T**echniques, and **P**rocedures) to components of an engagement.

Many regulation and standardization bodies have released their cyber kill chain. Each kill chain follows roughly the same structure, with some going more in-depth or defining objectives differently. Below is a small list of standard cyber kill chains.

- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [Unified Kill Chain](https://unifiedkillchain.com/)
- [Varonis Cyber Kill Chain](https://www.varonis.com/blog/cyber-kill-chain/)
- [Active Directory Attack Cycle](https://github.com/infosecn1nja/AD-Attack-Defense)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

In this room, we will commonly reference the "Lockheed Martin Cyber Kill Chain." It is a more standardized kill chain than others and is very commonly used among red and blue teams.

The Lockheed Martin kill chain focuses on a perimeter or external breach. Unlike other kill chains, it does not provide an in-depth breakdown of internal movement. You can think of this kill chain as a summary of all behaviors and operations present.

![](Pasted%20image%2020240123132126.png)

Components of the kill chain are broken down in the table below.

|Technique|Purpose|Examples|
|---|---|---|
|Reconnaissance|Obtain information on the target|Harvesting emails, OSINT|
|Weaponization|Combine the objective with an exploit. Commonly results in a deliverable payload.|Exploit with backdoor, malicious office document|
|Delivery|How will the weaponized function be delivered to the target|Email, web, USB|
|Exploitation|Exploit the target's system to execute code|MS17-010, Zero-Logon, etc.|
|Installation|Install malware or other tooling|Mimikatz, Rubeus, etc.|
|Command & Control|Control the compromised asset from a remote central controller|Empire, Cobalt Strike, etc.|
|Actions on Objectives|Any end objectives: ransomware, data exfiltration, etc.|Conti, LockBit2.0, etc.|
