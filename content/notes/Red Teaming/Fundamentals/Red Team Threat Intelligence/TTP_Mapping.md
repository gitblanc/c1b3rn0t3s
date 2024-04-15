---
title: TTP Mapping 🧲
---
**TTP Mapping** is employed by the red cell to map adversaries' collected TTPs to a standard cyber kill chain. Mapping TTPs to a kill chain aids the red team in planning an engagement to emulate an adversary.

To begin the process of mapping TTPs, an adversary must be selected as the target. An adversary can be chosen based on,

1. Target Industry
2. Employed Attack Vectors
3. Country of Origin
4. Other Factors

As an example for this task, we have decided to use **[APT 39](https://attack.mitre.org/groups/G0087/)**, a cyber-espionage group run by the Iranian ministry, known for targeting a wide variety of industries.

We will use the Lockheed Martin cyber kill chain as our standard cyber kill chain to map TTPs.

![](Pasted%20image%2020240123221341.png)

The first cyber framework we will be collecting TTPs from is **[MITRE ATT&CK](https://attack.mitre.org/)**. If you are not familiar with MITRE ATT&CK, it provides IDs and descriptions of categorized TTPs. For more information about MITRE and how to use ATT&CK, check out the [MITRE room](https://tryhackme.com/room/mitre).

ATT&CK provides a basic summary of a group's collected TTPs. We can use **[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)** to help us visualize each TTP and categorize its place in the kill chain. Navigator visualizes the ATT&CK chain with the adversaries' designated TTPs highlighted under the corresponding sub-section.

To use the ATT&CK Navigator: navigate to the groups summary page, next to _"Techniques Used,"_ navigate to _"ATT&CK Navigator Layers,"_ from the dropdown navigate to _"view."_ An ATT&CK Navigator layer should have opened with the selected group's TTPs highlighted in a new tab.

Going through the Navigator layer, we can assign various TTPs we want to employ during the engagement. Below is a compiled kill chain with mapped TTPs for **APT39**.

![](Pasted%20image%2020240123221407.png)

1. Reconnaissance:
    - No identified TTPs, use internal team methodology
2. Weaponization:
    - Command and Scripting Interpreter
        - PowerShell
        - Python
        - VBA
    - User executed malicious attachments
3. Delivery:
    - Exploit Public-Facing Applications
    - Spearphishing
4. Exploitation:
    - Registry modification
    - Scheduled tasks
    - Keylogging
    - Credential dumping
5. Installation:
    - Ingress tool transfer
    - Proxy usage
6. Command & Control:
    - Web protocols (HTTP/HTTPS)
    - DNS
7. Actions on Objectives
    - Exfiltration over C2

---

MITRE ATT&CK will do most of the work needed, but we can also supplement threat intelligence information with other platforms and frameworks. Another example of a TTP framework is **[OST Map](https://www.intezer.com/ost-map/)**.

OST Map provides a visual map to link multiple threat actors and their TTPs.

Other open-source and enterprise threat intelligence platforms can aid red teamers in adversary emulation and TTP mapping, such as,

- **Mandiant Advantage**
- **Ontic**
- **CrowdStrike Falcon**

![](Pasted%20image%2020240123222455.png)