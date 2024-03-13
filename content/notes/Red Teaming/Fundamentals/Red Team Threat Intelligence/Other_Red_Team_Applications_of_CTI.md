---
title: Other Red Team Applications of CTI 🔎
---
CTI can also be used during engagement execution, emulating the adversary's behavioral characteristics, such as  

- C2 Traffic
    - User Agents
    - Ports, Protocols
    - Listener Profiles
- Malware and Tooling
    - IOCs
    - Behaviors

![|200](Pasted%20image%2020240123222852.png)

---

The first behavioral use of CTI we will showcase is C2 (**C**ommand & **C**ontrol) traffic manipulation. A red team can use CTI to identify adversaries' traffic and modify their C2 traffic to emulate it.

An example of a red team modifying C2 traffic based on gathered CTI is **[malleable profiles](https://www.cobaltstrike.com/help-malleable-c2)**. A malleable profile allows a red team operator to control multiple aspects of a C2's listener traffic.

Information to be implemented in the profile can be gathered from ISACs and collected IOCs or packet captures, including,

- Host Headers
- POST URIs
- Server Responses and Headers

The gathered traffic can aid a red team to make their traffic look similar to the targeted adversary to get closer to the goal of adversary emulation.

---

The second behavioral use of CTI is analyzing behavior and actions of an adversaries' malware and tools to develop your offensive tooling that emulates similar behaviors or has similar vital indicators.

An example of this could be an adversary using a custom dropper. The red team can emulate the dropper by,

- Identifying traffic
- Observing syscalls and API calls
- Identifying overall dropper behavior and objective
- Tampering with file signatures and IOCs

Intelligence and tools gathered from behavioral threat intelligence can aid a red team in preparing the specific tools they will use to action planned TTPs.