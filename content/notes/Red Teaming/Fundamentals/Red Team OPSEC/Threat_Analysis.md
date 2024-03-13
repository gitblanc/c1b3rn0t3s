---
title: Threat Analysis 🚸
---
After we identify critical information, we need to analyse threats. _Threat analysis refers to identifying potential adversaries and their intentions and capabilities_. Adapted from the US Department of Defense [(DoD) Operations Security (OPSEC) Program Manual](https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodm/520502m.pdf), threat analysis aims to answer the following questions:

1. Who is the adversary?
2. What are the adversary’s goals?
3. What tactics, techniques, and procedures does the adversary use?
4. What critical information has the adversary obtained, if any?

![](Pasted%20image%2020240124111633.png)

The task of the red team is to emulate an actual attack so that the blue team discovers its shortcomings, if any, and becomes better prepared to face incoming threats. The blue team’s main objective is to ensure the security of the organization’s network and systems. The intentions of the blue team are clear; they want to keep the red team out of their network. Consequently, considering the task of the red team, the blue team is considered our adversary as each team has conflicting objectives. We should note that the blue team’s capabilities might not always be known at the beginning.

Malicious third-party players might have different intentions and capabilities and might pause a threat as a result. This party can be someone with humble capabilities scanning the systems randomly looking for low-hanging fruit, such as an unpatched exploitable server, or it can be a capable adversary targeting your company or your client systems. Consequently, the intentions and the capabilities of this third party can make them an adversary as well.

|Adversary|Intentions|Capabilities|
|---|---|---|
|Blue Team|Keep intruders out|Not always known|
|Malicious third-party|Varies|Varies|

We consider any adversary with the intent and capability to take actions that would prevent us from completing our operation as a threat:

```
threat = adversary + intent + capability
```

In other words, an adversary without the intent or capability does not pose a threat for our purposes.