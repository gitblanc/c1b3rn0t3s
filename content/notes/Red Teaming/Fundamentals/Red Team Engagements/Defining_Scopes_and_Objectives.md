---
title: Defining Scopes and Objectives 🎯
---
Engagements can be very complex and bureaucratic. The key to a successful engagement is clearly defined client objectives or goals. Client objectives should be discussed between the client and red team to create a mutual understanding between both parties of what is expected and provided. Set objectives are the basis for the rest of the engagement documentation and planning.

Without clear and concrete objectives and expectations, you are preparing for a very unstructured and unplanned campaign. Objectives set the tone for the rest of the engagement.

When assessing a client's objectives and planning the engagement details, you will often need to decide how focused the assessment is.

Engagements can be categorized between a general internal/network penetration test or a focused adversary emulation. A focused adversary emulation will define a specific APT or group to emulate within an engagement. This will typically be determined based on groups that target the company's particular industries, i.e., finance institutions and [APT38](https://web.archive.org/web/20230325143301/https://content.fireeye.com/apt/rpt-apt38). An internal or network penetration test will follow a similar structure but will often be less focused and use more standard TTPs. 

![|200](Pasted%20image%2020240123133713.png)

The specifics of the approach will depend on a case-by-case basis of the engagement defined by the client objectives.

Client objectives will also affect the engagement's general rules of engagement and scope.

These topics will be expanded upon in Task 6.

The client objectives only set a basic definition of the client's goals of the engagement. The specific engagement plans will expand upon the client objectives and determine the specifics of the engagement. Engagement plans will be covered later within this room.

---

The next keystone to a precise and transparent engagement is a well-defined scope. The scope of an engagement will vary by organization and what their infrastructure and posture look like. A client's scope will typically define what you _canno_t do or target; it can also include what you _can_ do or target. While client objectives can be discussed and determined along with the providing team, a scope should only be set by the client. In some cases the red team may discuss a grievance of the scope if it affects an engagement. They should have a clear understanding of their network and the implications of an assessment. The specifics of the scope and the wording will always look different, below is an example of what verbiage may look like within a client's scope.

- No exfiltration of data.
- Production servers are off-limits.
- 10.0.3.8/18 is out of scope.
- 10.0.0.8/20 is in scope.
- System downtime is not permitted under any circumstances.
- Exfiltration of PII is prohibited.

---

When analyzing a client's objectives or scopes from a red team perspective, it is essential to understand the more profound meaning and implications. When analyzing, you should always have a dynamic understanding of how your team would approach the problems/objectives. If needed, you should write your engagement plans or start them from only a bare reading of the client objectives and scope.