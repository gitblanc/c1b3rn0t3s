---
title: Securing and Monitoring Kali Linux 🔒
tags:
  - Offsec
  - PEN-103
---
- *All the info was extracted from [Offsec, Pen-103](https://portal.offsec.com/courses/pen-103-16306/)*, under the following [licencese](https://creativecommons.org/licenses/by-sa/3.0/)

# 8. Securing and Monitoring Kali Linux

As you begin to use Kali Linux for increasingly sensitive and higher-profile work, you will likely need to take the security of your installation more seriously. In this chapter, we will first discuss [security policies](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/securing-and-monitoring-kali-linux/defining-a-security-policy/defining-a-security-policy), highlighting various points to consider when defining such a policy, and outlining some of the threats to your system and to you as a security professional. We will also discuss [security measures](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/securing-and-monitoring-kali-linux/possible-security-measures/possible-security-measures) for desktop and laptop systems and focus on [firewalls and packet filtering](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/securing-and-monitoring-kali-linux/firewall-or-packet-filtering/firewall-or-packet-filtering). Finally, we will discuss [monitoring](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/securing-and-monitoring-kali-linux/monitoring-and-logging/monitoring-and-logging) tools and strategies and show you how to best implement them to detect potential threats to your system.

## 8.1. Defining a Security Policy

It is impractical to discuss security in broad strokes since the idea represents a vast range of concepts, tools, and procedures, none of which apply universally. Choosing among them requires a precise idea of what your goals are. Securing a system starts with answering a few questions. Rushing headlong into implementing an arbitrary set of tools runs the risk of focusing on the wrong aspects of security.

It is usually best to determine a specific goal. A good approach to help with that determination starts with the following questions:

- _What_ are you trying to protect? The security policy will be different depending on whether you want to protect computers or data. In the latter case, you also need to know which data.
- What are you trying to protect _against_? Is it leakage of confidential data? Accidental data loss? Revenue loss caused by disruption of service?
- Also, _who_ are you trying to protect against? Security measures will be quite different for guarding against a typo by a regular user of the system versus protecting against a determined external attacker group.

The term "risk" is customarily used to refer collectively to these three factors: what to protect, what should be prevented, and who might make this happen. Modeling the risk requires answers to these three questions. From this risk model, a security policy can be constructed and the policy can be implemented with concrete actions.

**Permanent Questioning**

Bruce Schneier, a world expert in security matters (not only computer security), tries to counter one of security's most important myths with a motto: "Security is a process, not a product." Assets to be protected change over time and so do threats and the means available to potential attackers. Even if a security policy has initially been perfectly designed and implemented, you should never rest on your laurels. The risk components evolve and the response to that risk must evolve accordingly.

Extra constraints are also worth taking into account as they can restrict the range of available policies. How far are you willing to go to secure a system? This question has a major impact on which policy to implement. Too often, the answer is only defined in terms of monetary costs, but other elements should also be considered, such as the amount of inconvenience imposed on system users or performance degradation.

Once the risk has been modeled, you can start thinking about designing an actual security policy.

There are extremes that can come into play when deciding the level of security protections to adopt. On one hand, it can be extremely simple to provide basic system security.

For instance, if the system to be protected only comprises a second-hand computer, the sole use of which is to add a few numbers at the end of the day, deciding not to do anything special to protect it would be quite reasonable. The intrinsic value of the system is low and the value of the data are zero since they are not stored on the computer. A potential attacker infiltrating this system would only gain a calculator. The cost of securing such a system would probably be greater than the cost of a breach.

At the other end of the spectrum, you might want to protect the confidentiality of secret data in the most comprehensive way possible, trumping any other consideration. In this case, an appropriate response would be the total destruction of the data (securely erasing the files, shredding of the hard disks to bits, then dissolving these bits in acid, and so on). If there is an additional requirement that data must be kept in store for future use (although not necessarily readily available), and if cost still isn't a factor, then a starting point would be storing the data on iridium–platinum alloy plates stored in bomb-proof bunkers under various mountains in the world, each of which being (of course) both entirely secret and guarded by entire armies.

Extreme though these examples may seem, they would nevertheless be an adequate response to certain defined risks, insofar as they are the outcome of a thought process that takes into account the goals to reach and the constraints to fulfill. When coming from a reasoned decision, no security policy is more, or less, respectable than any other.

Coming back to a more typical case, an information system can be segmented into consistent and mostly independent subsystems. Each subsystem will have its own requirements and constraints, and so the risk assessment and the design of the security policy should be undertaken separately for each. A good principle to keep in mind is that a small attack surface is easier to defend than a large one. The network organization should also be designed accordingly: the sensitive services should be concentrated on a small number of machines, and these machines should only be accessible via a minimal number of routes or check-points. The logic is straightforward: it is easier to secure these checkpoints than to secure all the sensitive machines against the entirety of the outside world. It is at this point that the usefulness of network filtering (including by firewalls) becomes apparent. This filtering can be implemented with dedicated hardware but a simpler and more flexible solution is to use a software firewall such as the one integrated in the Linux kernel.

## 8.2. Possible Security Measures

As the previous section explained, there is no single response to the question of how to secure Kali Linux. It all depends on how you use it and what you are trying to protect.

### 8.2.1. On a Server

If you run Kali Linux on a publicly accessible server, you most likely want to secure network services by changing any default passwords that might be configured (see ["Securing Network Services"](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/securing-and-monitoring-kali-linux/securing-network-services/securing-network-services)) and possibly also by restricting their access with a firewall (see the ["Firewall or Packet Filtering"](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/securing-and-monitoring-kali-linux/firewall-or-packet-filtering/firewall-or-packet-filtering)) section.

If you hand out user accounts either directly on the server or on one of the services, you want to ensure that you set strong passwords (they should resist brute-force attacks). At the same time, you might want to setup _fail2ban_, which will make it much harder to brute-force passwords over the network (by filtering away IP addresses that exceed a limit of failed login attempts). Install _fail2ban_ with `apt update` followed by `apt install fail2ban`.

If you run web services, you probably want to host them over HTTPS to prevent network intermediaries from sniffing your traffic (which might include authentication cookies).

### 8.2.2. On a Laptop

The laptop of a penetration tester is not subject to the same risks as a public server: for instance, you are less likely to be subject to random scans from script kiddies and even when you are, you probably won't have any network services enabled.

Real risk often arises when you travel from one customer to the next. For example, your laptop could be stolen while traveling or seized by customs. That is why you most likely want to use full disk encryption (see ["Installation on a Fully Encrypted File System"](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/installing-kali-linux/step-by-step-installation-on-a-hard-drive/installation-on-a-fully-encrypted-file-system)) and possibly also setup the "nuke" feature (see [Adding a Nuke Password for Extra Safety](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/advanced-usage/adding-persistence-to-the-live-iso-with-a-usb-key/the-persistence-feature:-explanations)): the data that you have collected during your engagements are confidential and require the utmost protection.

You may also need firewall rules (see ["Firewall or Packet Filtering"](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/securing-and-monitoring-kali-linux/firewall-or-packet-filtering/firewall-or-packet-filtering)) but not for the same purpose as on the server. You might want to forbid all outbound traffic except the traffic generated by your VPN access. This is meant as a safety net, so that when the VPN is down, you immediately notice it (instead of falling back to the local network access). That way, you do not divulge the IP addresses of your customers when you browse the web or do other online activities. In addition, if you are performing a local internal engagement, it is best to remain in control of all of your activity to reduce the noise you create on the network, which can alert the customer and their defense systems.

## 8.3. Securing Network Services

In general, it is a good idea to disable services that you do not use. Kali makes it easy to do this since network services are disabled by default.

As long as services remain disabled, they do not pose any security threat. However, you must be careful when you enable them because:

- There is no firewall by default, so if they listen on all network interfaces, they are effectively publicly available.
- Some services have no authentication credentials and let you set them on first use; others have default (and thus widely known) credentials preset. Make sure to (re)set any password to something that only you know.
- Many services run as root with full administrator privileges, so the consequences of unauthorized access or a security breach are therefore usually severe.

**Default Credentials**

We won't list here all tools that come with default credentials, instead you should check the `README.Debian` file of the respective packages, as well as [kali.org/docs/](https://www.kali.org/docs/introduction/default-credentials/) and [tools.kali.org](https://tools.kali.org/) to see if the service needs some special care to be secured.

**SSH Service**

If you run in live mode, the password of the `kali` account is `kali`. Thus you should not enable SSH before changing the password of the kali account, or before having tweaked its configuration to disallow password-based logins.

You may also want to generate new host SSH keys, if you installed Kali by a pre-generated image. This is covered in [Generating New SSH Host Keys](https://portal.offsec.com/courses/pen-103-16306/learning/securing-and-monitoring-kali-linux-16820/exercises-16879/sect.configuring-services.html#sidebar.generating-new-ssh-host-keys).

## 8.4. Firewall or Packet Filtering

A _firewall_ is a piece of computer equipment with hardware, software, or both that parses the incoming or outgoing network packets (coming to or leaving from a local network) and only lets through those matching certain predefined conditions.

A filtering network gateway is a type of firewall that protects an entire network. It is usually installed on a dedicated machine configured as a gateway for the network so that it can parse all packets that pass in and out of the network. Alternatively, a local firewall is a software service that runs on one particular machine in order to filter or limit access to some services on that machine, or possibly to prevent outgoing connections by rogue software that a user could, willingly or not, have installed.

The Linux kernel embeds the _netfilter_ firewall. There is no turn-key solution for configuring any firewall since network and user requirements differ. However, you can control _netfilter_ from user space with the `iptables` and `ip6tables` commands. The difference between these two commands is that the former works for IPv4 networks, whereas the latter works on IPv6. Since both network protocol stacks will probably be around for many years, both tools will need to be used in parallel. You can also use the excellent GUI-based `fwbuilder` tool, which provides a graphical representation of the filtering rules.

However you decide to configure it, _netfilter_ is Linux's firewall implementation, so let's take a closer look at how it works.

### 8.4.1. Netfilter Behavior

_Netfilter_ uses four distinct tables, which store rules regulating three kinds of operations on packets:

- `filter` - concerns filtering rules (accepting, refusing, or ignoring a packet);
- `nat` (Network Address Translation) - concerns translation of source or destination addresses and ports of packets;
- `mangle` - concerns other changes to the IP packets (including the ToS—_Type of Service_—field and options);
- `raw` - allows other manual modifications on packets before they reach the connection tracking system.

Each table contains lists of rules called _chains_. The firewall uses standard chains to handle packets based on predefined circumstances. The administrator can create other chains, which will only be used when referred by one of the standard chains (either directly or indirectly).

The `filter` table has three standard chains:

- `INPUT` - concerns packets whose destination is the firewall itself.
- `OUTPUT` - concerns packets emitted by the firewall.
- `FORWARD` - concerns packets passing through the firewall (which is neither their source nor their destination).

The `nat` table also has three standard chains:

- `PREROUTING` - to modify packets as soon as they arrive.
- `POSTROUTING` - to modify packets when they are ready to go on their way.
- `OUTPUT` - to modify packets generated by the firewall itself.

These chains are illustrated in Figure 1

![Figure 1: How Netfilter Chains are Called](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/863fe2dcbd4e51d23350dcb0fd35f2e5-08_netfilter.png)

Figure 1: How Netfilter Chains are Called

Each chain is a list of rules; each rule is a set of conditions and an action to perform when the conditions are met. When processing a packet, the firewall scans the appropriate chain, one rule after another, and when the conditions for one rule are met, it jumps (hence the `-j` option in the commands with [_Rules_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/securing-and-monitoring-kali-linux/firewall-or-packet-filtering/syntax-of-%60iptables%60-and-%60ip6tables%60)) to the specified action to continue processing. The most common behaviors are standardized and dedicated actions exist for them. Taking one of these standard actions interrupts the processing of the chain, since the packets fate is already sealed (barring an exception mentioned below). Listed below are the _Netfilter_ actions.

- `ACCEPT`: allow the packet to go on its way.
- `REJECT`: reject the packet with an Internet control message protocol (ICMP) error packet (the `--reject-with type` option of `iptables` determines the type of error to send).
- `DROP`: delete (ignore) the packet.
- `LOG`: log (via `syslogd`) a message with a description of the packet. Note that this action does not interrupt processing, and the execution of the chain continues at the next rule, which is why logging refused packets requires both a LOG and a REJECT/DROP rule. Common parameters associated with logging include:
    - `--log-level`, with default value `warning`, indicates the `syslog` severity level.
    - `--log-prefix` allows specifying a text prefix to differentiate between logged messages.
    - `--log-tcp-sequence`, `--log-tcp-options`, and `--log-ip-options` indicate extra data to be integrated into the message: respectively, the TCP sequence number, TCP options, and IP options.
- `ULOG`: log a message via `ulogd`, which can be better adapted and more efficient than `syslogd` for handling large numbers of messages; note that this action, like LOG, also returns processing to the next rule in the calling chain.
- _chain_name_: jump to the given chain and evaluate its rules.
- `RETURN`: interrupt processing of the current chain and return to the calling chain; in case the current chain is a standard one, there's no calling chain, so the default action (defined with the `-P` option to `iptables`) is executed instead.
- `SNAT` (only in the `nat` table): apply _Source Network Address Translation_ (SNAT). Extra options describe the exact changes to apply, including the `--to-source address:port` option, which defines the new source IP address and/or port.
- `DNAT` (only in the `nat` table): apply _Destination Network Address Translation_ (DNAT). Extra options describe the exact changes to apply, including the `--to-destination address:port` option, which defines the new destination IP address and/or port.
- `MASQUERADE` (only in the `nat` table): apply _masquerading_ (a special case of _Source NAT_).
- `REDIRECT` (only in the `nat` table): transparently redirect a packet to a given port of the firewall itself; this can be used to set up a transparent web proxy that works with no configuration on the client side, since the client thinks it connects to the recipient whereas the communications actually go through the proxy. The `--to-ports port(s)` option indicates the port, or port range, where the packets should be redirected.

Other actions, particularly those concerning the `mangle` table, are outside the scope of this text. The iptables(8) and ip6tables(8) manual pages have a comprehensive list.

**What is ICMP?**

_Internet Control Message Protocol_ (ICMP) is the protocol used to transmit ancillary information on communications. It tests network connectivity with the `ping` command, which sends an ICMP _echo request_ message, which the recipient is meant to answer with an ICMP _echo reply_ message. It signals a firewall rejecting a packet, indicates an overflow in a receive buffer, proposes a better route for the next packets in the connection, and so on. This protocol is defined by several RFC documents. RFC777 and RFC792 were the first, but many others extended and/or revised the protocol.

> [http://www.faqs.org/rfcs/rfc777.html](http://www.faqs.org/rfcs/rfc777.html)

> [http://www.faqs.org/rfcs/rfc792.html](http://www.faqs.org/rfcs/rfc792.html)

For reference, a receive buffer is a small memory zone storing data between the time it arrives from the network and the time the kernel handles it. If this zone is full, new data cannot be received and ICMP signals the problem so that the emitter can slow down its transfer rate (which should ideally reach an equilibrium after some time).

Note that although an IPv4 network can work without ICMP, ICMPv6 is strictly required for an IPv6 network, since it combines several functions that were, in the IPv4 world, spread across ICMPv4, _Internet Group Membership Protocol_ (IGMP), and _Address Resolution Protocol_ (ARP). ICMPv6 is defined in RFC4443.

> [http://www.faqs.org/rfcs/rfc4443.html](http://www.faqs.org/rfcs/rfc4443.html)

### 8.4.2. Syntax of iptables and ip6tables

The `iptables` and `ip6tables` commands are used to manipulate tables, chains, and rules. Their `-t table` option indicates which table to operate on (by default, `filter`).

#### Commands

The major options for interacting with chains are listed below:

- `-L chain` lists the rules in the chain. This is commonly used with the `-n` option to disable name resolution (for example, `iptables -n -L INPUT` will display the rules related to incoming packets).
- `-N chain` creates a new chain. You can create new chains for a number of purposes, including testing a new network service or fending off a network attack.
- `-X chain` deletes an empty and unused chain (for example, `iptables -X ddos-attack`).
- `-A chain rule` adds a rule at the end of the given chain. Remember that rules are processed from top to bottom so be sure to keep this in mind when adding rules.
- `-I chain rule_num rule` inserts a rule before the rule number _rule_num_. As with the `-A` option, keep the processing order in mind when inserting new rules into a chain.
- `-D chain rule_num` (or `-D chain rule`) deletes a rule in a chain; the first syntax identifies the rule to be deleted by its number (`iptables -L --line-numbers` will display these numbers), while the latter identifies it by its contents.
- `-F chain` flushes a chain (deletes all its rules). For example, to delete all of the rules related to outgoing packets, you would run `iptables -F OUTPUT`. If no chain is mentioned, all the rules in the table are deleted.
- `-P chain action` defines the default action, or "policy" for a given chain; note that only standard chains can have such a policy. To drop all incoming traffic by default, you would run `iptables -P INPUT DROP`.

#### Rules

Each rule is expressed as `conditions -j action action_options`. If several conditions are described in the same rule, then the criterion is the conjunction (logical _AND_) of the conditions, which is at least as restrictive as each individual condition.

The `-p protocol` condition matches the protocol field of the IP packet. The most common values are `tcp`, `udp`, `icmp`, and `icmpv6`. This condition can be complemented with conditions on the TCP ports, with clauses such as `--source-port port` and `--destination-port port`.

**Negating Conditions**

Prefixing a condition with an exclamation mark negates the condition. For example, negating a condition on the `-p` option matches "any packet with a different protocol than the one specified." This negation mechanism can be applied to all other conditions as well.

The `-s address` or `-s network/mask` condition matches the source address of the packet. Correspondingly, `-d address` or `-d network/mask` matches the destination address.

The `-i interface` condition selects packets coming from the given network interface. `-o interface` selects packets going out on a specific interface.

The `--state state` condition matches the state of a packet in a connection (this requires the `ipt_conntrack` kernel module, for connection tracking). The `NEW` state describes a packet starting a new connection, `ESTABLISHED` matches packets belonging to an already existing connection, and `RELATED` matches packets initiating a new connection related to an existing one (which is useful for the `ftp-data` connections in the "active" mode of the FTP protocol).

There are many available options for `iptables` and `ip6tables` and mastering them all requires a great deal of study and experience. However, one of the options you will use most often is the one to block malicious network traffic from a host or range of hosts. For example, to silently block incoming traffic from the IP address `10.0.1.5` and the `31.13.74.0/24` class C subnet:

```
# iptables -A INPUT -s 10.0.1.5 -j DROP
# iptables -A INPUT -s 31.13.74.0/24 -j DROP
# iptables -n -L INPUT
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
DROP       all  -- 10.0.1.5             0.0.0.0/0
DROP       all  -- 31.13.74.0/24        0.0.0.0/0
```

Another commonly-used `iptables` command is to permit network traffic for a specific service or port. To allow users to connect to SSH, HTTP, and IMAP, you could run the following commands:

```
# iptables -A INPUT -m state --state NEW -p tcp --dport 22 -j ACCEPT
# iptables -A INPUT -m state --state NEW -p tcp --dport 80 -j ACCEPT
# iptables -A INPUT -m state --state NEW -p tcp --dport 143 -j ACCEPT
# iptables -n -L INPUT
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
DROP       all  -- 10.0.1.5             0.0.0.0/0
DROP       all  -- 31.13.74.0/24        0.0.0.0/0
ACCEPT     tcp  -- 0.0.0.0/0            0.0.0.0/0            state NEW tcp dpt:22
ACCEPT     tcp  -- 0.0.0.0/0            0.0.0.0/0            state NEW tcp dpt:80
ACCEPT     tcp  -- 0.0.0.0/0            0.0.0.0/0            state NEW tcp dpt:143
```

It is considered to be good computer _hygiene_ to clean up old and unnecessary rules. The easiest way to delete `iptables` rules is to reference the rules by line number, which you can retrieve with the `--line-numbers` option. Be wary though: dropping a rule will renumber all the rules appearing further down in the chain.

```
# iptables -n -L INPUT --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
1    DROP       all  -- 10.0.1.5             0.0.0.0/0
2    DROP       all  -- 31.13.74.0/24        0.0.0.0/0
3    ACCEPT     tcp  -- 0.0.0.0/0            0.0.0.0/0            state NEW tcp dpt:22
4    ACCEPT     tcp  -- 0.0.0.0/0            0.0.0.0/0            state NEW tcp dpt:80
5    ACCEPT     tcp  -- 0.0.0.0/0            0.0.0.0/0            state NEW tcp dpt:143
# iptables -D INPUT 2
# iptables -D INPUT 1
# iptables -n -L INPUT --line-numbers
Chain INPUT (policy ACCEPT)
num  target     prot opt source               destination
1    ACCEPT     tcp  -- 0.0.0.0/0            0.0.0.0/0            state NEW tcp dpt:22
2    ACCEPT     tcp  -- 0.0.0.0/0            0.0.0.0/0            state NEW tcp dpt:80
3    ACCEPT     tcp  -- 0.0.0.0/0            0.0.0.0/0            state NEW tcp dpt:143
```

There are more specific conditions, depending on the generic conditions described above. For more information refer to manual pages for iptables(8) and ip6tables(8)

### 8.4.3. Creating Rules

Each rule creation requires one invocation of `iptables` or `ip6tables`. Typing these commands manually can be tedious, so the calls are usually stored in a script so that the system is automatically configured the same way every time the machine boots. This script can be written by hand but it can also be interesting to prepare it with a high-level tool such as `fwbuilder`.

```
# apt install fwbuilder
```

The principle is simple. In the first step, describe all the elements that will be involved in the actual rules:

- The firewall itself, with its network interfaces.
- The networks, with their corresponding IP ranges.
- The servers.
- The ports belonging to the services hosted on the servers.

Next, create the rules with simple drag-and-drop actions on the objects as shown in Figure 2. A few contextual menus can change the condition (negating it, for instance). Then the action needs to be chosen and configured.

As far as IPv6 is concerned, you can either create two distinct rulesets for IPv4 and IPv6, or create only one and let `fwbuilder` translate the rules according to the addresses assigned to the objects.

![Figure 2: Figure 7.2. Fwbuilder's Main Window](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/d05760228a125e8efc2a52864ef94a0d-08_fwbuilder.png)

Figure 2: Figure 7.2. Fwbuilder's Main Window

`fwbuilder` will generate a script configuring the firewall according to the rules that you have defined. Its modular architecture gives it the ability to generate scripts targeting different systems including `iptables` for Linux, `ipf` for FreeBSD, and `pf` for OpenBSD.

### 8.4.4. Installing the Rules at Each Boot

In order to implement the firewall rules each time the machine is booted, you will need to register the configuration script in an `up` directive of the `/etc/network/interfaces` file. In the following example, the script is stored under `/usr/local/etc/arrakis.fw` (_arrakis_ being the hostname of the machine).

```
auto eth0
iface eth0 inet static
    address 192.168.0.1
    network 192.168.0.0
    netmask 255.255.255.0
    broadcast 192.168.0.255
    up /usr/local/etc/arrakis.fw
```

This example assumes that you are using `ifupdown` to configure the network interfaces. If you are using something else (like _NetworkManager_ or _systemd-networkd_), then refer to their respective documentation to find out ways to execute a script after the interface has been brought up.

## 8.5. Monitoring and Logging

Data confidentiality and protection is an important aspect of security but it is equally important to ensure availability of services. As an administrator and security practitioner, you must ensure that everything works as expected, and it is your responsibility to detect anomalous behavior and service degradation in a timely manner. Monitoring and logging software plays a key role in this aspect of security, providing insight into what is happening on the system and the network.

In this section, we will review some tools that can be used to monitor several aspects of a Kali system.

### 8.5.1. Monitoring Logs with logcheck

The `logcheck` program monitors log files every hour by default and sends unusual log messages in emails to the administrator for further analysis.

The list of monitored files is stored in `/etc/logcheck/logcheck.logfiles`. The default values work fine if the `/etc/rsyslog.conf` file has not been completely overhauled.

`logcheck` can report in various levels of detail: _paranoid_, _server_, and _workstation_. _paranoid_ is _very_ verbose and should probably be restricted to specific servers such as firewalls. _server_ is the default mode and is recommended for most servers. _workstation_ is obviously designed for workstations and is extremely terse, filtering out more messages than the other options.

In all three cases, `logcheck` should probably be customized to exclude some extra messages (depending on installed services), unless you really want to receive hourly batches of long uninteresting emails. Since the message selection mechanism is rather complex, `/usr/share/doc/logcheck-database/README.logcheck-database.gz` is a required—if challenging—read.

The applied rules can be split into several types:

- Those that qualify a message as a cracking attempt (stored in a file in the `/etc/logcheck/cracking.d/` directory).
- Ignored cracking attempts (`/etc/logcheck/cracking.ignore.d/`).
- Those classifying a message as a security alert (`/etc/logcheck/violations.d/`).
- Ignored security alerts (`/etc/logcheck/violations.ignore.d/`).
- Finally, those applying to the remaining messages (considered as _system events_).

_ignore.d_ files are used to (obviously) ignore messages. For example, a message tagged as a cracking attempt or a security alert (following a rule stored in a `/etc/logcheck/violations.d/myfile` file) can only be ignored by a rule in a `/etc/logcheck/violations.ignore.d/myfile` or `/etc/logcheck/violations.ignore.d/myfile-extension` file.

A system event is always signaled unless a rule in one of the `/etc/logcheck/ignore.d.{paranoid,server,workstation}/` directories states the event should be ignored. Of course, the only directories taken into account are those corresponding to verbosity levels equal or greater than the selected operation mode.

**Curly Brackets {} in a Command**

The use of braces in a bash command, has many different functions. In the example above, we are using it for a shorthand for repeating parts of the command. Bash then will expand out the command before executing it.

In the example below, it will have have the same outcome, three files created in our home directory.

```
# touch /home/kali/file1.txt /home/kali/file2.txt /home/kali/file3.txt
# touch /home/kali/file{1,2,3}.txt
```

### 8.5.2. Monitoring Activity in Real Time

`top` is an interactive tool that displays a list of currently running processes. The default sorting is based on the current amount of processor use and can be obtained with the `P` key. Other sort orders include a sort by occupied memory (`M` key), by total processor time (`T` key), and by process identifier (`N` key). The `k` key kills a process by entering its process identifier. The `r` key changes the priority of a process.

When the system seems to be overloaded, `top` is a great tool to see which processes are competing for processor time or consuming too much memory. In particular, it is often interesting to check if the processes consuming resources match the real services that the machine is known to host. An unknown process running as the "www-data" user should really stand out and be investigated since it's probably an instance of software installed and executed on the system through a vulnerability in a web application.

`top` is a very flexible tool and its manual page gives details on how to customize its display and adapt it to your personal needs and habits.

The `xfce4-taskmanager` graphical tool is similar to `top` and it provides roughly the same features. For GNOME users there is `gnome-system-monitor` and for KDE users there is `ksysguard` which are both similar as well.

### 8.5.3. Detecting Changes

Once a system is installed and configured, most system files should stay relatively static until the system is upgraded. Therefore, it is a good idea to monitor changes in system files since any unexpected change could be cause for alarm and should be investigated. This section presents a few of the most common tools used to monitor system files, detect changes, and optionally notify you as the administrator of the system.

#### Auditing Packages with dpkg --verify

`dpkg --verify` (or `dpkg -V`) is an interesting tool since it displays the system files that have been modified (potentially by an attacker), but this output should be taken with a grain of salt. To do its job, `dpkg` relies on checksums stored in its own database which is stored on the hard disk (found in `/var/lib/dpkg/info/_package_.md5sums`). A thorough attacker will therefore modify these files so they contain the new checksums for the subverted files, or an advanced attacker will compromise the package on your Debian mirror. To protect against this class of attack, use APT's digital signature verification system (see [_Validating Package Authenticity_](https://portal.offsec.com/courses/pen-103-16306/learning/securing-and-monitoring-kali-linux-16820/exercises-16879/sect.advanced-apt-config-and-usage.html#sect.package-authentication)) to properly verify the packages.

**What Is a File Fingerprint?**

As a reminder: a fingerprint is a value, often a number (although in hexadecimal notation), that contains a kind of signature for the contents of a file. This signature is calculated with an algorithm (MD5, SHA1, SHA256 being well-known examples) that more or less guarantees that even the tiniest change in the file contents will result in a change of the fingerprint; this is known as the "avalanche effect". A simple numerical fingerprint then serves as a litmus test to check whether the contents of a file have been altered. These algorithms are not reversible; in other words, for most of them, knowing a fingerprint doesn't allow finding the corresponding contents. Recent mathematical advances seem to weaken the absoluteness of these principles but their use is not called into question so far, since creating different contents yielding the same fingerprint still seems to be quite a difficult task.

Running `dpkg -V` will verify all installed packages and will print out a line for each file that fails verification. Each character denotes a test on some specific meta-data. Unfortunately, `dpkg` does not store the meta-data needed for most tests and will thus output question marks for them. Currently only the checksum test can yield a 5 on the third character (when it fails).

```
# dpkg -V
??5??????   /lib/systemd/system/ssh.service
??5?????? c /etc/libvirt/qemu/networks/default.xml
??5?????? c /etc/lvm/lvm.conf
??5?????? c /etc/salt/roster
```

In the example above, dpkg reports a change to SSH's service file that the administrator made to the packaged file instead of using an appropriate `/etc/systemd/system/ssh.service` override (which would be stored below `/etc` like any configuration change should be). It also lists multiple configuration files (identified by the "c" letter on the second field) that had been legitimately modified.

#### Monitoring Files: AIDE

The Advanced Intrusion Detection Environment (AIDE) tool checks file integrity and detects any change against a previously-recorded image of the valid system. The image is stored as a database (`/var/lib/aide/aide.db`) containing the relevant information on all files of the system (fingerprints, permissions, timestamps, and so on).

You can install AIDE by running `apt update` followed by `apt install aide`. You will first initialize the database with `aideinit`; it will then run daily (via the `/etc/cron.daily/aide` script) to check that nothing relevant changed. When changes are detected, AIDE records them in log files (`/var/log/aide/*.log`) and sends its findings to the administrator by email.

**Protecting the Database**

Since AIDE uses a local database to compare the states of the files, the validity of its results is directly linked to the validity of the database. If an attacker gets root permissions on a compromised system, they will be able to replace the database and cover their tracks. One way to prevent this subversion is to store the reference data on read-only storage media.

You can use options in `/etc/default/aide` to tweak the behavior of the `aide` package. The AIDE configuration proper is stored in `/etc/aide/aide.conf` and `/etc/aide/aide.conf.d/` (actually, these files are only used by `update-aide.conf` to generate `/var/lib/aide/aide.conf.autogenerated`). The configuration indicates which properties of which files need to be checked. For instance, the contents of log files changes routinely, and such changes can be ignored as long as the permissions of these files stay the same, but both contents and permissions of executable programs must be constant. Although not very complex, the configuration syntax is not fully intuitive and we recommend reading the aide.conf(5) manual page for more details.

A new version of the database is generated daily in `/var/lib/aide/aide.db.new`; if all recorded changes were legitimate, it can be used to replace the reference database.

Tripwire is very similar to AIDE; even the configuration file syntax is almost the same. The main addition provided by _tripwire_ is a mechanism to sign the configuration file so that an attacker cannot make it point at a different version of the reference database.

Samhain also offers similar features as well as some functions to help detect rootkits (see [The checksecurity and chkrootkit/rkhunter packages](https://portal.offsec.com/courses/pen-103-16306/learning/securing-and-monitoring-kali-linux-16820/exercises-16879/securing-the-kali-file-system-16941#sidebar.the-checksecurity-and-chkrootkit-rkhunter-packages) below). It can also be deployed globally on a network and record its traces on a central server (with a signature).

**The checksecurity and chkrootkit/rkhunter packages**

_checksecurity_ consists of several small scripts that perform basic checks on the system (searching for empty passwords, new setuid files, and so on) and warn you if these conditions are detected. Despite its explicit name, you should not rely solely on it to make sure a Linux system is secure.

The `chkrootkit` and `rkhunter` packages detect certain rootkits potentially installed on the system. As a reminder, these are pieces of software designed to hide the compromise of a system while discreetly keeping control of the machine. The tests are not 100 percent reliable but they can usually draw your attention to potential problems.

## 8.6. Summary

In this chapter, we took a look at the concept of security policies, highlighting various points to consider when defining such a policy and outlining some of the threats to your system and to you personally, as a security professional. We discussed desktop and laptop security measures as well as firewalls and packet filtering. Finally, we reviewed monitoring tools and strategies and showed how to best implement them to detect potential threats to your system.

Summary Tips:

- Take time to define a comprehensive security policy.
- Real risk often arises when you travel from one customer to the next. For example, your laptop could be stolen while traveling or seized by customs. Prepare for these unfortunate possibilities by using full disk encryption (see [Section 4.2.2, "Installation on a Fully Encrypted File System"](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/installing-kali-linux/step-by-step-installation-on-a-hard-drive/installation-on-a-fully-encrypted-file-system)) and consider the nuke feature (see [Adding a Nuke Password for Extra Safety](https://portal.offsec.com/courses/pen-103-16306/learning/securing-and-monitoring-kali-linux-16820/exercises-16879/sect.adding-persistence.html#sidebar.luks-nuke-password)) to protect your clients data.
- Disable services that you do not use. Kali makes it easy to do this since all external network services are disabled by default.
- If you are running Kali on a publicly accessible server, change any default passwords for services that might be configured (see [Section 7.3, "Securing Network Services"](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/securing-and-monitoring-kali-linux/securing-network-services/securing-network-services)) and restrict their access with a firewall (see [Section 7.4, "Firewall or Packet Filtering"](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/securing-and-monitoring-kali-linux/firewall-or-packet-filtering/firewall-or-packet-filtering)) prior to launching them.
- Use _fail2ban_ to detect and block password-guessing attacks and remote brute force password attacks.
- If you run web services, host them over HTTPS to prevent network intermediaries from sniffing your traffic (which might include authentication cookies).
- The Linux kernel embeds the _netfilter_ firewall. There is no turn-key solution for configuring any firewall, since network and user requirements differ. However, you can control _netfilter_ from user space with the `iptables` and `ip6tables` commands.
- Implement firewall rules (see [Section 7.4, "Firewall or Packet Filtering"](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/securing-and-monitoring-kali-linux/firewall-or-packet-filtering/firewall-or-packet-filtering)) to forbid all outbound traffic except the traffic generated by your VPN access. This is meant as a safety net, so that when the VPN is down you immediately notice it (instead of falling back to the local network access).
- `top` is an interactive tool that displays a list of currently running processes.
- The `logcheck` program monitors log files every hour by default and sends unusual log messages in emails to the administrator for further analysis.
- `dpkg --verify` (or `dpkg -V`) displays the system files that have been modified (potentially by an attacker), but relies on checksums, which may be subverted by a clever attacker.
- The Advanced Intrusion Detection Environment (AIDE) tool checks file integrity and detects any changes against a previously-recorded image of the valid system.
- Tripwire is very similar to AIDE but uses a mechanism to sign the configuration file, so that an attacker cannot make it point at a different version of the reference database.
- Consider the use of `rkhunter`, `checksecurity`, and `chkrootkit` to help detect rootkits on your system.

In the next chapter, we are going to dig into Debian fundamentals ([_Debian Package Management_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/debian-package-management)) and package management. You will quickly understand the power behind Kali's Debian roots and learn how the developers have harnessed that power. Be warned, the next chapter is fairly dense, but it is critical that you understand Debian basics and package management if you are going to be a Kali power user.

### 8.7.1. Securing Kali networking

#### Exercise:

1. Identify all open ports on your Kali instance.
2. Configure your Kali firewall to allow inbound TCP connections on ports 22, 80, and 443 only.
3. Verify other ports are blocked with a utility such as netcat.
4. Make sure these rules persist after a reboot. Reboot to check!

---

#### Exercise solution:

1. Check the open ports:

```
kali@kali:~$ netstat -tulpen
kali@kali:~$
kali@kali:~$ sudo iptables -n -L INPUT
kali@kali:~$
```

If you have ports you blocked, or previous iptables rules, you can drop them all:

```
kali@kali:~$ sudo iptables -F INPUT
kali@kali:~$
kali@kali:~$ sudo iptables -P INPUT ACCEPT
kali@kali:~$
kali@kali:~$ sudo iptables -P FORWARD ACCEPT
kali@kali:~$
kali@kali:~$ sudo iptables -P OUTPUT ACCEPT
kali@kali:~$
```

Now check to see if you can connect to port 4444 on your machine by running `netcat` in the following way.

_Note: that in this exercise, your IP addresses will, of course differ:_

```
kali@kali:~$ nc -lnvp 4444
listening on [any] 4444 ...
```

From your host machine, or another machine, try to connect to the listening netcat instance. Once connected, type some characters, and they should appear on the Kali VM nc listener:

```
root@HOST_MACHINE:~# nc -v 172.16.161.136 4444
aaaaaaaa
```

Note: If you do not see the characters you typed in your Kali nc listener, there's a problem. Get that resolved before you continue. If in a VM, switch to bridged networking instead of NAT, etc until this nc example works.

2. Configure the firewall with commands similar to the following:

```
kali@kali:~$ sudo iptables -P INPUT DROP
kali@kali:~$
kali@kali:~$ sudo iptables -A INPUT -i lo -j ACCEPT
kali@kali:~$
kali@kali:~$ sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
kali@kali:~$
kali@kali:~$ sudo iptables -A INPUT -m state --state NEW -p tcp --dport 22 -j ACCEPT
kali@kali:~$
kali@kali:~$ sudo iptables -A INPUT -m state --state NEW -p tcp --dport 80 -j ACCEPT
kali@kali:~$
kali@kali:~$ sudo iptables -A INPUT -m state --state NEW -p tcp --dport 443 -j ACCEPT
kali@kali:~$
```

Now check to see if you can connect to port 4444 on the firewalled machine by running netcat in the following way:

```
kali@kali:~$ nc -lvp 4444
listening on [any] 4444 ...
```

3. From your host machine, try to connect to the listening netcat instance. It should fail:

```
root@HOST_MACHINE:~# nc -v 172.16.161.136 4444
nc: connectx to 172.16.161.136 port 4444 (tcp) failed: Operation timed out
```

4. Now, create a iptables script from these rules:

```
kali@kali:~$ iptables-save | sudo tee /usr/local/etc/myconfig.fw
kali@kali:~$
```

Now register the configuration script in a pre-up directive of the /etc/network/interfaces file. Reboot to see if the rules persist!

```
auto lo
iface lo inet loopback
auto eth0
iface eth0 inet dhcp
pre-up iptables-restore < /usr/local/etc/myconfig.fw
```

### 8.7.2. Monitoring Kali services

#### Exercise:

1. Install logcheck on your Kali instance
2. Try brute forcing your own SSH service, and see if logcheck picks up on this, and reports the attack.
3. Create a cron'ed instance of logcheck, so that it runs once an hour, and creates a log file in /data/$(date-time).log

---

#### Exercise solution:

1. Install logcheck and run it for the first time:

```
kali@kali:~$ sudo apt-get install logcheck
kali@kali:~$
kali@kali:~$ sudo -u logcheck logcheck -o
kali@kali:~$
```

2. Download password list, brute force your SSH service with hydra, check that logcheck reports it:

```
kali@kali:~$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/500-worst-passwords.txt
kali@kali:~$
kali@kali:~$ hydra -l kali -P 500-worst-passwords.txt 127.0.0.1 ssh
kali@kali:~$
kali@kali:~$ tail -f /var/log/auth.log
kali@kali:~$
kali@kali:~$ sudo -u logcheck logcheck -o
kali@kali:~$
```

3. Next, write a bash script similar to the following:

```
kali@kali:~$ mkdir -p /data/
kali@kali:~$
kali@kali:~$ sudo -u logcheck logcheck -o > /data/$(date +"%m-%d-%Y-%T").log
kali@kali:~$
```

Make it executable and drop it in **/etc/cron.hourly.**

### 8.7.3. Securing the Kali file system

#### Exercise:

1. Install tripwire on your Kali machine. Monitor the `/var/www/html/` folder for changes.
2. If you did everything right, you'll get a lot of "File system errors". Fix it.

---

#### Exercise solution:

1. Install tripwire and configure the files you want to protect:

```
kali@kali:~$ sudo apt-get install tripwire # yes, yes, yes, yes
kali@kali:~$
kali@kali:~$ sudo nano /etc/tripwire/twpol.txt # list the directories and files you want to protect
kali@kali:~$
```

Add the following block of code in the tripwire policy file:

```
# Webserver file and folder monitoring
(
  rulename = "Web server file and directories",
  severity = $(SIG_HI)
)
{
        /var/www/html   -> $(SEC_BIN);
}
```

Now verify that any changes in /var/www/html get picked up by tripwire:

```
kali@kali:~$ sudo twadmin -m P /etc/tripwire/twpol.txt #Create Policy File
kali@kali:~$
kali@kali:~$ sudo tripwire --init #Initialize database
kali@kali:~$
kali@kali:~$ sudo tripwire --check #Initial integrity check
kali@kali:~$
kali@kali:~$ sudo touch /var/www/html/shell_backdoor.php
kali@kali:~$
kali@kali:~$ sudo tripwire --check
kali@kali:~$
kali@kali:~$ sudo tripwire --update-policy -Z low /etc/tripwire/twpol.txt
kali@kali:~$
kali@kali:~$ sudo tripwire --check
kali@kali:~$
```

2. The secret is in the /etc/tripwire/twpol.txt policy file. Delete the lines that are throwing errors. As of the time of this writing, the files may include:

- /etc/rc.boot
- /root/mail
- /root/Mail
- /root/.xsession-errors
- /root/.xauth
- /root/.tcshrc
- /root/.sawfish
- /root/.pinerc
- /root/.mc
- /root/.gnome_private
- /root/.gnome-desktop
- /root/.gnome
- /root/.esd_auth
- /root/.elm
- /root/.cshrc
- /root/.bash_profile
- /root/.bash_logout
- /root/.bash_history
- /root/.amandahosts
- /root/.addressbook.lu
- /root/.addressbook
- /root/.Xresources
- /root/.Xauthority
- /root/.ICEauthority

Once you change this file, you must update the policy file, and run the check again:

```
kali@kali:~$ sudo tripwire --update-policy -Z low /etc/tripwire/twpol.txt #Update Policy File
kali@kali:~$
kali@kali:~$ sudo tripwire --check
kali@kali:~$
```

---

#### Questions

Here's a cool and interesting use of `iptables`. You can turn any computer with a wireless interface into a wireless access point with `hostapd`. This solution comes from [here](https://linuxnatives.net/2014/create-wireless-access-point-hostapd):

```
kali@kali:~$ sudo iptables -t nat -F
kali@kali:~$
kali@kali:~$ sudo iptables -F
kali@kali:~$
kali@kali:~$ sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
kali@kali:~$
kali@kali:~$ sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
kali@kali:~$
kali@kali:~$ echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward # (DNS, dhcp still required)
kali@kali:~$
```

1. Also, check out this great great [reference guide for iptables](https://www.digitalocean.com/community/tutorials/iptables-essentials-common-firewall-rules-and-commands).

Next Module -> [Debian Package Management 🎙️](package_management.md)