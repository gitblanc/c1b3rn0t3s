---
title: Built-in Tools 🐔
tags:
  - TryHackMe
  - Theory
---
This note focuses on:

- `whois`
- `dig`, `nslookup`, `host`
- `traceroute`/`tracert`

Before we start using the `whois` tool, let's look at WHOIS. WHOIS is a request and response protocol that follows the [RFC 3912](https://www.ietf.org/rfc/rfc3912.txt) specification. A WHOIS server listens on TCP port 43 for incoming requests. The domain registrar is responsible for maintaining the WHOIS records for the domain names it is leasing. `whois` will query the WHOIS server to provide all saved records. In the following example, we can see `whois` provides us with:

- Registrar WHOIS server
- Registrar URL
- Record creation date
- Record update date
- Registrant contact info and address (unless withheld for privacy)
- Admin contact info and address (unless withheld for privacy)
- Tech contact info and address (unless withheld for privacy)

Pentester Terminal

````shell
           
pentester@TryHackMe$ whois thmredteam.com
[Querying whois.verisign-grs.com]
[Redirected to whois.namecheap.com]
[Querying whois.namecheap.com]
[whois.namecheap.com]
Domain name: thmredteam.com
Registry Domain ID: 2643258257_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.namecheap.com
Registrar URL: http://www.namecheap.com
Updated Date: 0001-01-01T00:00:00.00Z
Creation Date: 2021-09-24T14:04:16.00Z
Registrar Registration Expiration Date: 2022-09-24T14:04:16.00Z
Registrar: NAMECHEAP INC
Registrar IANA ID: 1068
Registrar Abuse Contact Email: abuse@namecheap.com
Registrar Abuse Contact Phone: +1.6613102107
Reseller: NAMECHEAP INC
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registry Registrant ID: 
Registrant Name: Withheld for Privacy Purposes
Registrant Organisation: Privacy service provided by Withheld for Privacy ehf
Registrant Street: Kalkofnsvegur 2 
Registrant City: Reykjavik
Registrant State/Province: Capital Region
Registrant Postal Code: 101
Registrant Country: IS
Registrant Phone: +354.4212434
Registrant Phone Ext: 
Registrant Fax: 
Registrant Fax Ext: 
Registrant Email: 4c9d5617f14e4088a4396b2f25430925.protect@withheldforprivacy.com
Registry Admin ID: 
Admin Name: Withheld for Privacy Purposes
[...]
Tech Name: Withheld for Privacy Purposes
[...]
Name Server: kip.ns.cloudflare.comName Server: uma.ns.cloudflare.com
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2021-10-13T10:42:40.11Z <<<
For more information on Whois status codes, please visit https://icann.org/epp
````

As we can see above, it is possible to gain a lot of valuable information with only a domain name. After a `whois` lookup, we might get lucky and find names, email addresses, postal addresses, and phone numbers, in addition to other technical information. At the end of the `whois` query, we find the authoritative name servers for the domain in question.

DNS queries can be executed with many different tools found on our systems, especially Unix-like systems. One common tool found on Unix-like systems, Windows, and macOS is `nslookup`. In the following query, we can see how `nslookup` uses the default DNS server to get the A and AAAA records related to our domain.

Pentester Terminal

````shell
pentester@TryHackMe$ nslookup cafe.thmredteam.com
Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
Name:	cafe.thmredteam.com
Address: 104.21.93.169
Name:	cafe.thmredteam.com
Address: 172.67.212.249
Name:	cafe.thmredteam.com
Address: 2606:4700:3034::ac43:d4f9
Name:	cafe.thmredteam.com
Address: 2606:4700:3034::6815:5da9
````

Another tool commonly found on Unix-like systems is `dig`, short for Domain Information Groper (dig). `dig` provides a lot of query options and even allows you to specify a different DNS server to use. For example, we can use Cloudflare's DNS server: `dig @1.1.1.1 tryhackme.com`.

Pentester Terminal

````shell 
pentester@TryHackMe$ dig cafe.thmredteam.com @1.1.1.1

; <<>> DiG 9.16.21-RH <<>> cafe.thmredteam.com @1.1.1.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16698
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;cafe.thmredteam.com.		IN	A

;; ANSWER SECTION:
cafe.thmredteam.com.	3114	IN	A	104.21.93.169
cafe.thmredteam.com.	3114	IN	A	172.67.212.249

;; Query time: 4 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
;; WHEN: Thu Oct 14 10:44:11 EEST 2021
;; MSG SIZE  rcvd: 80
````

`host` is another useful alternative for querying DNS servers for DNS records. Consider the following example.

Pentester Terminal

````shell
pentester@TryHackMe$ host cafe.thmredteam.com
cafe.thmredteam.com has address 172.67.212.249
cafe.thmredteam.com has address 104.21.93.169
cafe.thmredteam.com has IPv6 address 2606:4700:3034::ac43:d4f9
cafe.thmredteam.com has IPv6 address 2606:4700:3034::6815:5da9
````

The final tool that ships with Unix-like systems is `traceroute`, or on MS Windows systems, `tracert`. As the name indicates, it traces the route taken by the packets from our system to the target host. The console output below shows that `traceroute` provided us with the routers (hops) connecting us to the target system. It's worth stressing that some routers don’t respond to the packets sent by `traceroute`, and as a result, we don’t see their IP addresses; a `*` is used to indicate such a case.

Pentester Terminal

````shell  
pentester@TryHackMe$ traceroute cafe.thmredteam.com
traceroute to cafe.thmredteam.com (172.67.212.249), 30 hops max, 60 byte packets
 1  _gateway (192.168.0.1)  3.535 ms  3.450 ms  3.398 ms
 2  * * *
 3  * * *
 4  * * *
 5  * * *
 6  * * *
 7  172.16.79.229 (172.16.79.229)  4.663 ms  6.417 ms  6.347 ms
 8  * * *
 9  172.16.49.1 (172.16.49.1)  6.688 ms 172.16.48.1 (172.16.48.1)  6.671 ms 172.16.49.1 (172.16.49.1)  6.651 ms
10  213.242.116.233 (213.242.116.233)  96.769 ms 81.52.187.243 (81.52.187.243)  96.634 ms  96.614 ms
11  bundle-ether302.pastr4.paris.opentransit.net (193.251.131.116)  96.592 ms  96.689 ms  96.671 ms
12  193.251.133.251 (193.251.133.251)  96.679 ms  96.660 ms  72.465 ms
13  193.251.150.10 (193.251.150.10)  72.392 ms 172.67.212.249 (172.67.212.249)  91.378 ms  91.306 ms
````

In summary, we can always rely on:

- `whois` to query the WHOIS database
- `nslookup`, `dig`, or `host` to query DNS servers

WHOIS databases and DNS servers hold publicly available information, and querying either does not generate any suspicious traffic.

Moreover, we can rely on Traceroute (`traceroute` on Linux and macOS systems and `tracert` on MS Windows systems) to discover the hops between our system and the target host.