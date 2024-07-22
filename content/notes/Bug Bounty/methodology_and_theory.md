---
title: Methodology & Theory🍓
tags:
  - Bug-Bounty
  - Theory
---
# Web

## WHOIS

WHOIS is a widely used query and response protocol designed to access databases that store information about registered internet resources. Primarily associated with domain names, WHOIS can also provide details about IP address blocks and autonomous systems. Think of it as a giant phonebook for the internet, letting you look up who owns or is responsible for various online assets.

```shell
gitblanc@htb[/htb]$ whois inlanefreight.com

[...]
Domain Name: inlanefreight.com
Registry Domain ID: 2420436757_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrar.amazon
Registrar URL: https://registrar.amazon.com
Updated Date: 2023-07-03T01:11:15Z
Creation Date: 2019-08-05T22:43:09Z
[...]
```

Each WHOIS record typically contains the following information:

- `Domain Name`: The domain name itself (e.g., example.com)
- `Registrar`: The company where the domain was registered (e.g., GoDaddy, Namecheap)
- `Registrant Contact`: The person or organization that registered the domain.
- `Administrative Contact`: The person responsible for managing the domain.
- `Technical Contact`: The person handling technical issues related to the domain.
- `Creation and Expiration Dates`: When the domain was registered and when it's set to expire.
- `Name Servers`: Servers that translate the domain name into an IP address.

### Why WHOIS Matters for Web Recon

WHOIS data serves as a treasure trove of information for penetration testers during the reconnaissance phase of an assessment. It offers valuable insights into the target organisation's digital footprint and potential vulnerabilities:

- `Identifying Key Personnel`: WHOIS records often reveal the names, email addresses, and phone numbers of individuals responsible for managing the domain. This information can be leveraged for social engineering attacks or to identify potential targets for phishing campaigns.
- `Discovering Network Infrastructure`: Technical details like name servers and IP addresses provide clues about the target's network infrastructure. This can help penetration testers identify potential entry points or misconfigurations.
- `Historical Data Analysis`: Accessing historical WHOIS records through services like [WhoisFreaks](https://whoisfreaks.com/) can reveal changes in ownership, contact information, or technical details over time. This can be useful for tracking the evolution of the target's digital presence.

## DNS

The `Domain Name System` (`DNS`) acts as the internet's GPS, guiding your online journey from memorable landmarks (domain names) to precise numerical coordinates (IP addresses). Much like how GPS translates a destination name into latitude and longitude for navigation, DNS translates human-readable domain names (like `www.example.com`) into the numerical IP addresses (like `192.0.2.1`) that computers use to communicate.

### The Hosts File

The `hosts` file is a simple text file used to map hostnames to IP addresses, providing a manual method of domain name resolution that bypasses the DNS process. While DNS automates the translation of domain names to IP addresses, the `hosts` file allows for direct, local overrides. This can be particularly useful for development, troubleshooting, or blocking websites.

The `hosts` file is located in `C:\Windows\System32\drivers\etc\hosts` on Windows and in `/etc/hosts` on Linux and MacOS. Each line in the file follows the format:

```txt
127.0.0.1       localhost
192.168.1.10    devserver.local
```

Common uses include redirecting a domain to a local server for development:

```txt
127.0.0.1       myapp.local
```

testing connectivity by specifying an IP address:

```txt
192.168.1.20    testserver.local
```

or blocking unwanted websites by redirecting their domains to a non-existent IP address:

```txt
0.0.0.0       unwanted-site.com
```

### Why DNS Matters for Web Recon

DNS is not merely a technical protocol for translating domain names; it's a critical component of a target's infrastructure that can be leveraged to uncover vulnerabilities and gain access during a penetration test:

- `Uncovering Assets`: DNS records can reveal a wealth of information, including subdomains, mail servers, and name server records. For instance, a `CNAME` record pointing to an outdated server (`dev.example.com` CNAME `oldserver.example.net`) could lead to a vulnerable system.
- `Mapping the Network Infrastructure`: You can create a comprehensive map of the target's network infrastructure by analysing DNS data. For example, identifying the name servers (`NS` records) for a domain can reveal the hosting provider used, while an `A` record for `loadbalancer.example.com` can pinpoint a load balancer. This helps you understand how different systems are connected, identify traffic flow, and pinpoint potential choke points or weaknesses that could be exploited during a penetration test.
- `Monitoring for Changes`: Continuously monitoring DNS records can reveal changes in the target's infrastructure over time. For example, the sudden appearance of a new subdomain (`vpn.example.com`) might indicate a new entry point into the network, while a `TXT` record containing a value like `_1password=...` strongly suggests the organization is using 1Password, which could be leveraged for social engineering attacks or targeted phishing campaigns.

### Digging DNS

#### DNS Tools

DNS reconnaissance involves utilizing specialized tools designed to query DNS servers and extract valuable information. Here are some of the most popular and versatile tools in the arsenal of web recon professionals:

| Tool                       | Key Features                                                                                            | Use Cases                                                                                                                                                       |
| -------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `dig`                      | Versatile DNS lookup tool that supports various query types (A, MX, NS, TXT, etc.) and detailed output. | Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, and in-depth analysis of DNS records. Check the note [dig 🍑](/notes/tools/dig.md) |
| `nslookup`                 | Simpler DNS lookup tool, primarily for A, AAAA, and MX records.                                         | Basic DNS queries, quick checks of domain resolution and mail server records.                                                                                   |
| `host`                     | Streamlined DNS lookup tool with concise output.                                                        | Quick checks of A, AAAA, and MX records.                                                                                                                        |
| `dnsenum`                  | Automated DNS enumeration tool, dictionary attacks, brute-forcing, zone transfers (if allowed).         | Discovering subdomains and gathering DNS information efficiently.                                                                                               |
| `fierce`                   | DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection.         | User-friendly interface for DNS reconnaissance, identifying subdomains and potential targets.                                                                   |
| `dnsrecon`                 | Combines multiple DNS reconnaissance techniques and supports various output formats.                    | Comprehensive DNS enumeration, identifying subdomains, and gathering DNS records for further analysis.                                                          |
| `theHarvester`             | OSINT tool that gathers information from various sources, including DNS records (email addresses).      | Collecting email addresses, employee information, and other data associated with a domain from multiple sources.                                                |
| Online DNS Lookup Services | User-friendly interfaces for performing DNS lookups.                                                    | Quick and easy DNS lookups, convenient when command-line tools are not available, checking for domain availability or basic information                         |
### Groping DNS

```shell
gitblanc@htb[/htb]$ dig google.com

; <<>> DiG 9.18.24-0ubuntu0.22.04.1-Ubuntu <<>> google.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449
;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             0       IN      A       142.251.47.142

;; Query time: 0 msec
;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP)
;; WHEN: Thu Jun 13 10:45:58 SAST 2024
;; MSG SIZE  rcvd: 54
```

This output is the result of a DNS query using the `dig` command for the domain `google.com`. The command was executed on a system running `DiG` version `9.18.24-0ubuntu0.22.04.1-Ubuntu`. The output can be broken down into four key sections:

1. Header
    
    - `;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449`: This line indicates the type of query (`QUERY`), the successful status (`NOERROR`), and a unique identifier (`16449`) for this specific query.
        
        - `;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0`: This describes the flags in the DNS header:
            - `qr`: Query Response flag - indicates this is a response.
            - `rd`: Recursion Desired flag - means recursion was requested.
            - `ad`: Authentic Data flag - means the resolver considers the data authentic.
            - The remaining numbers indicate the number of entries in each section of the DNS response: 1 question, 1 answer, 0 authority records, and 0 additional records.
    - `;; WARNING: recursion requested but not available`: This indicates that recursion was requested, but the server does not support it.
        
2. Question Section
    
    - `;google.com. IN A`: This line specifies the question: "What is the IPv4 address (A record) for `google.com`?"
3. Answer Section
    
    - `google.com. 0 IN A 142.251.47.142`: This is the answer to the query. It indicates that the IP address associated with `google.com` is `142.251.47.142`. The '`0`' represents the `TTL` (time-to-live), indicating how long the result can be cached before being refreshed.
4. Footer
    
    - `;; Query time: 0 msec`: This shows the time it took for the query to be processed and the response to be received (0 milliseconds).
        
    - `;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP)`: This identifies the DNS server that provided the answer and the protocol used (UDP).
        
    - `;; WHEN: Thu Jun 13 10:45:58 SAST 2024`: This is the timestamp of when the query was made.
        
    - `;; MSG SIZE rcvd: 54`: This indicates the size of the DNS message received (54 bytes).
        

An `opt pseudosection` can sometimes exist in a `dig` query. This is due to Extension Mechanisms for DNS (`EDNS`), which allows for additional features such as larger message sizes and DNS Security Extensions (`DNSSEC`) support.

### Subdomains

#### Active Subdomain Enumeration

This involves directly interacting with the target domain's DNS servers to uncover subdomains. One method is attempting a `DNS zone transfer`, where a misconfigured server might inadvertently leak a complete list of subdomains. However, due to tightened security measures, this is rarely successful.

A more common active technique is `brute-force enumeration`, which involves systematically testing a list of potential subdomain names against the target domain. Tools like `dnsenum`, `ffuf`, and `gobuster` can automate this process, using wordlists of common subdomain names or custom-generated lists based on specific patterns.

#### Passive Subdomain Enumeration

This relies on external sources of information to discover subdomains without directly querying the target's DNS servers. One valuable resource is `Certificate Transparency (CT) logs`, public repositories of SSL/TLS certificates. These certificates often include a list of associated subdomains in their Subject Alternative Name (SAN) field, providing a treasure trove of potential targets.

Another passive approach involves utilising `search engines` like Google or DuckDuckGo. By employing specialised search operators (e.g., `site:`), you can filter results to show only subdomains related to the target domain.

Additionally, various online databases and tools aggregate DNS data from multiple sources, allowing you to search for subdomains without directly interacting with the target.

### Subdomain Bruteforcing

There are several tools available that excel at brute-force enumeration:

| Tool                                                    | Description                                                                                                                     |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| [dnsenum](https://github.com/fwaeytens/dnsenum)         | Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains.                 |
| [fierce](https://github.com/mschwager/fierce)           | User-friendly tool for recursive subdomain discovery, featuring wildcard detection and an easy-to-use interface.                |
| [dnsrecon](https://github.com/darkoperator/dnsrecon)    | Versatile tool that combines multiple DNS reconnaissance techniques and offers customisable output formats.                     |
| [amass](https://github.com/owasp-amass/amass)           | Actively maintained tool focused on subdomain discovery, known for its integration with other tools and extensive data sources. |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans.               |
| [puredns](https://github.com/d3mondev/puredns)          | Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively.                           |
> You should check [Tools I use for Pentesting 🌀](tools_to_use.md) for more tools

### DNS Zone Transfers

While brute-forcing can be a fruitful approach, there's a less invasive and potentially more efficient method for uncovering subdomains – DNS zone transfers. This mechanism, designed for replicating DNS records between name servers, can inadvertently become a goldmine of information for prying eyes if misconfigured.

#### What is a Zone Transfer

A DNS zone transfer is essentially a wholesale copy of all DNS records within a zone (a domain and its subdomains) from one name server to another. This process is essential for maintaining consistency and redundancy across DNS servers. However, if not adequately secured, unauthorised parties can download the entire zone file, revealing a complete list of subdomains, their associated IP addresses, and other sensitive DNS data.

![](https://mermaid.ink/svg/pako:eNqNkc9qwzAMxl9F-JSx7gV8KISWXcY2aHYYwxdjK39obGWKvBFK333ukg5aGNQnW9b3Q_q-g3LkUWk14mfC6HDb2YZtMBHyGdFR9JanCvkL-WG9vh-4C38FDeX74w52J-0oUHxQRHhjG8ca-W5mXAgy4YqpoXotM8EReygqsSxANZRJWuJOpoXSEw0gC3ku3QTfvlQLfBZh9DeOdbELbCgMPQr-58u1LZsnKEq3j_Tdo28wYJS8iVqpgBxs57PjhxPLKGnzr1E6XzNxb5SJx9xnk1A1Rae0cMKVYkpNq3Rt-zG_0uCtnLM6t6DvhPh5zvM31uMPG8qm-A)

1. `Zone Transfer Request (AXFR)`: The secondary DNS server initiates the process by sending a zone transfer request to the primary server. This request typically uses the AXFR (Full Zone Transfer) type.
2. `SOA Record Transfer`: Upon receiving the request (and potentially authenticating the secondary server), the primary server responds by sending its Start of Authority (SOA) record. The SOA record contains vital information about the zone, including its serial number, which helps the secondary server determine if its zone data is current.
3. `DNS Records Transmission`: The primary server then transfers all the DNS records in the zone to the secondary server, one by one. This includes records like A, AAAA, MX, CNAME, NS, and others that define the domain's subdomains, mail servers, name servers, and other configurations.
4. `Zone Transfer Complete`: Once all records have been transmitted, the primary server signals the end of the zone transfer. This notification informs the secondary server that it has received a complete copy of the zone data.
5. `Acknowledgement (ACK)`: The secondary server sends an acknowledgement message to the primary server, confirming the successful receipt and processing of the zone data. This completes the zone transfer process.

#### The Zone Transfer Vulnerability

While zone transfers are essential for legitimate DNS management, a misconfigured DNS server can transform this process into a significant security vulnerability. The core issue lies in the access controls governing who can initiate a zone transfer.

In the early days of the internet, allowing any client to request a zone transfer from a DNS server was common practice. This open approach simplified administration but opened a gaping security hole. It meant that anyone, including malicious actors, could ask a DNS server for a complete copy of its zone file, which contains a wealth of sensitive information.

#### Exploiting Zone Transfers

You can use the `dig` command to request a zone transfer:

  DNS Zone Transfers

```shell
gitblanc@htb[/htb]$ dig axfr @nsztm1.digi.ninja zonetransfer.me

# other way
nslookup -query=AXFR inlanefreight.htb 10.129.7.202
```

This command instructs `dig` to request a full zone transfer (`axfr`) from the DNS server responsible for `zonetransfer.me`. If the server is misconfigured and allows the transfer, you'll receive a complete list of DNS records for the domain, including all subdomains.

`zonetransfer.me` is a service specifically setup to demonstrate the risks of zone transfers so that the `dig` command will return the full zone record.

### Virtual Hosts

Once the DNS directs traffic to the correct server, the web server configuration becomes crucial in determining how the incoming requests are handled. Web servers like Apache, Nginx, or IIS are designed to host multiple websites or applications on a single server. They achieve this through virtual hosting, which allows them to differentiate between domains, subdomains, or even separate websites with distinct content.

### Virtual Host Discovery Tools

While manual analysis of `HTTP headers` and reverse `DNS lookups` can be effective, specialised `virtual host discovery tools` automate and streamline the process, making it more efficient and comprehensive. These tools employ various techniques to probe the target server and uncover potential `virtual hosts`.

Several tools are available to aid in the discovery of virtual hosts:

| Tool                                                 | Description                                                                                                      | Features                                                                                                      |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| [gobuster](https://github.com/OJ/gobuster)           | A multi-purpose tool often used for directory/file brute-forcing, but also effective for virtual host discovery. | Fast, supports multiple HTTP methods, can use custom wordlists. Check [Gobuster 🐦](/notes/tools/Gobuster.md) |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | Similar to Gobuster, but with a Rust-based implementation, known for its speed and flexibility.                  | Supports recursion, wildcard discovery, and various filters.                                                  |
| [ffuf](https://github.com/ffuf/ffuf)                 | Another fast web fuzzer that can be used for virtual host discovery by fuzzing the `Host` header.                | Customizable wordlist input and filtering options.                                                            |
>[!Warning]
>Virtual host discovery can generate significant traffic and might be detected by intrusion detection systems (IDS) or web application firewalls (WAF). Exercise caution and obtain proper authorization before scanning any targets.

### Certificate Transparency Logs

In the sprawling mass of the internet, trust is a fragile commodity. One of the cornerstones of this trust is the `Secure Sockets Layer/Transport Layer Security` (`SSL/TLS`) protocol, which encrypts communication between your browser and a website. At the heart of SSL/TLS lies the `digital certificate`, a small file that verifies a website's identity and allows for secure, encrypted communication.

However, the process of issuing and managing these certificates isn't foolproof. Attackers can exploit rogue or mis-issued certificates to impersonate legitimate websites, intercept sensitive data, or spread malware. This is where Certificate Transparency (CT) logs come into play.

#### What are Certificate Transparency Logs?

`Certificate Transparency` (`CT`) logs are public, append-only ledgers that record the issuance of SSL/TLS certificates. Whenever a Certificate Authority (CA) issues a new certificate, it must submit it to multiple CT logs. Independent organisations maintain these logs and are open for anyone to inspect.

Think of CT logs as a `global registry of certificates`. They provide a transparent and verifiable record of every SSL/TLS certificate issued for a website. This transparency serves several crucial purposes:

- `Early Detection of Rogue Certificates`: By monitoring CT logs, security researchers and website owners can quickly identify suspicious or misissued certificates. A rogue certificate is an unauthorized or fraudulent digital certificate issued by a trusted certificate authority. Detecting these early allows for swift action to revoke the certificates before they can be used for malicious purposes.
- `Accountability for Certificate Authorities`: CT logs hold CAs accountable for their issuance practices. If a CA issues a certificate that violates the rules or standards, it will be publicly visible in the logs, leading to potential sanctions or loss of trust.
- `Strengthening the Web PKI (Public Key Infrastructure)`: The Web PKI is the trust system underpinning secure online communication. CT logs help to enhance the security and integrity of the Web PKI by providing a mechanism for public oversight and verification of certificates.

#### CT Logs and Web Recon

Certificate Transparency logs offer a unique advantage in subdomain enumeration compared to other methods. Unlike brute-forcing or wordlist-based approaches, which rely on guessing or predicting subdomain names, CT logs provide a definitive record of certificates issued for a domain and its subdomains. This means you're not limited by the scope of your wordlist or the effectiveness of your brute-forcing algorithm. Instead, you gain access to a historical and comprehensive view of a domain's subdomains, including those that might not be actively used or easily guessable.

Furthermore, CT logs can unveil subdomains associated with old or expired certificates. These subdomains might host outdated software or configurations, making them potentially vulnerable to exploitation.

In essence, CT logs provide a reliable and efficient way to discover subdomains without the need for exhaustive brute-forcing or relying on the completeness of wordlists. They offer a unique window into a domain's history and can reveal subdomains that might otherwise remain hidden, significantly enhancing your reconnaissance capabilities.

#### Searching CT Logs

There are two popular options for searching CT logs:

| Tool                                | Key Features                                                                                                     | Use Cases                                                                                                 | Pros                                              | Cons                                         |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------- | -------------------------------------------- |
| [crt.sh](https://crt.sh/)           | User-friendly web interface, simple search by domain, displays certificate details, SAN entries.                 | Quick and easy searches, identifying subdomains, checking certificate issuance history.                   | Free, easy to use, no registration required.      | Limited filtering and analysis options.      |
| [Censys](https://search.censys.io/) | Powerful search engine for internet-connected devices, advanced filtering by domain, IP, certificate attributes. | In-depth analysis of certificates, identifying misconfigurations, finding related certificates and hosts. | Extensive data and filtering options, API access. | Requires registration (free tier available). |
## Fingerprinting

Fingerprinting focuses on extracting technical details about the technologies powering a website or web application. Similar to how a fingerprint uniquely identifies a person, the digital signatures of web servers, operating systems, and software components can reveal critical information about a target's infrastructure and potential security weaknesses. This knowledge empowers attackers to tailor attacks and exploit vulnerabilities specific to the identified technologies.

Fingerprinting serves as a cornerstone of web reconnaissance for several reasons:

- `Targeted Attacks`: By knowing the specific technologies in use, attackers can focus their efforts on exploits and vulnerabilities that are known to affect those systems. This significantly increases the chances of a successful compromise.
- `Identifying Misconfigurations`: Fingerprinting can expose misconfigured or outdated software, default settings, or other weaknesses that might not be apparent through other reconnaissance methods.
- `Prioritising Targets`: When faced with multiple potential targets, fingerprinting helps prioritise efforts by identifying systems more likely to be vulnerable or hold valuable information.
- `Building a Comprehensive Profile`: Combining fingerprint data with other reconnaissance findings creates a holistic view of the target's infrastructure, aiding in understanding its overall security posture and potential attack vectors.

### Fingerprinting Techniques

There are several techniques used for web server and technology fingerprinting:

- `Banner Grabbing`: Banner grabbing involves analysing the banners presented by web servers and other services. These banners often reveal the server software, version numbers, and other details.
- `Analysing HTTP Headers`: HTTP headers transmitted with every web page request and response contain a wealth of information. The `Server` header typically discloses the web server software, while the `X-Powered-By` header might reveal additional technologies like scripting languages or frameworks.
- `Probing for Specific Responses`: Sending specially crafted requests to the target can elicit unique responses that reveal specific technologies or versions. For example, certain error messages or behaviours are characteristic of particular web servers or software components.
- `Analysing Page Content`: A web page's content, including its structure, scripts, and other elements, can often provide clues about the underlying technologies. There may be a copyright header that indicates specific software being used, for example.

A variety of tools exist that automate the fingerprinting process, combining various techniques to identify web servers, operating systems, content management systems, and other technologies:

|Tool|Description|Features|
|---|---|---|
|`Wappalyzer`|Browser extension and online service for website technology profiling.|Identifies a wide range of web technologies, including CMSs, frameworks, analytics tools, and more.|
|`BuiltWith`|Web technology profiler that provides detailed reports on a website's technology stack.|Offers both free and paid plans with varying levels of detail.|
|`WhatWeb`|Command-line tool for website fingerprinting.|Uses a vast database of signatures to identify various web technologies.|
|`Nmap`|Versatile network scanner that can be used for various reconnaissance tasks, including service and OS fingerprinting.|Can be used with scripts (NSE) to perform more specialised fingerprinting.|
|`Netcraft`|Offers a range of web security services, including website fingerprinting and security reporting.|Provides detailed reports on a website's technology, hosting provider, and security posture.|
|`wafw00f`|Command-line tool specifically designed for identifying Web Application Firewalls (WAFs).|Helps determine if a WAF is present and, if so, its type and configuration.|

### Fingerprinting a domain

- Check [Fingerprinting 🫐](/notes/fingerprinting.md)

## Crawling

`Crawling`, often called `spidering`, is the `automated process of systematically browsing the World Wide Web`. Similar to how a spider navigates its web, a web crawler follows links from one page to another, collecting information. These crawlers are essentially bots that use pre-defined algorithms to discover and index web pages, making them accessible through search engines or for other purposes like data analysis and web reconnaissance.

### robots.txt

Imagine you're a guest at a grand house party. While you're free to mingle and explore, there might be certain rooms marked "Private" that you're expected to avoid. This is akin to how `robots.txt` functions in the world of web crawling. It acts as a virtual "`etiquette guide`" for bots, outlining which areas of a website they are allowed to access and which are off-limits.

Technically, `robots.txt` is a simple text file placed in the root directory of a website (e.g., `www.example.com/robots.txt`). It adheres to the Robots Exclusion Standard, guidelines for how web crawlers should behave when visiting a website. This file contains instructions in the form of "directives" that tell bots which parts of the website they can and cannot crawl.

#### How robots.txt Works

The directives in robots.txt typically target specific user-agents, which are identifiers for different types of bots. For example, a directive might look like this:

Code: txt

```txt
User-agent: *
Disallow: /private/
```

This directive tells all user-agents (`*` is a wildcard) that they are not allowed to access any URLs that start with `/private/`. Other directives can allow access to specific directories or files, set crawl delays to avoid overloading a server or provide links to sitemaps for efficient crawling.

#### Understanding robots.txt Structure

The robots.txt file is a plain text document that lives in the root directory of a website. It follows a straightforward structure, with each set of instructions, or "record," separated by a blank line. Each record consists of two main components:

1. `User-agent`: This line specifies which crawler or bot the following rules apply to. A wildcard (`*`) indicates that the rules apply to all bots. Specific user agents can also be targeted, such as "Googlebot" (Google's crawler) or "Bingbot" (Microsoft's crawler).
2. `Directives`: These lines provide specific instructions to the identified user-agent.

Common directives include:

|Directive|Description|Example|
|---|---|---|
|`Disallow`|Specifies paths or patterns that the bot should not crawl.|`Disallow: /admin/` (disallow access to the admin directory)|
|`Allow`|Explicitly permits the bot to crawl specific paths or patterns, even if they fall under a broader `Disallow` rule.|`Allow: /public/` (allow access to the public directory)|
|`Crawl-delay`|Sets a delay (in seconds) between successive requests from the bot to avoid overloading the server.|`Crawl-delay: 10` (10-second delay between requests)|
|`Sitemap`|Provides the URL to an XML sitemap for more efficient crawling.|`Sitemap: https://www.example.com/sitemap.xml`|

#### robots.txt in Web Reconnaissance

For web reconnaissance, robots.txt serves as a valuable source of intelligence. While respecting the directives outlined in this file, security professionals can glean crucial insights into the structure and potential vulnerabilities of a target website:

- `Uncovering Hidden Directories`: Disallowed paths in robots.txt often point to directories or files the website owner intentionally wants to keep out of reach from search engine crawlers. These hidden areas might house sensitive information, backup files, administrative panels, or other resources that could interest an attacker.
- `Mapping Website Structure`: By analyzing the allowed and disallowed paths, security professionals can create a rudimentary map of the website's structure. This can reveal sections that are not linked from the main navigation, potentially leading to undiscovered pages or functionalities.
- `Detecting Crawler Traps`: Some websites intentionally include "honeypot" directories in robots.txt to lure malicious bots. Identifying such traps can provide insights into the target's security awareness and defensive measures.

### Well-Known URIs

The `.well-known` standard, defined in [RFC 8615](https://datatracker.ietf.org/doc/html/rfc8615), serves as a standardized directory within a website's root domain. This designated location, typically accessible via the `/.well-known/` path on a web server, centralizes a website's critical metadata, including configuration files and information related to its services, protocols, and security mechanisms.

By establishing a consistent location for such data, `.well-known` simplifies the discovery and access process for various stakeholders, including web browsers, applications, and security tools. This streamlined approach enables clients to automatically locate and retrieve specific configuration files by constructing the appropriate URL. For instance, to access a website's security policy, a client would request `https://example.com/.well-known/security.txt`.

The `Internet Assigned Numbers Authority` (`IANA`) maintains a [registry](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml) of `.well-known` URIs, each serving a specific purpose defined by various specifications and standards. Below is a table highlighting a few notable examples:

|URI Suffix|Description|Status|Reference|
|---|---|---|---|
|`security.txt`|Contains contact information for security researchers to report vulnerabilities.|Permanent|RFC 9116|
|`/.well-known/change-password`|Provides a standard URL for directing users to a password change page.|Provisional|https://w3c.github.io/webappsec-change-password-url/#the-change-password-well-known-uri|
|`openid-configuration`|Defines configuration details for OpenID Connect, an identity layer on top of the OAuth 2.0 protocol.|Permanent|http://openid.net/specs/openid-connect-discovery-1_0.html|
|`assetlinks.json`|Used for verifying ownership of digital assets (e.g., apps) associated with a domain.|Permanent|https://github.com/google/digitalassetlinks/blob/master/well-known/specification.md|
|`mta-sts.txt`|Specifies the policy for SMTP MTA Strict Transport Security (MTA-STS) to enhance email security.|Permanent|RFC 8461|

This is just a small sample of the many `.well-known` URIs registered with IANA. Each entry in the registry offers specific guidelines and requirements for implementation, ensuring a standardized approach to leveraging the `.well-known` mechanism for various applications.

#### Web Recon and .well-known

In web recon, the `.well-known` URIs can be invaluable for discovering endpoints and configuration details that can be further tested during a penetration test. One particularly useful URI is `openid-configuration`.

The `openid-configuration` URI is part of the OpenID Connect Discovery protocol, an identity layer built on top of the OAuth 2.0 protocol. When a client application wants to use OpenID Connect for authentication, it can retrieve the OpenID Connect Provider's configuration by accessing the `https://example.com/.well-known/openid-configuration` endpoint. This endpoint returns a JSON document containing metadata about the provider's endpoints, supported authentication methods, token issuance, and more:

```json
{
  "issuer": "https://example.com",
  "authorization_endpoint": "https://example.com/oauth2/authorize",
  "token_endpoint": "https://example.com/oauth2/token",
  "userinfo_endpoint": "https://example.com/oauth2/userinfo",
  "jwks_uri": "https://example.com/oauth2/jwks",
  "response_types_supported": ["code", "token", "id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"]
}
```

The information obtained from the `openid-configuration` endpoint provides multiple exploration opportunities:

1. `Endpoint Discovery`:
    - `Authorization Endpoint`: Identifying the URL for user authorization requests.
    - `Token Endpoint`: Finding the URL where tokens are issued.
    - `Userinfo Endpoint`: Locating the endpoint that provides user information.
2. `JWKS URI`: The `jwks_uri` reveals the `JSON Web Key Set` (`JWKS`), detailing the cryptographic keys used by the server.
3. `Supported Scopes and Response Types`: Understanding which scopes and response types are supported helps in mapping out the functionality and limitations of the OpenID Connect implementation.
4. `Algorithm Details`: Information about supported signing algorithms can be crucial for understanding the security measures in place.

Exploring the [IANA Registry](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml) and experimenting with the various `.well-known` URIs is an invaluable approach to uncovering additional web reconnaissance opportunities. As demonstrated with the `openid-configuration` endpoint above, these standardized URIs provide structured access to critical metadata and configuration details, enabling security professionals to comprehensively map out a website's security landscape.

### Creepy Crawlies

Web crawling is vast and intricate, but you don't have to embark on this journey alone. A plethora of web crawling tools are available to assist you, each with its own strengths and specialties. These tools automate the crawling process, making it faster and more efficient, allowing you to focus on analyzing the extracted data.

#### Popular Web Crawlers

1. `Burp Suite Spider`: Burp Suite, a widely used web application testing platform, includes a powerful active crawler called Spider. Spider excels at mapping out web applications, identifying hidden content, and uncovering potential vulnerabilities.
2. `OWASP ZAP (Zed Attack Proxy)`: ZAP is a free, open-source web application security scanner. It can be used in automated and manual modes and includes a spider component to crawl web applications and identify potential vulnerabilities.
3. `Scrapy (Python Framework)`: Scrapy is a versatile and scalable Python framework for building custom web crawlers. It provides rich features for extracting structured data from websites, handling complex crawling scenarios, and automating data processing. Its flexibility makes it ideal for tailored reconnaissance tasks. Check [ReconSpider 🧟](/notes/tools/ReconSpider.md)
4. `Apache Nutch (Scalable Crawler)`: Nutch is a highly extensible and scalable open-source web crawler written in Java. It's designed to handle massive crawls across the entire web or focus on specific domains. While it requires more technical expertise to set up and configure, its power and flexibility make it a valuable asset for large-scale reconnaissance projects.

## Search Engine Discovery

### Search Operators

Search operators are like search engines' secret codes. These special commands and modifiers unlock a new level of precision and control, allowing you to pinpoint specific types of information amidst the vastness of the indexed web.

While the exact syntax may vary slightly between search engines, the underlying principles remain consistent. Let's delve into some essential and advanced search operators:

| Operator                | Operator Description                                         | Example                                             | Example Description                                                                     |
| :---------------------- | :----------------------------------------------------------- | :-------------------------------------------------- | :-------------------------------------------------------------------------------------- |
| `site:`                 | Limits results to a specific website or domain.              | `site:example.com`                                  | Find all publicly accessible pages on example.com.                                      |
| `inurl:`                | Finds pages with a specific term in the URL.                 | `inurl:login`                                       | Search for login pages on any website.                                                  |
| `filetype:`             | Searches for files of a particular type.                     | `filetype:pdf`                                      | Find downloadable PDF documents.                                                        |
| `intitle:`              | Finds pages with a specific term in the title.               | `intitle:"confidential report"`                     | Look for documents titled "confidential report" or similar variations.                  |
| `intext:` or `inbody:`  | Searches for a term within the body text of pages.           | `intext:"password reset"`                           | Identify webpages containing the term “password reset”.                                 |
| `cache:`                | Displays the cached version of a webpage (if available).     | `cache:example.com`                                 | View the cached version of example.com to see its previous content.                     |
| `link:`                 | Finds pages that link to a specific webpage.                 | `link:example.com`                                  | Identify websites linking to example.com.                                               |
| `related:`              | Finds websites related to a specific webpage.                | `related:example.com`                               | Discover websites similar to example.com.                                               |
| `info:`                 | Provides a summary of information about a webpage.           | `info:example.com`                                  | Get basic details about example.com, such as its title and description.                 |
| `define:`               | Provides definitions of a word or phrase.                    | `define:phishing`                                   | Get a definition of "phishing" from various sources.                                    |
| `numrange:`             | Searches for numbers within a specific range.                | `site:example.com numrange:1000-2000`               | Find pages on example.com containing numbers between 1000 and 2000.                     |
| `allintext:`            | Finds pages containing all specified words in the body text. | `allintext:admin password reset`                    | Search for pages containing both "admin" and "password reset" in the body text.         |
| `allinurl:`             | Finds pages containing all specified words in the URL.       | `allinurl:admin panel`                              | Look for pages with "admin" and "panel" in the URL.                                     |
| `allintitle:`           | Finds pages containing all specified words in the title.     | `allintitle:confidential report 2023`               | Search for pages with "confidential," "report," and "2023" in the title.                |
| `AND`                   | Narrows results by requiring all terms to be present.        | `site:example.com AND (inurl:admin OR inurl:login)` | Find admin or login pages specifically on example.com.                                  |
| `OR`                    | Broadens results by including pages with any of the terms.   | `"linux" OR "ubuntu" OR "debian"`                   | Search for webpages mentioning Linux, Ubuntu, or Debian.                                |
| `NOT`                   | Excludes results containing the specified term.              | `site:bank.com NOT inurl:login`                     | Find pages on bank.com excluding login pages.                                           |
| `*` (wildcard)          | Represents any character or word.                            | `site:socialnetwork.com filetype:pdf user* manual`  | Search for user manuals (user guide, user handbook) in PDF format on socialnetwork.com. |
| `..` (range search)     | Finds results within a specified numerical range.            | `site:ecommerce.com "price" 100..500`               | Look for products priced between 100 and 500 on an e-commerce website.                  |
| `" "` (quotation marks) | Searches for exact phrases.                                  | `"information security policy"`                     | Find documents mentioning the exact phrase "information security policy".               |
| `-` (minus sign)        | Excludes terms from the search results.                      | `site:news.com -inurl:sports`                       | Search for news articles on news.com excluding sports-related content.                  |
### Google Dorking

Google Dorking, also known as Google Hacking, is a technique that leverages the power of search operators to uncover sensitive information, security vulnerabilities, or hidden content on websites, using Google Search.

Here are some common examples of Google Dorks, for more examples, refer to the [Google Hacking Database](https://www.exploit-db.com/google-hacking-database):

- Finding Login Pages:
    - `site:example.com inurl:login`
    - `site:example.com (inurl:login OR inurl:admin)`
- Identifying Exposed Files:
    - `site:example.com filetype:pdf`
    - `site:example.com (filetype:xls OR filetype:docx)`
- Uncovering Configuration Files:
    - `site:example.com inurl:config.php`
    - `site:example.com (ext:conf OR ext:cnf)` (searches for extensions commonly used for configuration files)
- Locating Database Backups:
    - `site:example.com inurl:backup`
    - `site:example.com filetype:sql`

## Web Archives

- [The Wayback Machine](https://web.archive.org/)

## Automating Recon

### Reconnaissance Frameworks

These frameworks aim to provide a complete suite of tools for web reconnaissance:

- [FinalRecon](https://github.com/thewhiteh4t/FinalRecon): A Python-based reconnaissance tool offering a range of modules for different tasks like SSL certificate checking, Whois information gathering, header analysis, and crawling. Its modular structure enables easy customisation for specific needs.
- [Recon-ng](https://github.com/lanmaster53/recon-ng): A powerful framework written in Python that offers a modular structure with various modules for different reconnaissance tasks. It can perform DNS enumeration, subdomain discovery, port scanning, web crawling, and even exploit known vulnerabilities.
- [theHarvester](https://github.com/laramies/theHarvester): Specifically designed for gathering email addresses, subdomains, hosts, employee names, open ports, and banners from different public sources like search engines, PGP key servers, and the SHODAN database. It is a command-line tool written in Python.
- [SpiderFoot](https://github.com/smicallef/spiderfoot): An open-source intelligence automation tool that integrates with various data sources to collect information about a target, including IP addresses, domain names, email addresses, and social media profiles. It can perform DNS lookups, web crawling, port scanning, and more.
- [OSINT Framework](https://osintframework.com/): A collection of various tools and resources for open-source intelligence gathering. It covers a wide range of information sources, including social media, search engines, public records, and more.