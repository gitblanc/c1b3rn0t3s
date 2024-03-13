---
title: Advanced Searching 🐢
---
Being able to use a search engine efficiently is a crucial skill. The following table shows some popular search modifiers that work with many popular search engines.  

|Symbol / Syntax|Function|
|---|---|
|`"search phrase"`|Find results with exact search phrase|
|`OSINT filetype:pdf`|Find files of type `PDF` related to a certain term.|
|`salary site:blog.tryhackme.com`|Limit search results to a specific site.|
|`pentest -site:example.com`|Exclude a specific site from results|
|`walkthrough intitle:TryHackMe`|Find pages with a specific term in the page title.|
|`challenge inurl:tryhackme`|Find pages with a specific term in the page URL.|

Note: In addition to `pdf`, other filetypes to consider are: `doc`, `docx`, `ppt`, `pptx`, `xls` and `xlsx`.

Each search engine might have a slightly varied set of rules and syntax. To learn about the specific syntax for the different search engines, you will need to visit their respective help pages. Some search engines, such as Google, provide a web interface for advanced searches: [Google Advanced Search](https://www.google.com/advanced_search). Other times, it is best to learn the syntax by heart, such as [Google Refine Web Searches](https://support.google.com/websearch/answer/2466433), [DuckDuckGo Search Syntax](https://help.duckduckgo.com/duckduckgo-help-pages/results/syntax/), and [Bing Advanced Search Options](https://help.bing.microsoft.com/apex/index/18/en-US/10002).

Search engines crawl the world wide web day and night to index new web pages and files. Sometimes this can lead to indexing confidential information. Examples of confidential information include:

- Documents for internal company use
- Confidential spreadsheets with usernames, email addresses, and even passwords
- Files containing usernames
- Sensitive directories
- Service version number (some of which might be vulnerable and unpatched)
- Error messages

Combining advanced Google searches with specific terms, documents containing sensitive information or vulnerable web servers can be found. Websites such as [Google Hacking Database](https://www.exploit-db.com/google-hacking-database) (GHDB) collect such search terms and are publicly available. Let's take a look at some of the GHDB queries to see if our client has any confidential information exposed via search engines. GHDB contains queries under the following categories:

- **Footholds**  
    Consider [GHDB-ID: 6364](https://www.exploit-db.com/ghdb/6364) as it uses the query `intitle:"index of" "nginx.log"` to discover Nginx logs and might reveal server misconfigurations that can be exploited.
- **Files Containing Usernames**  
    For example, [GHDB-ID: 7047](https://www.exploit-db.com/ghdb/7047) uses the search term `intitle:"index of" "contacts.txt"` to discover files that leak juicy information.
- **Sensitive Directories**  
    For example, consider [GHDB-ID: 6768](https://www.exploit-db.com/ghdb/6768), which uses the search term `inurl:/certs/server.key` to find out if a private RSA key is exposed.
- **Web Server Detection**  
    Consider [GHDB-ID: 6876](https://www.exploit-db.com/ghdb/6876), which detects GlassFish Server information using the query `intitle:"GlassFish Server - Server Running"`.
- **Vulnerable Files**  
    For example, we can try to locate PHP files using the query `intitle:"index of" "*.php"`, as provided by [GHDB-ID: 7786](https://www.exploit-db.com/ghdb/7786).
- **Vulnerable Servers**  
    For instance, to discover SolarWinds Orion web consoles, [GHDB-ID: 6728](https://www.exploit-db.com/ghdb/6728) uses the query `intext:"user name" intext:"orion core" -solarwinds.com`.
- **Error Messages**  
    Plenty of useful information can be extracted from error messages. One example is [GHDB-ID: 5963](https://www.exploit-db.com/ghdb/5963), which uses the query `intitle:"index of" errors.log` to find log files related to errors.

You might need to adapt these Google queries to fit your needs as the queries will return results from all web servers that fit the criteria and were indexed. To avoid legal issues, it is best to refrain from accessing any files outside the scope of your legal agreement.

We recommend you join the [Google Dorking](https://tryhackme.com/room/googledorking) room for more in-depth information.

Now we'll explore two additional sources that can provide valuable information without interacting with our target:

- Social Media
- Job ads

![](Pasted%20image%2020240125230409.png)

### Social Media

Social media websites have become very popular for not only personal use but also for corporate use. Some social media platforms can reveal tons of information about the target. This is especially true as many users tend to overshare details about themselves and their work. To name a few, it's worthwhile checking the following:

- LinkedIn
- Twitter
- Facebook
- Instagram

Social media websites make it easy to collect the names of a given company's employees; moreover, in certain instances, you might learn specific pieces of information that can reveal answers to password recovery questions or gain ideas to include in a targeted wordlist. Posts from technical staff might reveal details about a company’s systems and vendors. For example, a network engineer who was recently issued Juniper certifications may allude to Juniper networking infrastructure being used in their employer’s environment.

![](Pasted%20image%2020240125230433.png)
### Job Ads

Job advertisements can also tell you a lot about a company. In addition to revealing names and email addresses, job posts for technical positions could give insight into the target company’s systems and infrastructure. The popular job posts might vary from one country to another. Make sure to check job listing sites in the countries where your client would post their ads. Moreover, it is always worth checking their website for any job opening and seeing if this can leak any interesting information.

Note that the [Wayback Machine](https://archive.org/web/) can be helpful to retrieve previous versions of a job opening page on your client’s site.
