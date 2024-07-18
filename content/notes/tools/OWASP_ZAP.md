---
title: OWASP ZAP 🦈
tags:
  - Tool
---
## Configuration guide

1. Go to `Tools/Options/Local Servers/Proxies` and set port to 8081
2. Then go to `Tools/Options/Server Certificates` and click on save
3. Import it in your browser (in brave/chrome search for certificates and add it on authorities)

## Set up dark mode

- Go to `Options >> Display >> Look and Fell` and select `Flat Dark` :D

## Benefits of OWASP ZAP

It’s completely open source and free. There is no premium version, no features are locked behind a paywall, and there is no proprietary code.  

There’s a couple of feature benefits too with using OWASP ZAP over Burp Suite:
- **Automated Web Application Scan**: This will automatically passively and actively scan a web application, build a sitemap, and discover vulnerabilities. This is a paid feature in Burp. 
- **Web Spidering**: You can passively build a website map with Spidering. This is a paid feature in Burp.
- **Unthrottled Intruder**: You can bruteforce login pages within OWASP as fast as your machine and the web-server can handle. This is a paid feature in Burp.
- **No need to forward individual requests through Burp**: When doing manual attacks, having to change windows to send a request through the browser, and then forward in burp, can be tedious. OWASP handles both and you can just browse the site and OWASP will intercept automatically. This is NOT a feature in Burp.

If you’re already familiar with Burp the keywords translate over like so:

![](Pasted%20image%2020240508203539.png)

ZAP is unable to perform Login timing attacks. Burp can.

## Installation

Download from the official website: [zaproxy](https://www.zaproxy.org/download/)

- In Kali you can use: `sudo apt install zaproxy -y`

## How to perform an automated scan

Lets perform an automated scan. Click the big Automated Scan button and input your target:

![](Pasted%20image%2020240508204120.png)

The automated scan performs both passive and automated scans to build a sitemap and detect vulnerabilities.

On the next page you may see the options to select either to use “traditional spider” or “Ajax spider”.  

A **traditional spider scan** is a passive scan that enumerates links and directories of the website. It builds a website index without brute-forcing. This is much quieter than a brute-force attack and can still net a login page or other juicy details, but is not as comprehensive as a bruteforce.  

The **Ajax Spider** is an add-on that integrates in ZAP a crawler of AJAX rich sites called Crawljax. You can use it in conjunction with the traditional spider for better results. It uses your web browser and proxy.  

The easiest way to use the Ajax Spider is with HTMLUnit.   

To install HTML Unit use the command: `sudo apt install libjenkins-htmlunit-core-js-java`

And then select HtmlUnity from the Ajax Spider Dropdown. 


Both utilities can further be configured in the options menu (Ctrl+Alt+O)

Example Automated Scan Output:

![](Pasted%20image%2020240508204301.png)

With very minimal setup we were able to do an automated scan that gave us a sitemap and a handful of vulnerabilities.

## Manual scanning

Lets perform a manual scan against the DVWA machine.

Like Burp, you should set-up your proxy between OWASP ZAP and your Browser. We’ll be using Firefox. 

**OWASP Proxy Setup:**

![](Pasted%20image%2020240508204830.png)

![](Pasted%20image%2020240508204845.png)

**Add ZAP Certificates:**  

Without importing ZAP Certificates, ZAP is unable to handle simultaneous Web request forwarding and intercepting. Do not skip this step.

![](Pasted%20image%2020240508204910.png)

In the same options menu, navigate to Dynamic SSL Certificates and save the certificate somewhere you’ll remember and not delete.

![](Pasted%20image%2020240508204926.png)

Then, open Firefox, navigate to your preferences, and search for certificates and click “View Certificates”

![](Pasted%20image%2020240508204943.png)

Then click “Import” and then navigate to the earlier downloaded certificate and open it.

![](Pasted%20image%2020240508205000.png)

Select both and then hit OK.

## Scanning an Authenticated Web Application

Without your Zap application being authenticated, it can't scan pages that are only accessible when you've logged in. Lets set up the OWASP ZAP application to scan these pages, using your logged in session.

Lets go to the DVWA machine ([http://10.10.176.113](http://10.10.176.113/)), and login using the following credentials:  

**Username**: admin
**Password**: password

![](Pasted%20image%2020240508205540.png)

After logging in you should see this.

![](Pasted%20image%2020240508205551.png)

For the purpose of this exercise, once you've logged in, navigate to the DVWA Security tab and set the Security level to Low and then hit submit.

We're going to pass our authentication token into ZAP so that we can use the tool to scan authenticated webpages.

![](Pasted%20image%2020240508205600.png)

Enter inspect element and take note of your PHPSESSION cookie.

![](Pasted%20image%2020240508205611.png)

In ZAP open the HTTP Sessions tab with the new tab button, and set the authenticated session as active.

Now re-scan the application. You’ll see it’s able to pick up a lot more. This is because its able to see all of the sections of DVWA that was previously behind the login page.

## Brute-Force Directories

If the passive scans are not enough, you can use a wordlist attack and directory bruteforce through ZAP just as you would with gobuster. This would pick up pages that are not indexed.

![](Pasted%20image%2020240508210241.png)

First. Go into your ZAP Options (at the bottom navigation panel, with the screen plus button), navigate to Forced Browse, and add the Custom Wordlist. You can also add more threads and turn off recursive brute-forcing.

![](Pasted%20image%2020240508210254.png)

Then, right click the `site->attack->forced browse site`

![](Pasted%20image%2020240508210315.png)

Select your imported wordlist from the list menu, and then hit the play button!

## Brute-force Web Login

Lets brute-force a form to get credentials. Although we already know the credentials, lets see if we can use Zap to obtain credentials through a Brute-Force attack.

If you wanted to do this with BurpSuite, you'd need to intercept the request, and then pass it to Hydra. However, this process is much easier with ZAP!

![](Pasted%20image%2020240508210547.png)

Navigate to the Brute Force page on DVWA and attempt login as “admin” with the password “test123”

![](Pasted%20image%2020240508210559.png)

Then, find the GET request and open the Fuzz menu.

![](Pasted%20image%2020240508210611.png)

Then highlight the password you attempted and add a wordlist. This selects the area of the request you wish to replace with other data.

![](Pasted%20image%2020240508210621.png)

For speed we can use fasttrack.txt which is located in your /usr/share/wordlists if you’re using Kali Linux.

![](Pasted%20image%2020240508210633.png)

After running the fuzzer, sort the state tab to show Reflected results first. Sometimes you will get false-positives, but you can ignore the passwords that are less than 8 characters in length.

## ZAP Extensions

Want to further enhance ZAPs capabilities? Look at some of it’s downloadable extensions!

- [https://github.com/zaproxy/zap-extensions](https://github.com/zaproxy/zap-extensions)
- [https://github.com/bugcrowd/HUNT](https://github.com/bugcrowd/HUNT)[](https://github.com/bugcrowd/HUNT)

Let’s install the bugcrowd HUNT extensions for OWASP ZAP. This will passively scan for known vulnerabilities in web applications.

![](Pasted%20image%2020240508212034.png)

First navigate in your terminal somewhere you’d like to store the scripts

```shell
git clone https://github.com/bugcrowd/HUNT
```

![](Pasted%20image%2020240508212104.png)

Then in ZAP click the “Manage Add-Ons” icon

![](Pasted%20image%2020240508212113.png)

From the Marketplace install "Python Scripting" and "Community Scripts"

![](Pasted%20image%2020240508212132.png)

In ZAP Options, under Passive Scanner, make sure "Only scan messages in scope" is enabled. Then hit OK.

![](Pasted%20image%2020240508212142.png)

In ZAP open the Scripts tab.

![](Pasted%20image%2020240508212149.png)

And under Passive Rules, find and enable the HUNT.py script

Now when you browse sites and HUNT will passively scan for SQLi, LFI, RFI, SSRF, and others. Exciting!