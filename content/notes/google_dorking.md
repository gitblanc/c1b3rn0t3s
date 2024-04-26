---
title: Google Dorking 👓
---
- Credits to [OsintCurious.us](https://www.osintcurio.us/2019/12/20/google-dorks/)

The term ‘Google dorks’ has been around for quite some years by now and is used for specific search queries that use Google’s search operators, combined with targeted parameters to find specific information. And in the webcast/podcast of early December we reached out to the listeners, to send us your favourite Google Dork.

We grouped the dorks by the type of target information that it is used for, starting with the human being:

## People and Accounts

The first one that was posted on Twitter after we talked about it, came from [Kirby](https://twitter.com/kirbstr). She loves to find emails based on a username, so she lets Google do the heavy lifting. Instead of searching for all possible email providers, she replaced the domain name with an asterisk:

```shell
"username*com"
```

[OSINT Techniques](https://twitter.com/OSINTtechniques) shared his favourite dork, that searches for online resumes of a person. You can search within the URL of a website, or within the text of a site:

```shell
inurl:resume “john smith”
intext:resume “john smith”
```

[OSINT Combine](https://twitter.com/osintcombine) also shared a tweet that focuses on jobs. By targeting the LinkedIn site, he searches for people with a specific job title and location. But he shared another trick, which is the fact that you can search for icons or Unicode characters:

```shell
site:http://linkedin.com/in "<job title>" (☎ OR ☏ OR ✆ OR 📱) +"<location>"
```

And in case you are looking for a specific name, you can of course always search for:

```shell
"<name>" (☎ OR ☏ OR ✆ OR 📱)
```

The last dork touching people that was sent to us via Twitter, came from [Jung Kim](https://twitter.com/Azn_CyberSleuth). He shows a nice dork to find people within GitHub code:

```shell
site:http://github.com/orgs/*/people
```

And if you are looking for lists of attendees, or finalists, [Jung Kim](https://twitter.com/Azn_CyberSleuth) shared a second dork with us:

```shell
intitle:final.attendee.list OR inurl:final.attendee.list
```

Another tips was given by [Nixintel](http://twitter.com/nixintel), that searches for login information on a Trello board. Since a lot of people forget to tighten the security settings on their Trello board, loads of them are exposed and indexed by Google:

```shell
site:http://trello.com password + admin OR username
```

## Documents

To finding specific documents within a website or domain name, [CyberSquarePeg](https://twitter.com/CyberSquarePeg) shared with us the basic Google dork to do just that:

```shell
site:<domain> filetype:PDF
```

_Note: Instead of ‘filetype:’ you can also use the abbreviation for extention, which is: ‘ext:’_

[Alex](https://twitter.com/JudgeMegapolis) shared with us a search that is also targeting PDF’s, but he shows how to search for only those documents that might contain possible email information. Change the `<domain>` to the specific company domain name and have a look what’s out there:

```shell
filetype:pdf <domain> "email"
```

[Zerconil](https://twitter.com/zerconil) shared a dork that is looking for XLS files within government websites:

```shell
filetype:xls site:.gov
```

Of course you can look for more extensions, depending on what you are trying to achieve. You do that by adding multiple file extensions in between double quotes, where each of the extensions is being separated by a pipe of vertical line ‘|’. And don’t forget to add extra spaces around it:

```shell
filetype:"xls | xlsx | doc | docx | txt | pdf" site:.gov
```

In case you are looking for even more extensions that might be of interest, Twitter user [Insider](https://twitter.com/cypheractivist) helped us out there with his tip that he sent via Twitter:

```shell
filetype:"doc | pdf | xls | txt | ps | rtf | odt | sxw | psw | ppt | pps | xml"
```

And another tip shared by [Jung Kim](https://twitter.com/Azn_CyberSleuth), this time searching for any kind of document on HubSpot that contains the word ‘trends’ and that has the year 2019 in the URL:

```shell
site:http://cdn2.hubspot.net intitle:2019 OR inurl:2019 "* trends"
```

[Dutch_Osintguy](https://twitter.com/dutch_osintguy/status/1201202175441022977) shared another one targeting Google as email platform with looking for txt OR pdf files containing words like FBI, CIA Or NYpD (these are interchangeable by words by your particular interest):

```shell
"Email delivery powered by Google" ext:pdf OR ext:txt nypd OR fbi OR cia
```

## Cloud, Buckets and Databases

[Dutch_OsintGuy](https://twitter.com/dutch_osintguy/status/1201204073602715653) shared one of his favorite dorks. This one is searching for indexed documents that contain the phrase ‘confidential’ or ‘top secret’ within open Amazon S3 buckets:

```shell
site:http://s3.amazonaws.com confidential OR "top secret"
```

Another search touching Amazon buckets came from [Zerconil](https://twitter.com/zerconil), that might show some confidential login information within XLS files:

```shell
s3 site:http://amazonaws.com filetype:xls password
```

And here again the tip of maybe adding all kinds of interesting extensions, since Excel files might not be the only interesting document format that contain the information you are looking for.

And of course you can search for copies of databases via Google too. To find some of them, simply search for:

```shell
ext:sql intext:"-- phpMyAdmin SQL Dump"
```

## Social Media

[Jules Darmanin](https://twitter.com/JulesDrmnn) shared a tip on how to find out whether a certain tweet was shared on other media, for instance a news site. For that, search for the specific text and tell Google to ignore anything that was posted within twitter.com by adding the minus sign to that part of the dork:

```shell
"text of a tweet" -site:https://twitter.com
```

Almost the same method can be used to search messages and/or links for a specific username not coming from that username his/her account. For example this searches for links or information containing ‘@dutch_osintguy’ but not coming directly of the twitter user timeline Dutch_osintguy

```shell
@dutch_osintguy -site:twitter.com/dutch_osintguy
```

## Want to learn more about Google Dorking ?

Using Google search operators as effective as possible is an art by itself. For OSINT the goal is (most of the time) to create your targeted haystack. But by using **well chosen keywords** and dorked together with **the right search operators** you will be able to create a haystack with as **low** a possible **volume** with an as **high** as possible **probability**.

Keep in mind that Google has limited the amount of keywords that you can search for to a total of 32 words. This means that all search term beyond the 32 word limit will not be taken into account (keyword 33 and beyond) in a search. Also there is a character limit per one keyword. A single keyword can not be longer than 2048 characters.

All of the above Google dorks came from a specific intelligence requirement question. Without a good question it is way harder to craft your search query is targeted as possible. So an advice might be, what are you looking for? What question are you trying to answer? That makes it easier to pinpoint which search operators might be needed to answer that specific question.

For extra inspiration you might want to look into sources like the [Google Hacking Database](https://www.exploit-db.com/google-hacking-database). This is a website that collects user generated Google dorks with a specific need or interest. Another great resource to learn how to craft a good Google dork is the [GoogleGuide](http://www.googleguide.com/advanced_operators_reference.html). The GoogleGuide is a good website to see which Google search operators are available and how you can use them for your research. Even though it is a bit old (info from 2007) the GoogleGuide still has a lot to offer en learn from when you are OSINTcurious. Another option is the [ahrefs blog](https://ahrefs.com/blog/google-advanced-search-operators/) about Google search operators. They visually explain how you an use 42 search operators.

There is also one Google Dorking book which is a must read when it comes to learning and understanding how to use google searches for research. It is a book by [Johnny Long](https://twitter.com/ihackstuff) with the title “[Google hacking for penetration testers”](https://www.amazon.co.uk/Google-Hacking-Penetration-Testers-Johnny/dp/1931836361/ref=pd_sbs_14_1/260-3306090-7596003?_encoding=UTF8&pd_rd_i=1931836361&pd_rd_r=f99c768e-ad16-468f-83ad-9fe8653ac153&pd_rd_w=1Jcwv&pd_rd_wg=9Q0Dt&pf_rd_p=f4a31d1d-8f61-48f5-b6f4-a22ba06df575&pf_rd_r=NYFJ3M3Q749XC9Q0S0WC&psc=1&refRID=NYFJ3M3Q749XC9Q0S0WC). Within the osint community there is a debate on which version is the best for OSINT practitioners. My personal (Dutch_Osintguy) opinion is that version 1 of this book is the best and most complete. Non the less all other versions (there are 3 editions) are worth the read.

3. **Reverse your thinking**

One of the methods for geolocating an image is to do an image reverse search. This means that we are searching for the image itself online, and if the image has been indexed by search engines we may find the exact image or we can do a visual search or crop search to help us find similar images. 

 [Aric Toler](https://twitter.com/AricToler) from [Bellingcat](https://www.bellingcat.com/) has written a fantastic guide on reversing images, please read it [here](https://www.bellingcat.com/resources/how-tos/2019/12/26/guide-to-using-reverse-image-search-for-investigations/). [OSINT Curious](https://osintcurio.us/) also has a [write-up](https://osintcurio.us/2020/04/12/tips-and-tricks-on-reverse-image-searches/) on the topic that you should look through before attempting this challenge. 

I recommend adding this extension to ease the workflow for when you find images online that you want to do an image reverse on:

**Addon description:** "Perform a search by image. Choose between the image search engines Google, Bing, Yandex, TinEye and Baidu."

**Chrome:** [RevEye Reverse Image Search](https://chrome.google.com/webstore/search/RevEye%20Reverse%20Image%20Search?hl=no) - 

**Firefox:** [RevEye Reverse Image Search](https://addons.mozilla.org/nb-NO/firefox/addon/reveye-ris/)