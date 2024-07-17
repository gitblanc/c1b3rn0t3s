---
title: Helping yourself and getting help 🌀
---
- *All the info was extracted from [Offsec, Pen-103](https://portal.offsec.com/courses/pen-103-16306/)*, under the following [licencese](https://creativecommons.org/licenses/by-sa/3.0/)

# 7. Helping Yourself and Getting Help

No matter how many years of experience you have, there is no doubt that—sooner or later—you will encounter a problem. Solving that problem is then often a matter of understanding it and then taking advantage of various resources to find a solution or work-around.

In this chapter, we will discuss the various information sources available and discuss the best strategies for finding the help you need or the solution to a problem you might be facing. We will also take you on a tour of some of the Kali Linux community resources available, including [forums](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/helping-yourself-and-getting-help/kali-linux-communities/forums-on-forums.kali.org) and [Internet Relay Chat (IRC)](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/helping-yourself-and-getting-help/kali-linux-communities/%23kali-linux-irc-channel-on-oftc) channel. Lastly, we will introduce [bug reporting](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/helping-yourself-and-getting-help/filing-a-good-bug-report/filing-a-good-bug-report) and show you how to take advantage of bug filing systems to troubleshoot problems and lay out strategies to help you file your own bug report so that undocumented issues can be handled quickly and effectively.

## 7.1. Documentation Sources

Before you can understand what is really going on when there is a problem, you need to know the theoretical role played by each program involved in the problem. One of the best ways to do this is to review the program's documentation. Let's begin by discussing where, exactly, you can find documentation since it is often scattered.

**How to Avoid RTFM Answers**

This acronym stands for "read the f***ing manual," but can also be expanded in a friendlier variant, "read the fine manual." This phrase is sometimes used in (terse) responses to questions from newbies. It is rather abrupt, and betrays a certain annoyance at a question asked by someone who has not even bothered to read the documentation. Some say that this classic response is better than no response at all since this at least hints that the answer lies within the documentation.

When you are posting questions, don't necessarily be offended by the occasional RTFM response, but do what you can to at least show that you have taken the time to do some research before posting the question; mention the sources that you have consulted and describe the various steps that you have personally taken to find information. This will go a long way to show that you are not lazy and are truly seeking knowledge. Following Eric Raymond's guidelines is a good way to avoid the most common mistakes and get useful answers.

> [http://catb.org/~esr/faqs/smart-questions.html](http://catb.org/~esr/faqs/smart-questions.html)

### 7.1.1. Manual Pages

Manual (man) pages, while relatively terse in style, contain a great deal of essential information. To view a manual page, simply type `man manual-page`. The manual page usually coincides with the command name. For example, to learn about the possible options for the `cp` command, you would type `man cp` at the command prompt.

Manual pages not only document programs accessible from the command line, but also configuration files, system calls, C library functions, and so forth. Sometimes names can collide. For example, the shell's `read` command has the same name as the `read` system call. This is why manual pages are organized in the following numbered sections:

1. Commands that can be executed from the command line
2. System calls (functions provided by the kernel)
3. Library functions (provided by system libraries)
4. Devices (on Unix-like systems, these are special files, usually placed in the `/dev/` directory)
5. Configuration files (formats and conventions)
6. Games
7. Sets of macros and standards
8. System administration commands
9. Kernel routines

You can specify the section of the manual page that you are looking for: to view the documentation for the `read` system call, you would type `man 2 read`. When no section is explicitly specified, the first section that has a manual page with the requested name will be shown. Thus, `man shadow` returns shadow(5) because there are no manual pages for _shadow_ in sections 1–4.

Of course, if you do not know the names of the commands, the manual is not going to be of much use to you. Enter the `apropos` command, which searches manual pages (or more specifically their short descriptions) for any keywords that you provide. The `apropos` command then returns a list of manual pages whose summary mentions the requested keywords along with the one-line summary from the manual page. If you choose your keywords well, you will find the name of the command that you need.

**Example 6.1. Finding `cp` with `apropos`**

```
$ apropos "copy file"
cp (1)               - copy files and directories
cpio (1)             - copy files to and from archives
gvfs-copy (1)        - Copy files
gvfs-move (1)        - Copy files
hcopy (1)            - copy files from or to an HFS volume
install (1)          - copy files and set attributes
ntfscp (8)           - copy file to an NTFS volume.
```

**Browsing Documentation by Following Links**

Many manual pages have a "See Also" section, usually near the end of the document, which refers to other manual pages relevant to similar commands, or to external documentation. You can use this section to find relevant documentation even when the first choice is not optimal.

In addition to `man`, you can use `konqueror` (in KDE) and `yelp` (in GNOME) to search manual pages as well.

### 7.1.2. Info Documents

The GNU project has written manuals for most of its programs in the _info_ format; this is why many manual pages refer to the corresponding _info_ documentation. This format offers some advantages but the default program to view these documents (also called `info`) is slightly more complex. You would be well advised to use `pinfo` instead (from the pinfo package). To install it, simply run `apt update` followed by `apt install pinfo` (see [_Installing Packages with APT_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/debian-package-management/basic-package-interaction/installing-packages)).

The _info_ documentation has a hierarchical structure and if you invoke `pinfo` without parameters, it will display a list of the nodes available at the first level. Usually, nodes bear the name of the corresponding commands.

You can use the arrow keys to navigate between nodes. Alternatively, you could also use a graphical browser (which is a lot more user-friendly) such as `konqueror` or `yelp`.

As far as language translations are concerned, the _info_ system is always in English and is not suitable for translation, unlike the `man` page system. However, when you ask the `pinfo` program to display a non-existing _info_ page, it will fall back on the _man_ page by the same name (if it exists), which might be translated.

### 7.1.3. Package-Specific Documentation

Each package includes its own documentation and even the least documented programs generally have a `README` file containing some interesting and/or important information. This documentation is installed in the `/usr/share/doc/package/` directory (where _ package_ represents the name of the package). If the documentation is particularly large, it may not be included in the program's main package, but might be offloaded to a dedicated package which is usually named `package-doc`. The main package generally recommends the documentation package so that you can easily find it.

The `/usr/share/doc/package/` directory also contains some files provided by Debian, which complete the documentation by specifying the package's particularities or improvements compared to a traditional installation of the software. The `README.Debian` file also indicates all of the adaptations that were made to comply with the [Debian policy](https://www.debian.org/doc/debian-policy/) The `changelog.Debian.gz` file allows the user to follow the modifications made to the package over time; it is very useful to try to understand what has changed between two installed versions that do not have the same behavior. Finally, there is sometimes a `NEWS.Debian.gz` file that documents the major changes in the program that may directly concern the administrator.

### 7.1.4. Websites

In many cases, you can find websites that are used to distribute free software programs and to bring together the community of its developers and users. These sites are loaded with relevant information in various forms such as official documentation, frequently asked questions (FAQ), and mailing list archives. In most cases, the FAQ or mailing list archives address problems that you have encountered. As you search for information online, it is immensely valuable to master search syntax. One quick tip: try restricting a search to a specific domain, like the one dedicated to the program that is giving you trouble. If the search returns too many pages or if the results do not match what you seek, you can add the keyword `kali` or `debian` to limit results and target relevant information.

**From the Error to a Solution**

If the software returns a very specific error message, enter it into a search engine (between double quotes, `"`, in order to search for the complete phrase, rather than the individual keywords). In most cases, the first links returned will contain the answer that you need.

In other cases, you will get very general errors, such as "Permission denied". In this case, it is best to check the permissions of the elements involved (files, user ID, groups, etc.). In short, don't get in the habit of always using a search engine to find a solution to your problem. You will find it is much too easy to forget to use common sense.

If you do not know the address of the software's website, there are various means of locating it. First, look for a `Homepage` field in the package's meta-information (`apt show package`). Alternatively, the package description may contain a link to the program's official website. If no URL is indicated, the package maintainer may have included a URL in the `/usr/share/doc/package/copyright` file. Finally, you may be able to use a Internet search engine (such as Google, Bing, DuckDuckGo, etc.) to find the software's website.

### 7.1.5. Kali Documentation at kali.org/docs/

The Kali project maintains a collection of useful documentation at https://www.kali.org/docs/. While this course covers a large part of what you should know about Kali Linux, the documentation there might still be useful as it contains step-by-step instructions (much like how-tos) on many topics.

> [https://www.kali.org/docs/](https://www.kali.org/docs/)

Let's review the various topics covered there:

- Introduction: documentation describing what Kali Linux is and all of its features.
- Installation: various documents describing Kali Linux installation, including how to install it side-by-side with other operating systems.
- Virtualization: various documents describing how to create Kali Linux virtual machines through various software.
- USB: documentation describing how to create a Kali Linux bootable live USB.
- Kali Linux on ARM: many recipes about running Kali Linux on various ARM-based devices.
- Containers: documentation describing how to use Kali Linux in containers such as Docker or LXC.
- WSL: various documents containing information on potential ways to use Kali Linux through the Windows Subsystem for Linux.
- Cloud: documentation describing how to create cloud instances of Kali Linux.
- Kali NetHunter: documentation on everything involving the mobile port of Kali.
- General Use: various documents on the typical use cases of Kali Linux and answers to various questions that may be asked.
- Tools: documentation on the tools contained within Kali Linux.
- Troubleshooting: various documents that contain information that may be beneficial when troubleshooting issues.
- Development: documentation describing many aspects of the Kali Linux creation process.
- Community: documentation describing how to get involved in the Kali Linux community.
- Policy: explanations about what makes Kali Linux special when compared to other Linux distributions.

## 7.2. Kali Linux Communities

There are many Kali Linux communities around the world using many different tools to communicate (forums, real-time chat and social networks, for example). In this section, we will only present two official Kali Linux communities.

### 7.2.1. Forums on forums.kali.org

The official community forums for the Kali Linux project are located at [forums.kali.org](https://forums.kali.org/). Like every web-based forum, you must create an account to be able to post and the system remembers what posts you have already seen, making it easy to follow conversations on a regular basis.

Before posting, you should read the forum rules:

> [https://www.kali.org/docs/community/kali-linux-community-forums/](https://www.kali.org/docs/community/kali-linux-community-forums/)

We won't copy them here but it is worth noting that you are not allowed to speak about illegal activities such as breaking into other people's networks. You must be respectful of other community members so as to create a welcoming community. Advertising is banned and off-topic discussions are to be avoided. There are enough categories to cover everything that you would like to discuss about Kali Linux.

### 7.2.2. #kali-linux IRC Channel on OFTC

IRC is a real-time chat system. Discussions happen in chat rooms that are called _channels_ and are usually centered around a particular topic or community. The Kali Linux project uses the **#kali-linux** channel on the [OFTC](https://www.oftc.net/) network (you can use **irc.oftc.net** as IRC server, on port 6697 for a TLS-encrypted connection or port 6667 for a clear-text connection).

To join the discussions on IRC, you have to use an IRC client such as **hexchat** (in graphical mode) or **irssi** (in console mode). There is also a web-based client available on [webchat.oftc.net](https://webchat.otfc.net/).

While it is really easy to join the conversation, you should be aware that IRC channels have their own rules and that there are channel operators (their nickname is prefixed with @ when using the [HexChat](https://hexchat.github.io/) IRC client) who can enforce the rules: they can kick you out of the channel (or even ban you if you continue to disobey the rules). The **#kali-linux** channel is no exception. The rules have been documented here:

> [https://www.kali.org/docs/community/kali-linux-irc-channel/](https://www.kali.org/docs/community/kali-linux-irc-channel/)

To summarize the rules: you have to be friendly, tolerant, and reasonable. You should avoid off-topic discussions. In particular, discussions about illegal activities, pirated software, politics, and religions are forbidden. Keep in mind that your IP address will be available to others by default.

If you want to ask for help, follow the recommendations listed in [How to Avoid RTFM Answers](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/helping-yourself-and-getting-help#sidebar.rtfm): do your research first and share the results. When you are asked for supplementary information, please provide it accurately (if you must provide some verbose output, don't paste it in the channel directly, instead use a service like [Pastebin](https://pastebin.com/) and post only the Pastebin URL).

Do not expect an immediate answer. Even though IRC is a real-time communication platform, participants log in from all over the world, so time zones and work schedules vary. It may take a few minutes or hours for someone to respond to your question. However, when others include your nickname in a reply, your nickname will be highlighted and most IRC clients will notify you, so leave your client connected and be patient.

## 7.3. Filing a Good Bug Report

If all of your efforts to resolve a problem fail, it is possible that the problem is due to a bug in the program. In this case, the problem may have resulted in a bug report. You can search for bug reports to find a solution to your problem but let's take a look at the procedure of reporting a bug to Kali, Debian, or directly to the upstream developers so you understand the process should you need to submit your own report.

The goal of a bug report is to provide enough information so that the developers or maintainers of the (supposedly) faulty program can reproduce the problem, debug its behavior, and develop a fix. This means that your bug report must contain appropriate information and must be directed to the correct person or project team. The report must also be well-written and thorough, ensuring a faster response.

The exact procedure for the bug report will vary depending on where you will submit the report (Kali, Debian, or upstream developers) but there are some generic recommendations that apply to all cases. In this chapter we will discuss those recommendations.

### 7.3.1. Generic Recommendations

Let's discuss some general recommendations and guidelines that will help you submit a bug report that is clear, comprehensive, and improves the chances that the bug will be addressed by the developers in a timely fashion.

#### How to Communicate

**Write Your Report in English**

The Free Software community is international and unless you know your interlocutor, you should be using plain English. If you are a native speaker of English, use simple sentences and avoid constructions that might be hard to understand for people with limited English skills. Even though most developers are highly intelligent, not all of them have strong English language skills. It is best never to assume.

**Be Respectful of the Developers' Work**

Remember that most Free Software developers (including those behind Kali Linux) are benevolent and are spending their limited free time to work on the software that you are freely using. Many are doing this out of altruism. Thus, when you file a bug report, be respectful (even if the bug looks like an obvious mistake by the developer) and don't assume that they owe you a fix. Thank them for their contribution instead.

If you know how to modify and recompile the software, offer to assist the developers in testing any patches that they submit to you. This will show them that you are willing to invest your own time as well.

**Be Reactive and Ready to Provide More Information**

In some cases, the developer will come back to you with requests for more information or requests for you to try to re-create the problem perhaps by using different options or using an updated package. You should try to respond to those queries as quickly as possible. The quicker you submit your response, the higher the chance that they will be able to solve it quickly while the initial analysis is still fresh in their mind.

While you should aim to respond quickly, you should also not go too fast: the data submitted must be correct and it must contain everything that the developers requested. They may be annoyed if they have to request something a second time.

#### What to Put in the Bug Report

**Instructions to Reproduce the Problem**

To be able to reproduce the issue, the developers need to know what you are using, where you got it from, and how you installed it.

You should provide precise, step-by-step instructions describing how to reproduce the problem. If you need to use some data to reproduce the problem, attach the corresponding file to the bug report. Try to come up with the minimal set of instructions needed to reproduce the bug.

**Give Some Context and Set Your Expectations**

Explain what you were trying to do and how you expected the program to behave.

In some cases, the bug is only triggered because you were using the program in a way that it was not designed to operate by the developers. By explaining what you were trying to achieve, you will allow the developers to clearly see when this is the case.

In some other cases, the behavior that you describe as a bug might actually be the normal behavior. Be explicit about what you expected the program to do. This will clarify the situation for the developers. They may either improve the behavior or improve the documentation, but at least they know that the behavior of their program is confusing some users!

**Be Specific**

Include the versions numbers of the software that you use, possibly with the version numbers of their dependencies. When you refer to something that you downloaded, include its complete URL.

When you get an error message, quote it exactly as you saw it. If possible, include a copy of your screen output or a screenshot. Include a copy of any relevant log file, ensuring that you remove any sensitive data first.

**Mention Possible Fixes or Workarounds**

Before filing the bug report, you probably tried to resolve the problem. Explain what you tried and what results you received. Be very clear about what is a fact and what was just a hypothesis on your part.

If you did an Internet search and found some explanations about a similar problem, you can mention them, in particular when you found other similar bug reports in bug trackers.

If you found a way of achieving the desired result without triggering the bug, please document that as well. This will help other users who are hit by the same issue.

**Long Bug Reports Are Fine**

A two-line bug report is insufficient; providing all the information needed usually requires several paragraphs (or sometimes pages) of text.

Supply all the information you can. Try to stick to what is relevant, but if you are uncertain, too much is better than too little.

If your bug report is really long, take some time to structure the content and provide a short summary at the start.

#### Miscellaneous Tips

**Avoid Filing Duplicate Bug Reports**

In the Free Software world, all bug trackers are public. Open issues can be browsed and they even have a search feature. Thus, before filing a new bug report, try to determine if your problem has already been reported by someone else.

If you find an existing bug report, subscribe to it and possibly add supplementary information. Do not post comments to bump, such as "Me too" or "+1"; they serve no purpose. But you can indicate that you are available for further tests if the original submitter did not offer this.

If you have not found any report of your problem, go ahead and file it. If you have found related tickets, be sure to mention them.

**Ensure You Use the Latest Version**

It is very frustrating for developers to receive bug reports for problems that they have already solved or problems that they can't reproduce with the version that they are using (developers almost always use the latest version of their product). Even when older versions are maintained by the developers, the support is often limited to security fixes and major problems. Are you sure that your bug is one of those?

That is why, before filing a bug report, you should make sure that you are using the latest version of the problematic system and application and that you can reproduce the problem in that situation.

If Kali Linux does not offer the latest version of the application, you have alternative solutions: you can try a manual installation of the latest version in a throw-away virtual machine, or you can review the upstream Changelog (or any history logs in their chosen version control system) to see that there hasn't been any change that could fix the problem that you are seeing (and then file the bug even though you did not try the latest version).

**Do Not Mix Multiple Issues in a Single Bug Report**

File one bug report per issue. That way, the subsequent discussions do not get too messy and each bug can be fixed according to its own schedule. If you don't do that, either the single bug needs to be repurposed multiple times and can only be closed when all issues have been fixed, or the developers must file the supplementary reports that you should have created in the first place.

### 7.3.2. Where to File a Bug Report

To be able to decide where to file the bug report, you must have a good understanding of the problem and you must have identified in which piece of software the problem lies.

Ideally, you track the problem down to a file on your system and then you can use `dpkg` to find out which package owns that file and where that package comes from. Let's assume that you found a bug in a graphical application. After looking at the list of running processes (the output of `ps auxf`), you discovered that the application was started with the `/usr/bin/cherrytree` executable:

```
$ dpkg -S /usr/bin/cherrytree
cherrytree: /usr/bin/cherrytree
$ dpkg -s cherrytree | grep ^Version:
Version: 0.38.8-0kali1
```

You learn that `/usr/bin/cherrytree` is provided by the `cherrytree` package, which is in version `0.38.8-0kali1`. The fact that the version string contains `kali` indicates to you that the package comes from Kali Linux (or is modified by Kali Linux). Any package that does not have `kali` in its version string (or in its package name) comes straight from Debian (Debian Testing in general).

**Double Check Before Filing Bugs against Debian**

If you find a bug in a package imported straight from Debian, it should ideally be reported and fixed on the Debian side. However, before doing this, ensure that the problem is reproducible on a plain Debian system since Kali may have caused the problem by modifying other packages or dependencies.

The easiest way to accomplish this is to setup a virtual machine running Debian Testing. You can find an installation ISO for Debian Testing on the Debian Installer website:

[https://www.debian.org/devel/debian-installer/](https://www.debian.org/devel/debian-installer/)

If you can confirm the problem in the virtual machine, then you can submit the bug to Debian by running `reportbug` within the virtual machine and following the instructions provided.

Most bug reports about the behavior of applications should be directed to their upstream projects except when facing an integration problem: in that case, the bug is a mistake in the way the software gets packaged and integrated into Debian or Kali. For example, if an application offers compile-time options that the package does not enable or the application does not work because of a missing library (thus putting into light a missing dependency in the package meta-information), you may be facing an integration problem. When you don't know what kind of problem you face, it is usually best to file the issue on both sides and to cross-reference them.

Identifying the upstream project and finding where to file the bug report is usually easy. You just have to browse the upstream website, which is referenced in the `Homepage` field of the packaging meta-data:

```
$ dpkg -s wpscan | grep ^Homepage:
Homepage: https://wpscan.com/wordpress-security-scanner
```

### 7.3.3. How to File a Bug Report

#### Filing a Bug Report in Kali

Kali uses a web-based bug tracker at [https://bugs.kali.org/](https://bugs.kali.org/) where you can consult all the bug reports anonymously, but if you would like to comment or file a new bug report, you will need to register an account.

##### Signing Up for a Bug Tracker Account

To begin, simply click _Signup for new account_ on the bug tracker website, as shown in Figure 1.

![Figure 1: Kali Bug Tracker Start Page](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/d2d1d04250f2f95c219bf34e6fde70e1-07_kali-bugtracker-signup-1.png)

Figure 1: Kali Bug Tracker Start Page

Next, provide a username, e-mail address, and response to the CAPTCHA challenge. Then click the **Signup** button to proceed Figure 2).

![Figure 2: Signup Page](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/523d834e79189a41231f388dbdd41632-07_kali-bugtracker-signup-2.png)

Figure 2: Signup Page

If successful, the next page Figure 3) will notify you that the account registration has been processed, and the bug tracker system will send a confirmation email to the address you provided. You will need to click the link in the email in order to activate your account.

Once your account has been activated, click **Proceed** to continue to the bug tracker login page.

![Figure 3: Signup Confirmation Page](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/c991b779aa7fc741a636400bfff40ea8-07_kali-bugtracker-signup-3.png)

Figure 3: Signup Confirmation Page

##### Creating the Report

To begin your report, log into your account and click the **Report Issue** link on the landing page. You will be presented a form with many fields to fill, as shown in Figure 4.

![Figure 4: Form to report a bug](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/914a50ca08fe9986734d5c0a9a41ccb9-07_kali-bugtracker-report-issue.png)

Figure 4: Form to report a bug

Here is a rundown of all the fields on the form:

**Category (mandatory)**

This field describes the category of the bug you are submitting. Reports that can be attributed to a specific package should be filed in the Kali Package Bug or Kali Package Improvement categories. Other reports should use the General Bug or Feature Requests categories. The remaining categories are for specific use cases: Tool Upgrade can be used to notify the Kali developers of the availability of a new version of a software packaged in Kali. New Tool Requests can be used to suggest new tools to package and integrate in the Kali distribution. Kali Websites & Docs can be used to report bugs or updates relating to the various Kali websites. Queued Tool Addition is reserved for the Kali tool team, for when a tool submission has been agreed-upon to be added into Kali.

**Reproducibility**

This field documents whether the problem is reproducible in a predictable way or if it happens only somewhat randomly.

**Severity and Priority**

Those fields are best left unmodified as they are mainly for the developers. They can use them to sort the list of issues according to the severity of the problem and to the priority at which it must be handled.

**Product Version**

This field should indicate what version of Kali Linux you are running (or the one which is the closest to what you are running). Think twice before reporting an issue on an old release that is no longer supported.

**Assign To and Target Version**

Those fields are also best left unmodified as they are again, mainly for the developers. They can use them to indicate which developer is handling the issue and when the issue should be resolved.

**Summary (mandatory)**

This is essentially the title of your bug report and it is the first thing that people will see. Make sure that it conveys the reason why you are filing the report. Avoid generic descriptions like "X doesn't work" and opt instead for "X fails with error Y under condition Z."

**Description (mandatory)**

This is the body of your report. Here you should enter all of the information you collected about the problem that you are experiencing. Don't forget all the recommendations given in the former section.

**Steps to Reproduce**

In this field, list all the detailed instructions explaining how to trigger the problem.

**Additional Information**

In this section, you can provide any additional information you believe is relevant to the issue. If you have a fix or workaround for the issue, please provide it in this section.

**Attach Tags**

This is a section better left unmodified. Tags are used by the developers to allow easier access to similar bug reports.

**Upload File**

Not everything can be explained with plain text. This field lets you attach arbitrary files to your reports: screenshots to show the error, sample documents triggering the problem, log files, etc.

**View Status**

Leave that field set to "public" so that everybody can see your bug report. Use "private" only for security-related reports containing information about undisclosed security vulnerabilities.

#### Filing a Bug Report in Debian

Debian uses a (mostly) email-based bug tracking system known as Debbugs. To open a new bug report, you will send an email (with a special syntax) to `submit@bugs.debian.org`. This will allocate a bug number XXXXXX and inform you that you can send additional information by mailing `XXXXXX@bugs.debian.org`. Each bug is associated to a Debian package. You can browse all the bugs of a given package (including the bug that you are thinking of reporting) at **https://bugs.debian.org/_package_**. You can check the history of a given bug at **https://bugs.debian.org/_XXXXXX_**.

##### Setting Up Reportbug

While you can open a new bug with a simple e-mail, we recommend using `reportbug` because it will help you draft a solid bug report with all the required information. Ideally, you should run it from a Debian system (for example, in the virtual machine where you reproduced the problem).

The first run of `reportbug` starts a configuration script. First, select a skill level. You should choose Novice or Standard; we use the latter because it offers more fine-grained control. Next, select an interface and enter your personal details. Finally, select a user interface. The configuration script will allow you to use a local mail transport agent, an SMTP server, or as a last resort, a Debian SMTP server.

```
Welcome to reportbug! Since it looks like this is the first time you have
used reportbug, we are configuring its behavior. These settings will be
saved to the file "/home/kali/.reportbugrc", which you will be free to edit
further.
Please choose the default operating mode for reportbug.

1 novice    Offer simple prompts, bypassing technical questions.

2 standard  Offer more extensive prompts, including asking about things
            that a moderately sophisticated user would be expected to
            know about Debian.

3 advanced  Like standard, but assumes you know a bit more about Debian,
            including "incoming".

4 expert    Bypass most handholding measures and preliminary triage
            routines. This mode should not be used by people unfamiliar
            with Debian's policies and operating procedures.

Select mode: [novice] standard
Please choose the default interface for reportbug.

1 text   A text-oriented console user interface

2 gtk2   A graphical (GTK+) user interface.

3 urwid  A menu-based console user interface

Select interface: text
Will reportbug often have direct Internet access? (You should answer
yes to this question unless you know what you are doing and plan to
check whether duplicate reports have been filed via some other channel.)
[Y|n|q|?]? Y
What real name should be used for sending bug reports?
[kali]> Raphaël Hertzog
Which of your email addresses should be used when sending bug reports?
(Note that this address will be visible in the bug tracking system, so you
may want to use a webmail address or another address with good spam
filtering capabilities.)
[kali@localhost.localdomain]> buxy@kali.org
Do you have a "mail transport agent" (MTA) like Exim, Postfix or SSMTP
configured on this computer to send mail to the Internet? [y|N|q|?]? N
Please enter the name of your SMTP host. Usually it's called something
like "mail.example.org" or "smtp.example.org". If you need to use a
different port than default, use the : alternative
format. Just press ENTER if you don't have one or don't know, and so a
Debian SMTP host will be used.
>
Please enter the name of your proxy server. It should only use this
parameter if you are behind a firewall. The PROXY argument should be
formatted as a valid HTTP URL, including (if necessary) a port number; for
example, http://192.168.1.1:3128/. Just press ENTER if you don't have one
or don't know.
>
Default preferences file written. To reconfigure, re-run reportbug with
the "--configure" option.
```

##### Using Reportbug

With the setup phase completed, the actual bug report can begin. You will be prompted for a package name, although you can also provide the package name directly on the command line with `reportbug package`).

```
Please enter the name of the package in which you have found a problem, or
type 'other' to report a more general problem. If you don't know what
package the bug is in, please contact debian-user@lists.debian.org for
assistance.
> wireshark
```

Contrary to the advice given above, if you don't know against which package to file the bug, you should get in touch with a Kali support forum (described in [_Kali Linux Communities_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/helping-yourself-and-getting-help/kali-linux-communities/kali-linux-communities)). In the next step, **reportbug** downloads the list of bugs filed against the given package and lets you browse them to see if you can find yours.

```
*** Welcome to reportbug.  Use ? for help at prompts. ***
Note: bug reports are publicly archived (including the email address of the submitter).
Detected character set: UTF-8
Please change your locale if this is incorrect.

Using '"Raphaël Hertzog" ' as your from address.
Getting status for wireshark...
Verifying package integrity...
Checking for newer versions at madison...
Will send report to Debian (per lsb_release).
Querying Debian BTS for reports on wireshark (source)...
35 bug reports found:

Bugs with severity important
   1) #478200  tshark: seems to ignore read filters when writing to...
   2) #776206  mergecap: Fails to create output file > 2GB
   3) #780089  wireshark: "On gnome wireshark has not title bar. Does...
Bugs with severity normal
   4) #151017  ethereal: "Protocol Hierarchy Statistics" give misleading...
   5) #275839  doesn't correctly dissect ESMTP pipelining
[...]
  35) #815122  wireshark: add OID 1.3.6.1.4.1.11129.2.4.2
(24-35/35) Is the bug you found listed above [y|N|b|m|r|q|s|f|e|?]? ?
y - Problem already reported; optionally add extra information.
N - (default) Problem not listed above; possibly check more.
b - Open the complete bugs list in a web browser.
m - Get more information about a bug (you can also enter a number
    without selecting "m" first).
r - Redisplay the last bugs shown.
q - I'm bored; quit please.
s - Skip remaining problems; file a new report immediately.
f - Filter bug list using a pattern.
e - Open the report using an e-mail client.
? - Display this help.
(24-35/35) Is the bug you found listed above [y|N|b|m|r|q|s|f|e|?]? n
Maintainer for wireshark is 'Balint Reczey '.
Looking up dependencies of wireshark...
```

If you find your bug already filed, you can choose to send supplementary information, otherwise, you are invited to file a new bug report:

```
Briefly describe the problem (max. 100 characters allowed). This will be the bug email subject, so keep the summary as concise as possible, for example: "fails to send email"
or "does not start with -q option specified" (enter Ctrl+c to exit reportbug without reporting a bug).
> does not dissect protocol foobar
Rewriting subject to 'wireshark: does not dissect protocol foobar'
```

After providing a one-line summary of your problem, you must rate its severity along an extended scale:

```
How would you rate the severity of this problem or report?

1 critical        makes unrelated software on the system (or the whole system) break, or causes serious data loss, or introduces a security hole on systems where you install
                  the package.
2 grave           makes the package in question unusable by most or all users, or causes data loss, or introduces a security hole allowing access to the accounts of users who
                  use the package.
3 serious         is a severe violation of Debian policy (that is, the problem is a violation of a 'must' or 'required' directive); may or may not affect the usability of the
                  package. Note that non-severe policy violations may be 'normal,' 'minor,' or 'wishlist' bugs. (Package maintainers may also designate other bugs as
                  'serious' and thus release-critical; however, end users should not do so.). For the canonical list of issues deserving a serious severity you can refer to
                  this webpage: http://release.debian.org/testing/rc_policy.txt .
4 important       a bug which has a major effect on the usability of a package, without rendering it completely unusable to everyone.
5 does-not-build  a bug that stops the package from being built from source. (This is a 'virtual severity'.)
6 normal          a bug that does not undermine the usability of the whole package; for example, a problem with a particular option or menu item.
7 minor           things like spelling mistakes and other minor cosmetic errors that do not affect the core functionality of the package.
8 wishlist        suggestions and requests for new features.

Please select a severity level: [normal]
```

If you are unsure, just keep the default severity of **normal**.

You can also tag your report with a few keywords:

```
Do any of the following apply to this report?

 1 a11y      This bug is relevant to the accessibility of the package.
 2 d-i       This bug is relevant to the development of debian-installer.
 3 ftbfs     The package fails to build from source.
 4 ipv6      This bug affects support for Internet Protocol version 6.
 5 l10n      This bug reports a localization/internationalization issue.
 6 lfs       This bug affects support for large files (over 2 gigabytes).
 7 newcomer  This bug has a known solution but the maintainer requests someone else implement it.
 8 patch     You are including a patch to fix this problem.
 9 upstream  This bug applies to the upstream part of the package.
10 none

Please select tags: (one at a time) [none]
```

Most tags are rather esoteric, but if your report includes a fix, you should select the **patch** tag.

Once this is completed, **reportbug** opens a text editor with a template that you should edit ([_Template generated by **reportbug**_](https://portal.offsec.com/courses/pen-103-16306/learning/helping-yourself-and-getting-help-16823/summary-16865/summary-17081#example.reportbug-template)). It contains a few questions that you should delete and answer, as well as some information about your system that has been automatically collected. Notice how the first few lines are structured. They should not be modified as they will be parsed by the bug tracker to assign the report to the correct package.

**Example 6.2. Template generated by `reportbug`**

```
Subject: wireshark: does not dissect protocol foobar

Package: wireshark
Version: 3.2.5-1
Severity: normal

Dear Maintainer,

*** Reporter, please consider answering these questions, where appropriate ***

   * What led up to the situation?
   * What exactly did you do (or not do) that was effective (or
     ineffective)?
   * What was the outcome of this action?
   * What outcome did you expect instead?

*** End of the template - remove these template lines ***

-- System Information:
Distributor ID: Kali
Description:    Kali GNU/Linux Rolling
Release:        2020.3
Codename:       kali-rolling
Architecture: x86_64

Kernel: Linux 5.7.0-kali1-amd64 (SMP w/4 CPU threads)
Kernel taint flags: TAINT_UNSIGNED_MODULE
Locale: LANG=en_US.utf8, LC_CTYPE=en_US.utf8 (charmap=UTF-8), LANGUAGE not set
Shell: /bin/sh linked to /usr/bin/dash
Init: systemd (via /run/systemd/system)
LSM: AppArmor: enabled

Versions of packages wireshark depends on:
ii  wireshark-qt  3.2.5-1

wireshark recommends no packages.

wireshark suggests no packages.

-- no debconf information
```

Once you save the report and close the text editor, you return to **reportbug**, which provides many other options and offers to send the resulting report.

```
Spawning sensible-editor...
Report will be sent to "Debian Bug Tracking System"
Submit this report on wireshark (e to edit) [Y|n|a|c|e|i|l|m|p|q|d|t|s|?]? ?
Y - (default) Submit the bug report via email.
n - Don't submit the bug report; instead, save it in a temporary file (exits reportbug).
a - Attach a file.
c - Change editor and re-edit.
e - Re-edit the bug report.
i - Include a text file.
l - Pipe the message through the pager.
m - Choose a mailer to edit the report.
p - print message to stdout.
q - Save it in a temporary file and quit.
d - Detach an attachment file.
t - Add tags.
s - Add a X-Debbugs-CC recipient (a CC but after BTS processing).
? - Display this help.
Submit this report on wireshark (e to edit) [Y|n|a|c|e|i|l|m|p|q|d|t|s|?]? Y
Saving a backup of the report at /tmp/reportbug-wireshark-backup-20210328-19073-87oJWJ
Connecting to reportbug.debian.org via SMTP...

Bug report submitted to: "Debian Bug Tracking System"
Copies will be sent after processing to:
  buxy@kali.org

If you want to provide additional information, please wait to receive the
bug tracking number via email; you may then send any extra information to
n@bugs.debian.org (e.g. 999999@bugs.debian.org), where n is the bug
number. Normally you will receive an acknowledgement via email including
the bug report number within an hour; if you haven't received a
confirmation, then the bug reporting process failed at some point
(reportbug or MTA failure, BTS maintenance, etc.).
```

#### Filing a Bug Report in another Free Software Project

There is a large diversity of free software projects, using different workflows and tools. This diversity also applies to the bug trackers in use. While many projects are hosted on GitHub and use GitHub issues to track their bugs, there are also many others hosting their own trackers, based on Bugzilla, Trac, Redmine, Flyspray, and others. Most of them are web-based and require you to register an account to submit a new ticket.

We will not cover all the trackers here. It is up to you to learn the specifics of various trackers for other free software projects, but since [GitHub](https://github.com/) is relatively popular, we will take a brief look at it here. As with other trackers, you must first create an account and sign in. Next, click the Issues tab, as shown in Figure 5.

![Figure 5: Main page of a GitHub project](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/b6b785aaafcd1f2548d397af7562e1fd-07_github-issue-1.png)

Figure 5: Main page of a GitHub project

You can then browse (and search) the list of open issues. Once you are confident that your bug is not yet filed, you can click on the **New issue** button Figure 6).

![Figure 6: Issues page of a GitHub project](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/8b86128867c5882e48ddc820ac5f4063-07_github-issue-2.png)

Figure 6: Issues page of a GitHub project

You are now on a page where you must describe your problem Figure 7). GitHub has a template feature allowing the owner of the repository to define their own custom issue template, however it appears that this repository does not have one setup. However, the bug reporting mechanism is fairly straight-forward, allowing you to attach files, apply formatting to text, and much more. Of course, for best results, be sure to follow our guidelines for creating a detailed and well-described report.

![Figure 7: GitHub form to file a new issue](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/e61a6a83ffa264960fc09aa2191fa5e0-07_github-issue-3.png)

Figure 7: GitHub form to file a new issue

## 7.4. Summary

In this section, we discussed various methods to help you find documentation and information about programs and how to find help with problems you may encounter. We took a look at manual and info pages and the `apropos` and `info` commands. We discussed bug trackers, provided some tips on how to search for and submit good bug reports, and provided some tips to help you figure out who owns the program or project in question.

Summary Tips:

- Before you can understand what is really going on when there is a problem, you need to know the theoretical role played by each program involved in the problem. One of the best ways to do this is to review the program's documentation.
- To view a manual page, simply type `man manual-page`, filling in the name of the command after an optional section number.
- The `apropos` command returns a list of manual pages whose summary mentions the requested keywords, along with the one-line summary from the manual page.
- The GNU project has written manuals for most of its programs in the _info_ format. This is why many manual pages refer to corresponding _info_ documentation.
- Each package includes its own documentation and even the least documented programs generally have a `README` file containing some interesting and/or important information. This documentation is installed in the `/usr/share/doc/package/` directory.
- In most cases, the FAQ or mailing list archives of a program's official website may address problems that you have encountered.
- The Kali project maintains a collection of useful documentation at [https://www.kali.org/docs/](https://www.kali.org/docs/).
- The Kali Linux project uses the `#kali-linux` channel on the [OFTC](https://www.otfc.net/) IRC network. You can use `irc.otfc.net` as IRC server, on port 6697 for a TLS-encrypted connection or port 6667 for a clear-text connection. To join the discussions on IRC, you have to use an IRC client such as `hexchat` (in graphical mode) or `irssi` (in console mode). There is also a web-based client available on [webchat.otfc.net](https://webchat.otfc.net/).- The official community forums for the Kali Linux project are located at [forums.kali.org](https://forums.kali.org/).
- If you uncover a bug in a program, you can search bug reports or file your own. Be sure to follow the guidelines that we have outlined to ensure your report is clear, comprehensive, and improves the chances that the bug will be addressed by the developers in a timely fashion.
- Some bug reports should be filed to Kali, while others may be filed on the Debian side. A command like `dpkg -s package-name | grep ^Version:` will reveal the version number and will be tagged as "kali" if it is a Kali-modified package.
- Identifying an upstream project and finding where to file the bug report is usually easy. Simply browse the upstream website that is referenced in the `Homepage` field of the packaging meta-data.
- Kali uses a web-based bug tracker at [https://bugs.kali.org/](https://bugs.kali.org/) where you can consult all the bug reports anonymously, but if you would like to comment or file a new bug report, you will need to register an account.
- Debian uses a (mostly) email-based bug tracking system known as Debbugs. To open a new bug report, you can send an email (with a special syntax) to `submit@bugs.debian.org` or you can use the `reportbug` command, which will guide you through the process.
- While many projects are hosted on GitHub and use GitHub issues to track their bugs, there are also many others hosting their own trackers. You may have to research the basics of third-party bug trackers if you need to post to them.

Now that you have the basic tools for navigating Linux, installing and configuring Kali, and troubleshooting your system and getting help, it is time to look at locking down Kali so that you can protect your installation as well as your client's data.

### 7.5.1. Kali resources

#### Questions

1. You want to know if the newer **$xyz** version of nmap is in Kali. What is the quickest Kali resource to check this?
2. What are the two primary official, interactive Kali support community resources?
3. How do you search manual pages for a particular string?

---

#### Answers:

1. That would be **pkg.kali.org**. For example, [https://pkg.kali.org/nmap](https://pkg.kali.org/nmap).
2. The [Kali-Linux IRC channel](https://www.kali.org/docs/community/kali-linux-irc-channel/) and [the Kali Forums](https://forums.kali.org/).
3. Use the `apropos` command.

Next Module -> [Securing and Monitoring Kali Linux 🔒](securing_and_monitoring.md)