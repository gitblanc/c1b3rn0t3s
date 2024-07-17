---
title: Debian Package Management 🎙️
tags:
  - Offsec
  - PEN-103
---
- *All the info was extracted from [Offsec, Pen-103](https://portal.offsec.com/courses/pen-103-16306/)*, under the following [licencese](https://creativecommons.org/licenses/by-sa/3.0/)

# 9. Debian Package Management

After the basics of Linux, it is time to learn the package management system of a Debian-based distribution. In such distributions, including Kali, the Debian package is the canonical way to make software available to end-users. Understanding the package management system will give you a great deal of insight into how Kali is structured, enable you to more effectively troubleshoot issues, and help you quickly locate help and documentation for the wide array of tools and utilities included in Kali Linux.

In this chapter, we will introduce the Debian package management system and introduce `dpkg` and the APT suite of tools. One of the primary strengths of Kali Linux lies in the flexibility of its package management system, which leverages these tools to provide near-seamless installation, upgrades, removal, and manipulation of application software, and even of the base operating system itself. It is critical that you understand how this system works to get the most out of Kali and streamline your efforts. The days of painful compilations, disastrous upgrades, debugging `gcc`, `make`, and `configure` problems are long gone, however, the number of available applications has exploded and you need to understand the tools designed to take advantage of them. This is also a critical skill because there are a number of security tools that, due to licensing or other issues, cannot be included in Kali but have Debian packages available for download. It is important that you know how to process and install these packages and how they impact the system, especially when things do not go as expected.

We will begin with some basic overviews of APT, describe the structure and contents of binary and source packages, take a look at some basic tools and scenarios, and then dig deeper to help you wring every ounce of utility from this spectacular package system and suite of tools.

## 9.1. Introduction to APT

Let's begin with some basic definitions, an overview, and some history about Debian packages, starting with `dpkg` and APT.

### 9.1.1. Relationship between APT and dpkg

A Debian package is a compressed archive of a software application. A _binary package_ (a `.deb` file) contains files that can be directly used (such as programs or documentation), while a _source package_ contains the source code for the software and the instructions required for building a binary package. A Debian package contains the application's files as well as other _metadata_ including the names of the dependencies the application needs, as well as scripts that enable the execution of commands at different stages in the package's lifecycle (installation, upgrades, and removal).

The `dpkg` tool was designed to process and install `.deb` packages, but if it encountered an unsatisfied dependency (like a missing library) that would prevent the package from installing, `dpkg` would simply list the missing dependency, because it had no awareness or built-in logic to find or process the packages that might satisfy those dependencies. The Advanced Package Tool (APT), including `apt` and `apt-get`, were designed to address these shortcomings and could automatically resolve these issues. We will talk about both `dpkg` and the APT tools in this chapter.

The base command for handling Debian packages on the system is `dpkg`, which performs installation or analysis of `.deb` packages and their contents. However, `dpkg` has only a partial view of the Debian universe: it knows what is installed on the system and whatever you provide on the command line, but knows nothing of the other available packages. As such, it will fail if a dependency is not met. APT addresses the limitations.

APT is a set of tools that help manage Debian packages, or applications on your Debian system. You can use APT to install and remove applications, update packages, and even upgrade your entire system. The magic of APT lies in the fact that it is a complete package management system that will not only install or remove a package, but will consider the requirements and dependencies of the packaged application (and even their requirements and dependencies) and attempt to satisfy them automatically. APT relies on `dpkg` but APT differs from `dpkg`, as the former installs the latest package from an online source and works to resolve dependencies while `dpkg` installs a package located on your local system and does not automatically resolve dependencies.

If you have been around long enough to remember compiling programs with `gcc` (even with the help of utilities such as `make` and `configure`), you likely remember that it was a painful process, especially if the application had several dependencies. By deciphering the various warnings and error messages, you may have been able to determine which part of the code was failing and most often that failure was due to a missing library or other dependency. You would then track down that missing library or dependency, correct it, and try again. Then, if you were lucky, the compile would complete, but often the build would fail again, complaining about another broken dependency.

APT was designed to help alleviate that problem, collate program requirements and dependencies, and resolve them. This functionality works out-of-the-box on Kali Linux, but it isn't foolproof. It is important that you understand how Debian and Kali's packaging system works because you will need to install packages, update software, or troubleshoot problems with packages. You will use APT in your day-to-day work with Kali Linux and in this chapter, we will introduce you to APT and show you how to install, remove, upgrade, and manage packages, and even show you how to move packages between different Linux distributions. We will also talk about graphical tools that leverage APT, show you how to validate the authenticity of packages, and delve into the concept of a rolling distribution, a technique that brings daily updates to your Kali system.

Before we dig in and show you how to use `dpkg` and APT to install and manage packages, it is important that we delve into some of the inner workings of APT and discuss some terminology surrounding it.

**Package Source and Source Package**

The word _source_ can be ambiguous. A source package—a package containing the source code of a program—should not be confused with a package source—a repository (website, FTP server, CD/DVD-ROM, local directory, etc.) that contains packages.

APT retrieves its packages from a repository, a package storage system or simply, "package source". The `/etc/apt/sources.list` file lists the different repositories (or sources) that publish Debian packages.

### 9.1.2. Understanding the sources.list File

The `sources.list` file is the key configuration file for defining package sources, and it is important to understand how it is laid out and how to configure it since APT will not function without a properly defined list of package sources. Let's discuss its syntax, take a look at the various repositories that are used by Kali Linux, and discuss mirrors and mirror redirection, then you will be ready to put APT to use.

Each active line of the `/etc/apt/sources.list` file (and of the `/etc/apt/sources.list.d/*.list` files) contains the description of a source, made of three parts separated by spaces. Commented lines begin with a `#` character:

```
#deb cdrom:[Debian GNU/Linux 2020.3 _Kali-rolling_ - Official Snapshot amd64 LIVE/INSTALL Binary 20200728-20:25]/ kali-last-snapshot contrib main non-free

deb http://http.kali.org/kali kali-rolling main non-free contrib
```

Let's take a look at the syntax of this file. The first field indicates the source type:

- `deb` for binary packages.
- `deb-src` for source packages.

The second field gives the base URL of the source: this can consist of a Kali mirror or any other package archive set up by a third party. The URL can start with `file://` to indicate a local source installed in the system's file hierarchy, with `http://` to indicate a source accessible from a web server, or with `ftp://` for a source available on an FTP server. The URL can also start with `cdrom:` for CD/DVD-ROM/Blu-ray disc-based installations, although this is less frequent since network-based installation methods are more and more common.

The `cdrom` entries describe the CD/DVD-ROM you have. Contrary to other entries, a CD/DVD-ROM is not always available, since it has to be inserted into the drive and usually only one disc can be read at a time. For those reasons, these sources are managed in a slightly different way and need to be added with the `apt-cdrom` program, usually executed with the `add` parameter. The latter will then request the disc to be inserted in the drive and will browse its contents looking for `Packages` files. It will use these files to update its database of available packages (this operation is usually done by the `apt update` command). After that, APT will request the disc if it needs a package stored on it.

The syntax of the last field depends on the structure of the repository. In the simplest cases, you can easily indicate a subdirectory (with a required trailing slash) of the desired source (this is often a simple "`./`", which refers to the absence of a subdirectory—the packages are then directly at the specified URL). But in the most common case, the repositories will be structured like a Kali mirror, with multiple distributions each having multiple components. In those cases, name the chosen distribution, then the components (or sections) to enable. Let's take a moment to introduce these sections.

Debian and Kali use three sections to differentiate packages according to the licenses chosen by the authors of each work. A difference between Debian and Kali is that, Debian only has main enabled by default, whereas Kali has all three enabled by default.

`main` contains all packages that fully comply with the [Debian Free Software Guidelines](https://www.debian.org/social_contract#guidelines).

The `non-free` archive is different because it contains software that does not (entirely) conform to these principles but which can nevertheless be distributed without restrictions.

`contrib` (contributions) is a set of open source software that cannot function without some non-free elements. These elements may include software from the `non-free` section or non-free files such as game ROMs, BIOS of consoles, etc. `contrib` also includes free software whose compilation requires proprietary elements, such as VirtualBox, which requires a non-free compiler to build some of its files.

Now, let's take a look at the standard Kali Linux package sources, or repositories.

### 9.1.3. Kali Repositories

A standard `sources.list` file for a system running Kali Linux refers to one repository (`kali-rolling`) and the three previously mentioned components: `main`, `contrib`, and `non-free`:

```
# Main Kali repository
deb http://http.kali.org/kali kali-rolling main contrib non-free
```

Let's take a look at the Kali repositories.

#### The Kali-Rolling Repository

This is the main repository for end-users. It should always contain installable and recent packages. It is managed by a tool that merges Debian Testing and the Kali-specific packages in a way that ensures that each package's dependencies can be satisfied within kali-rolling. In other words, barring any bug in maintainer scripts, all packages should be installable.

Since Debian Testing evolves daily, so does Kali Rolling. The Kali-specific packages are also regularly updated as we monitor the upstream releases of the most important packages.

#### The Kali-Dev Repository

This repository is not for public use. It is a space where Kali developers resolve dependency problems arising from the merge of the Kali-specific packages into Debian Testing.

It is also the place where updated packages land first, so if you need an update that was released recently and that has not yet reached kali-rolling, you might be able to grab it from this repository. This is not recommended for regular users.

#### The Kali Linux Mirrors

The `sources.list` extracts above refer to `http.kali.org`: this is a server running [Mirrorbits](https://github.com/etix/mirrorbits), which will redirect your HTTP requests to an official mirror close to you. Mirrorbits monitors each mirror to ensure that they are working and up-to-date; it will always redirect you to a good mirror.

**Debugging a Mirror Redirection**

If you have a problem with the mirror (for instance because `apt update` fails), you can use `curl -sI` to see where you are being redirected:

```
$ curl -sI http://http.kali.org/README
HTTP/1.1 302 Found
Server: nginx
Date: Fri, 26 Jan 2024 06:05:36 GMT
Content-Type: text/html; charset=utf-8
Connection: keep-alive
Cache-Control: private, no-cache
Link: <http://kali.download/kali/README>; rel=duplicate; pri=1; geo=ae
Link: <http://archive-4.kali.org/kali/README>; rel=duplicate; pri=2; geo=fr
Location: http://mirror.accuris.ca/kali/README
```

If the problem persists, you can edit `/etc/apt/sources.list` and hardcode the name of another known working mirror in place of (or before) the `http.kali.org` entry.

We also have a second Mirrorbits instance: where `http.kali.org` hosts the package repositories, `cdimage.kali.org` hosts the released ISO images.

> [http://cdimage.kali.org/](http://cdimage.kali.org/)

If you want to request a list of official Kali Linux Mirrors, you can add `?mirrorlist` to any valid URL pointing to `http.kali.org` or `cdimage.kali.org`.

> [http://http.kali.org/README?mirrorlist](http://http.kali.org/README?mirrorlist)
> 
> [http://cdimage.kali.org/README?mirrorlist](http://cdimage.kali.org/README?mirrorlist)

These lists are not exhaustive due to some Mirrorbits limitations (most notably mirrors restricted to some countries do not appear in the list unless you are in the given country). But they contain the best mirrors: they are well maintained and have large amounts of bandwidth available.

## 9.2. Basic Package Interaction

Armed with a basic understanding of the APT landscape, let's take a look at some basic package interactions including the initialization of APT; installation, removal, and purging of packages; and upgrading of the Kali Linux system. Then let's venture from the command line to take a look at some graphical APT tools.

### 9.2.1. Initializing APT

APT is a vast project and tool set, whose original plans included a graphical interface. From a client perspective, it is centered around the command-line tool `apt-get` as well as `apt`, which was later developed to overcome design flaws of `apt-get`.

There are graphical alternatives developed by third parties, including `synaptic` and `aptitude`, which we will discuss later. We tend to prefer `apt`, which we use in the examples that follow. We will, however, detail some of the major syntax differences between tools, as they arise.

When working with APT, you should first download the list of currently available packages with `apt update`. Depending on the speed of your connection, this can take some time because various packages' list, sources' list and translation files have grown in size alongside Kali development. Of course, CD/DVD-ROM installation sets install much more quickly, because they are local to your machine.

### 9.2.2. Installing Packages

Thanks to the thoughtful design of the Debian package system, you can install packages, with or without their dependencies, fairly easily. Let's take a look at package installation with `dpkg` and `apt`.

#### Installing Packages with dpkg

`dpkg` is the core tool that you will use (either directly or indirectly through APT) when you need to install a package. It is also a go-to choice if you are operating offline, since it doesn't require an Internet connection. Remember, `dpkg` will not install any dependencies that the package might require. To install a package with `dpkg`, simply provide the `-i` or `--install` option and the path to the `.deb`. This implies that you have previously downloaded (or obtained in some other way) the `.deb` file of the package to install.

```
# dpkg -i man-db_2.9.3-2_amd64.deb
(Reading database ... 309317 files and directories currently installed.)
Preparing to unpack man-db_2.9.3-2_amd64.deb ...
Unpacking man-db (2.9.3-2) over (2.9.3-2) ...
Setting up man-db (2.9.3-2) ...
Updating database of manual pages ...
man-db.service is a disabled or a static unit not running, not starting it.
Processing triggers for kali-menu (2020.4.0) ...
Processing triggers for mime-support (3.64) ...
```

We can see the different steps performed by `dpkg` and can see at what point any error may have occurred. The `-i` or `--install` option performs two steps automatically: it unpacks the package and runs the configuration scripts. You can perform these two steps independently (as apt does behind the scenes) with the `--unpack` and `--configure` options, respectively:

```
# dpkg --unpack man-db_2.9.3-2_amd64.deb
(Reading database ... 309317 files and directories currently installed.)
Preparing to unpack man-db_2.9.3-2_amd64.deb ...
Unpacking man-db (2.9.3-2) over (2.9.3-2) ...
Processing triggers for kali-menu (2020.4.0) ...
Processing triggers for mime-support (3.64) ...
# dpkg --configure man-db
Setting up man-db (2.9.3-2) ...
Updating database of manual pages ...
```

Note that the "Processing triggers" lines refer to code that is automatically executed whenever a package adds, removes, or modifies files in some monitored directories. For instance, the _mime-support_ package monitors `/usr/lib/mime/packages` and executes the `update-mime` command whenever something changes in that directory (like `/usr/lib/mime/packages/man-db` in the specific case of man-db).

Sometimes `dpkg` will fail to install a package and return an error. However, you can order `dpkg` to ignore this and only issue a warning with various `--force-*` options. Issuing the `dpkg --force-help` command will display a complete list of these options. For example, you can use `dpkg` to forcibly install `zsh`:

```
$ dpkg -i --force-overwrite zsh_5.8-5+b1_amd64.deb
```

A frequent error, which you are bound to encounter sooner or later, is a file collision. When a package contains a file that is already installed by another package, `dpkg` will refuse to install it. The following types of messages will then appear:

```
Unpacking libgdm (from .../libgdm_3.8.3-2_amd64.deb) ...
dpkg: error processing /var/cache/apt/archives/libgdm_3.8.3-2_amd64.deb (--unpack): trying to overwrite '/usr/bin/gdmflexiserver', which is also in package gdm3 3.4.1-9
```

In this case, if you think that replacing this file is not a significant risk to the stability of your system (which is usually the case), you can use `--force-overwrite` to overwrite the file.

While there are many available `--force-*` options, only `--force-overwrite` is likely to be used regularly. These options exist for exceptional situations, and it is better to leave them alone as much as possible in order to respect the rules imposed by the packaging mechanism. Do not forget, these rules ensure the consistency and stability of your system.

#### Installing Packages with APT

Although APT is much more advanced than `dpkg` and does a lot more behind the scenes, you will find that interacting with packages is quite simple. You can add a package to the system with a simple `apt install package`. APT will automatically install the necessary dependencies:

```
# apt install kali-tools-gpu
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following additional packages will be installed:
  oclgausscrack truecrack
The following NEW packages will be installed:
Need to get 2,602 kB of archives.
After this operation, 2,898 kB of additional disk space will be used.
Get:1 http://kali.download/kali kali-rolling/main amd64 oclgausscrack amd64 1.3-1kali3 [30.7 kB]
Get:2 http://kali.download/kali kali-rolling/main amd64 truecrack amd64 3.6+git20150326-0kali1 [2,558 kB]
Get:3 http://kali.download/kali kali-rolling/main amd64 kali-tools-gpu amd64 2021.1.0 [12.6 kB]
Fetched 2,602 kB in 1s (2,645 kB/s)
Selecting previously unselected package oclgausscrack.
(Reading database ... 108127 files and directories currently installed.)
Preparing to unpack .../oclgausscrack_1.3-1kali3_amd64.deb ...
Unpacking oclgausscrack (1.3-1kali3) ...
Selecting previously unselected package truecrack.
Preparing to unpack .../truecrack_3.6+git20150326-0kali1_amd64.deb ...
Unpacking truecrack (3.6+git20150326-0kali1) ...
Selecting previously unselected package kali-tools-gpu.
Preparing to unpack .../kali-tools-gpu_2021.1.0_amd64.deb ...
Unpacking kali-tools-gpu (2021.1.0) ...
Setting up oclgausscrack (1.3-1kali3) ...
Setting up truecrack (3.6+git20150326-0kali1) ...
Setting up kali-tools-gpu (2021.1.0) ...
Processing triggers for man-db (2.9.3-2) ...
Processing triggers for kali-menu (2020.4.0) ...
```

You can also use `apt-get install package`, or `aptitude install package`. For simple package installation, they do essentially the same thing. As you will see later, the differences are more meaningful for upgrades or when dependencies resolution do not have any perfect solution.

If `sources.list` lists several distributions, you can specify the package version with `apt install package=version`, but indicating its distribution of origin (kali-rolling or kali-dev) with `apt install package/distribution` is usually preferred.

```
# apt install zsh=5.7.1-1
# apt install zsh/kali-dev
```

As with `dpkg`, you can also instruct `apt` to forcibly install a package and overwrite files with `--force-overwrite`, but the syntax is a bit strange since you are passing the argument through to `dpkg`:

```
# apt -o Dpkg::Options::="--force-overwrite" install zsh
```

### 9.2.3. Upgrading Kali Linux

As a rolling distribution, Kali Linux has spectacular upgrade capabilities. In this section, we will take a look at how simple it is to upgrade Kali, and we will discuss strategies for planning your updates.

We recommend regular upgrades, because they will install the latest security updates. To upgrade, use `apt update` followed by either `apt upgrade`, `apt-get upgrade`, or `aptitude safe-upgrade`. These commands look for installed packages that can be upgraded without removing any packages. In other words, the goal is to ensure the least intrusive upgrade possible. The `apt-get` command line tool is slightly more demanding than `aptitude` or `apt` because it will refuse to install packages that were not installed beforehand.

The `apt` tool will generally select the most recent version number.

To tell `apt` to use a specific distribution when searching for upgraded packages, you need to use the `-t` or `--target-release` option, followed by the name of the distribution you want (for example: `apt -t kali-rolling upgrade`). To avoid specifying this option every time you use `apt`, you can add `APT::Default-Release "kali-rolling";` in the file `/etc/apt/apt.conf.d/local`.

For more important upgrades, such as major version upgrades, use `apt full-upgrade`. With this instruction, `apt` will complete the upgrade even if it has to remove some obsolete packages or install new dependencies. This is also the command that you should use for regular upgrades of your Kali Rolling system. It is so simple that it hardly needs explanation: APT's reputation is based on this great functionality.

Unlike `apt` and `aptitude`, `apt-get` doesn't know the `full-upgrade` command. Instead, you should use `apt-get dist-upgrade` (distribution upgrade), a well-known command that `apt` and `aptitude` also accept for backwards compatibility.

**Be Aware of Important Changes**

To anticipate some of these problems, you can install the `apt-listchanges` package, which displays information about possible problems at the beginning of a package upgrade. This information is compiled by the package maintainers and put in `/usr/share/doc/package/NEWS.Debian` files for your benefit. Reading these files (possibly through `apt-listchanges`) should help you avoid nasty surprises.

Since becoming a rolling distribution, Kali can receive upgrades several times a day. However, that might not be the best strategy. So, how often should you upgrade Kali Linux? There is no hard rule but there are some guidelines that can help you. You should upgrade:

- When you are aware of a security issue that is fixed in an update.
- When you suspect that an updated version might fix a bug that you are experiencing.
- Before reporting a bug to make sure it is still present in the latest version that you have available.
- Often enough to get the security fixes that you have not heard about.

There are also cases where it is best to not upgrade. For example, it might not be a good idea to upgrade:

- If you can't afford any breakage (for example, because you go offline, or because you are about to give a presentation with your computer); it is best to do the upgrade later, when you have enough time to troubleshoot any issue introduced in the process.
- If a disruptive change happened recently (or is still ongoing) and you fear that all issues have not yet been discovered. For example, when a new GNOME version is released, not all packages are updated at the same time and you are likely to have a mix of packages with the old version and the new version. Most of the time this is fine and it helps everybody to release those updates progressively, but there are always exceptions and some applications might be broken due to such discrepancies.
- If the `apt full-upgrade` output tells you that it will remove packages that you consider important for your work. In those cases, you want to review the situation and try to understand why `apt` wants to remove them. Maybe the packages are currently broken and in this case you might want to wait until fixed versions are available, or they have been obsoleted and you should identify their replacements and then proceed with the full upgrade anyway.

In general, we recommend that you upgrade Kali at least once a week. You can certainly upgrade daily but it doesn't make sense to do it more often than that. Even if our mirrors are synchronized four times a day, the updates coming from Debian usually land only once a day.

### 9.2.4. Removing and Purging Packages

Removing a package is even simpler than installing one. Let's take a look at how to remove a package with `dpkg` and `apt`.

To remove a package with `dpkg`, supply the `-r` or `--remove` option, followed by the name of a package. This removal is not, however, complete: all of the configuration files, maintainer scripts, log files (system logs), data generated by the service (such as the content of an LDAP server directory or the content of a database for an SQL server), and most other user data handled by the package remain intact. The remove option makes it easy to uninstall a program and later re-install it with the same configuration. Also remember that dependencies are not removed. Consider this example:

```
# dpkg --remove kali-tools-gpu
(Reading database ... 108172 files and directories currently installed.)
Removing kali-tools-gpu (2021.1.0) ....
```

You can also remove packages from the system with `apt remove package`. APT will automatically delete the packages that depend on the package that is being removed. Like the `dpkg` example, configuration files and user data will not be removed.

Through the addition of suffixes to package names, you can use `apt` (or `apt-get` and `aptitude`) to install certain packages and remove others on the same command line. With an `apt install` command, add "`-`" to the names of the packages you wish to remove. With an `apt remove` command, add "`+`" to the names of the packages you wish to install.

The next example shows two different ways to install _package1_ and to remove _package2_.

```
# apt install package1 package2-
[...]
# apt remove package1+ package2
[...]
```

This can also be used to exclude packages that would otherwise be installed, for example due to a `Recommends` (discussed later in [_`Recommends`, `Suggests`, and `Enhances` Fields_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/debian-package-management/apt-package-reference:-digging-deeper-into-the-debian-package-system/apt-package-reference:-digging-deeper-into-the-debian-package-system). In general, the dependency solver will use that information as a hint to look for alternative solutions.

To remove all data associated with a package, you can purge the package with the `dpkg -P package`, or `apt purge package` commands. This will completely remove the package and all user data, and in the case of `apt`, will delete dependencies as well.

```
# dpkg -r debian-cd
(Reading database ... 333606 files and directories currently installed.)
Removing debian-cd (3.1.32) ...
# dpkg -P debian-cd
(Reading database ... 332950 files and directories currently installed.)
Removing debian-cd (3.1.32) ...
Purging configuration files for debian-cd (3.1.32) ...
```

Warning! Given the definitive nature of purge, do not execute it lightly. You will lose everything associated with that package.

### 9.2.5. Inspecting Packages

Next, let's take a look at some of the tools that can be used to inspect Debian packages. We will learn of `dpkg`, `apt`, and `apt-cache` commands that can be used to query and visualize the package database.

#### Querying dpkg's Database and Inspecting .deb Files

We will begin with several `dpkg` options that query the internal dpkg database. This database resides on the filesystem at `/var/lib/dpkg` and contains multiple sections including configuration scripts (`/var/lib/dpkg/info`), a list of files the package installed (`/var/lib/dpkg/info/*.list`), and the status of each package that has been installed (`/var/lib/dpkg/status`). You can use `dpkg` to interact with the files in this database. Note that most options are available in a long version (one or more relevant words, preceded by a double dash) and a short version (a single letter, often the initial of one word from the long version, and preceded by a single dash). This convention is so common that it is a POSIX standard.

First, let's take a look at `--listfiles package` (or `-L`), which lists the files that were installed by the specified package:

```
$ dpkg -L base-passwd
/.
/usr
/usr/sbin
/usr/sbin/update-passwd
/usr/share
/usr/share/lintian
/usr/share/lintian/overrides
/usr/share/lintian/overrides/base-passwd
/usr/share/doc-base
/usr/share/doc-base/users-and-groups
/usr/share/base-passwd
/usr/share/base-passwd/group.master
/usr/share/base-passwd/passwd.master
/usr/share/man
/usr/share/man/pl
/usr/share/man/pl/man8
/usr/share/man/pl/man8/update-passwd.8.gz
[...]
/usr/share/doc
/usr/share/doc/base-passwd
/usr/share/doc/base-passwd/users-and-groups.txt.gz
/usr/share/doc/base-passwd/changelog.gz
/usr/share/doc/base-passwd/copyright
/usr/share/doc/base-passwd/README
/usr/share/doc/base-passwd/users-and-groups.html
```

Next, `dpkg --search file` (or `-S`), finds any packages containing the file or path passed in the argument. For example, to find the package containing `/bin/date`:

```
$ dpkg -S /bin/date
coreutils: /bin/date
```

The `dpkg --status package` (or `-s`) command displays the headers of an installed package. For example, to search the headers for the `coreutils` package:

```
$ dpkg -s coreutils
Package: coreutils
Status: install ok installed
Priority: required
Section: utils
Installed-Size: 13855
Maintainer: Michael Stone
Architecture: amd64
Multi-Arch: foreign
Version: 8.23-3
Replaces: mktemp, realpath, timeout
Pre-Depends: libacl1 (>= 2.2.51-8), libattr1 (>= 1:2.4.46-8), libc6 (>= 2.17), libselinux1 (>= 2.1.13)
Conflicts: timeout
Description: GNU core utilities
This package contains the basic file, shell and text manipulation
utilities which are expected to exist on every operating system.
.
Specifically, this package includes:
arch base64 basename cat chcon chgrp chmod chown chroot cksum comm cp
csplit cut date dd df dir dircolors dirname du echo env expand expr
factor false flock fmt fold groups head hostid id install join link ln
logname ls md5sum mkdir mkfifo mknod mktemp mv nice nl nohup nproc numfmt
od paste pathchk pinky pr printenv printf ptx pwd readlink realpath rm
rmdir runcon sha*sum seq shred sleep sort split stat stty sum sync tac
tail tee test timeout touch tr true truncate tsort tty uname unexpand
uniq unlink users vdir wc who whoami yes
Homepage: http://gnu.org/software/coreutils
```

The `dpkg --list` (or `-l`) command displays the list of packages known to the system and their installation status. You can also use `grep` on the output to search for certain fields, or provide wildcards (such as `b*`) to search for packages that match a particular partial search string. This will show a summary of the packages. For example, to show a summary list of all packages that start with '**b**':

```
$ dpkg -l 'b*'
Desired=Unknown/Install/Remove/Purge/Hold
| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend
|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)
||/ Name              Version       Architecture  Description
+++-=========================-==========================-============-=====================
ii  backdoor-factory  3.4.2+dfsg-4  all           Patch 32/64 bits ELF & win32/64 binaries with shellcode
un  backupninja           (no description available)
un  backuppc              (no description available)
un  balsa                 (no description available)
un  base                  (no description available)
[...]
```

The `dpkg --contents file.deb` (or `-c`) command lists all the files in a particular `.deb` file:

```
$ dpkg -c /var/cache/apt/archives/gpg_2.2.20-1_amd64.deb
drwxr-xr-x root/root         0 2020-03-23 15:05 ./
drwxr-xr-x root/root         0 2020-03-23 15:05 ./usr/
drwxr-xr-x root/root         0 2020-03-23 15:05 ./usr/bin/
-rwxr-xr-x root/root   1062832 2020-03-23 15:05 ./usr/bin/gpg
drwxr-xr-x root/root         0 2020-03-23 15:05 ./usr/share/
drwxr-xr-x root/root         0 2020-03-23 15:05 ./usr/share/doc/
drwxr-xr-x root/root         0 2020-03-23 15:05 ./usr/share/doc/gpg/
-rw-r--r-- root/root       677 2020-03-23 14:45 ./usr/share/doc/gpg/NEWS.Debian.gz
-rw-r--r-- root/root     24353 2020-03-23 15:05 ./usr/share/doc/gpg/changelog.Debian.gz
-rw-r--r-- root/root    384091 2020-03-20 11:38 ./usr/share/doc/gpg/changelog.gz
-rw-r--r-- root/root     10555 2020-03-23 15:04 ./usr/share/doc/gpg/copyright
drwxr-xr-x root/root         0 2020-03-23 15:05 ./usr/share/man/
drwxr-xr-x root/root         0 2020-03-23 15:05 ./usr/share/man/man1/
-rw-r--r-- root/root     46139 2020-03-23 15:05 ./usr/share/man/man1/gpg.1.gz
```

The `dpkg --info file.deb` (or `-I`) command displays the headers of the specified `.deb` file:

```
$ dpkg -I /var/cache/apt/archives/gpg_2.2.20-1_amd64.deb
 new Debian package, version 2.0.
 size 894224 bytes: control archive=1160 bytes.
    1219 bytes,    25 lines      control
     374 bytes,     6 lines      md5sums
 Package: gpg
 Source: gnupg2
 Version: 2.2.20-1
 Architecture: amd64
 Maintainer: Debian GnuPG Maintainers
 Installed-Size: 1505
 Depends: gpgconf (= 2.2.20-1), libassuan0 (>= 2.5.0), libbz2-1.0, libc6 (>= 2.25), libgcrypt20 (>= 1.8.0), libgpg-error0 (>= 1.35), libreadline8 (>= 6.0), libsqlite3-0 (>= 3.7.15), zlib1g (>= 1:1.1.4)
 Recommends: gnupg (= 2.2.20-1)
 Breaks: gnupg (<< 2.1.21-4)
 Replaces: gnupg (<< 2.1.21-4)
 Section: utils
 Priority: optional
 Multi-Arch: foreign
 Homepage: https://www.gnupg.org/
 Description: GNU Privacy Guard -- minimalist public key operations
  GnuPG is GNU's tool for secure communication and data storage.
  It can be used to encrypt data and to create digital signatures.
  It includes an advanced key management facility and is compliant
  with the proposed OpenPGP Internet standard as described in RFC4880.
[...]
```

You can also use `dpkg` to compare package version numbers with the `--compare-versions` option, which is often called by external programs, including configuration scripts executed by `dpkg` itself. This option requires three parameters: a version number, a comparison operator, and a second version number. The different possible operators are: `lt` (strictly less than), `le` (less than or equal to), `eq` (equal), `ne` (not equal), `ge` (greater than or equal to), and `gt` (strictly greater than). If the comparison is correct, `dpkg` returns 0 (success); if not, it gives a non-zero return value (indicating failure). Consider these comparisons:

```
$ dpkg --compare-versions 1.2-3 gt 1.1-4
$ echo $?
0
$ dpkg --compare-versions 1.2-3 lt 1.1-4
$ echo $?
1
$ dpkg --compare-versions 2.6.0pre3-1 lt 2.6.0-1
$ echo $?
1
```

Note the unexpected failure of the last comparison: for `dpkg`, the string "`pre`" (usually denoting a pre-release) has no particular meaning, and `dpkg` simply interprets it as a string, in which case "`2.6.0pre3-1`" is alphabetically greater than "`2.6.0-1`". When we want a package's version number to indicate that it is a pre-release, we use the tilde character, "`~`":

```
$ dpkg --compare-versions 2.6.0~pre3-1 lt 2.6.0-1
$ echo $?
0
```

#### Querying the Database of Available Packages with `apt-cache` and `apt`

The `apt-cache` command can display much of the information stored in APT's internal database. This information is a sort of cache since it is gathered from the different sources listed in the `sources.list` file. This happens during the `apt update` operation.

**_VOCABULARY_ Cache**

A cache is a temporary storage system used to speed up frequent data access when the usual access method is expensive (performance-wise). This concept can be applied in numerous situations and at different scales, from the core of microprocessors up to high-end storage systems.

In the case of APT, the reference `Packages` files are those located on Debian mirrors. That said, it would be very ineffective to push every search through the online package databases. That is why APT stores a copy of those files (in `/var/lib/apt/lists/`) and searches are done within those local files. Similarly, `/var/cache/apt/archives/` contains a cached copy of already downloaded packages to avoid downloading them again if you need to reinstall them.

To avoid excessive disk usage when you upgrade frequently, you should regularly sort through the `/var/cache/apt/archives/` directory. Two commands can be used for this: `apt clean` (or `apt-get clean`) entirely empties the directory; `apt autoclean` (`apt-get autoclean`) only removes packages that can no longer be downloaded because they have disappeared from the mirror and are therefore useless. Note that the configuration parameter `APT::Clean-Installed` can be used to prevent the removal of `.deb` files that are currently installed. Also, note that `apt` drops the downloaded files once they have been installed, so this matters mainly when you use other tools.

The `apt-cache` command can do keyword-based package searches with `apt-cache search keyword`. It can also display the headers of the package's available versions with `apt-cache show package`. This command provides the package's description, its dependencies, and the name of its maintainer. This feature is particularly useful in determining the packages that are installed via metapackages, such as _kali-tools-wireless_, _kali-tools-web_, and _kali-tools-gpu_. Note that `apt search`, `apt show`, `aptitude search`, and `aptitude show` work in the same way.

**An Alternative: `axi-cache`**

`apt-cache search` is a very rudimentary tool, basically implementing `grep` on package's descriptions. It often returns too many results or none at all, when too many keywords are included.

`axi-cache search term`, on the other hand, provides better results, sorted by relevancy. It uses the _Xapian_ search engine and is part of the `apt-xapian-index` package, which indexes all package information (and more, like the `.desktop` files from all Debian packages). It knows about tags and returns results in a matter of milliseconds.

```
$ axi-cache search forensics graphical
7 results found.
Results 1-7:
100% autopsy - graphical interface to SleuthKit
94% forensics-all-gui - Debian Forensics Environment - GUI components (metapackage)
87% forensics-extra-gui - Forensics Environment - extra GUI components (metapackage)
86% forensics-colorize - show differences between files using color graphics
44% gpart - Guess PC disk partition table, find lost partitions
39% testdisk - Partition scanner and disk recovery tool, and PhotoRec file recovery tool
8% texlive-publishers - TeX Live: Publisher styles, theses, etc.
More terms: tools experts autopsy picture ethical pentesters hackers
More tags: admin::forensics security::forensics admin::recovery interface::commandline admin::boot scope::utility role::program
```

Some features are more rarely used. For instance, `apt-cache policy` displays the priorities of package sources as well as those of individual packages. Another example is `apt-cache dumpavail`, which displays the headers of all available versions of all packages. `apt-cache pkgnames` displays the list of all the packages that appear at least once in the cache.

### 9.2.6. Troubleshooting

Sooner or later, you will run into a problem when interacting with a package. In this section, we will outline some basic troubleshooting steps that you can take and provide some tools that will lead you closer to a potential solution.

#### Handling Problems after an Upgrade

In spite of the Debian or Kali maintainers' best efforts, a system upgrade isn't always as smooth as we would hope. New software versions may be incompatible with previous ones (for instance, their default behavior or their data format may have changed), or bugs may slip through the cracks despite the testing performed by package maintainers and Debian Unstable users.

##### Leveraging Bug Reports

You might sometimes find that a new version of software doesn't work at all. This generally happens if the application isn't particularly popular and hasn't been tested enough. The first thing to do is to have a look at the [Kali bug tracker](https://bugs.kali.org/) and at the [Debian bug tracking system](https://bugs.debian.org/) at `https://bugs.debian.org/package`, and check whether the problem has already been reported. If it hasn't, you should report it yourself (see [_Filing a Good Bug Report_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/helping-yourself-and-getting-help/filing-a-good-bug-report/filing-a-good-bug-report) for detailed instructions). If it is already known, the bug report and the associated messages are usually an excellent source of information related to the bug. In some cases, a patch already exists and has been made available in the bug report itself; you can then recompile a fixed version of the broken package locally (see [_Modifying Kali Packages_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/advanced-usage)). In other cases, users may have found a workaround for the problem and shared their insights about it in their replies to the report; those instructions may help you work around the problem until a fix or patch is released. In a best-case scenario, the package may have already been fixed and you may find details in the bug report.

##### Downgrading to a Working Version

When the problem is a clear regression (where the former version worked), you can try to downgrade the package. In this case, you will need a copy of the old version. If you have access to the old version in one of the repositories configured in APT, you can use a simple one-liner command to downgrade (see [_Installing Packages with APT_](https://portal.offsec.com/courses/pen-103-16306/learning/debian-package-management-16831/exercises-16872/kali-multiarch-16993#sect.apt-package-install)). But with Kali's rolling release, you will usually only find a single version of each package at any one time.

You can still try to find the old `.deb` file and install it manually with `dpkg`. Old `.deb` files can be found in multiple places:

- In APT's cache in `/var/cache/apt/archives/`.
- In the `pool` directory on your usual Kali mirror (removed and obsolete packages are kept for three to four days to avoid problems with users not having the latest package indices).
- In [https://snapshot.debian.org](https://snapshot.debian.org/) if the affected package was provided by Debian and not by Kali; this service keeps historical versions of all Debian packages.

##### Dealing with Broken Maintainer Scripts

Sometimes the upgrade gets interrupted because one of the package maintainer scripts fails (usually, it is the `postinst`). In those cases, you can try to diagnose the problem, and possibly work around it, by editing the problematic script.

Here we rely on the fact that maintainer scripts are stored in `/var/lib/dpkg/info/` and that we can review and modify them.

Since maintainer scripts are usually simple shell scripts, it is possible to add a `set -x` line just after the shebang line and arrange them to be rerun (with `dpkg --configure -a` for `postinst`) to see precisely what is happening and where it is failing. This output can also nicely complement any bug report that you might file.

With this newly gained knowledge, you can either fix the underlying problem or transform the failing command into a working one (for example by adding `|| true` at the end of the line).

Note that this tip does not work for a failing `preinst` since that script is executed even before the package gets installed so it is not yet in its final location. It does work for `postrm` and `prerm` although you will need to execute a package removal (respectively upgrade) to trigger them.

#### The dpkg Log File

The `dpkg` tool keeps a log of all of its actions in `/var/log/dpkg.log`. This log is extremely verbose, since it details all the stages of each package. In addition to offering a way to track dpkg's behavior, it helps to keep a history of the development of the system: you can find the exact moment when each package has been installed or updated, and this information can be extremely useful in understanding a recent change in behavior. Additionally, with all versions being recorded, it is easy to cross-check the information with the `changelog.Debian.gz` for packages in question, or even with online bug reports.

```
# tail /var/log/dpkg.log
2021-01-06 23:16:37 status installed kali-tools-gpu:amd64 2021.1.0
2021-01-06 23:16:37 remove kali-tools-gpu:amd64 2021.1.0
2021-01-06 23:16:37 status half-configured kali-tools-gpu:amd64 2021.1.0
2021-01-06 23:16:37 status half-installed kali-tools-gpu:amd64 2021.1.0
2021-01-06 23:16:37 status config-files kali-tools-gpu:amd64 2021.1.0
2021-01-06 23:16:37 status not-installed kali-tools-gpu:amd64
```

#### Reinstalling Packages with apt --reinstall and aptitude reinstall

When you mistakenly damage your system by removing or modifying certain files, the easiest way to restore them is to reinstall the affected package. Unfortunately, the packaging system finds that the package is already installed and politely refuses to reinstall it. To avoid this, use the `--reinstall` option of the `apt` and `apt-get` commands. The following command reinstalls `postfix` even if it is already present:

```
# apt --reinstall install postfix
```

The `aptitude` command line is slightly different but achieves the same result with `aptitude reinstall postfix`. The `dpkg` command does not prevent re-installation, but it is rarely called directly.

**Do Not Use `apt --reinstall` to Recover from an Attack**

Using `apt --reinstall` to restore packages modified during an attack will certainly not recover the system as it was.

After an attack, you can't rely on anything: `dpkg` and `apt` might have been replaced by malicious programs, not reinstalling the files as you would like them to. The attacker might also have altered or created files outside the control of `dpkg`.

Remember that you can specify a specific distribution with `apt` as well, which means you can roll back to an older version of a package (if for instance you know that it works well), provided that it is still available in one of the sources referenced by the `sources.list` file:

```
# apt install w3af/kali-dev
```

#### Leveraging --force-* to Repair Broken Dependencies

If you are not careful, the use of a `--force-*` option or some other malfunction can lead to a system where the APT family of commands will refuse to function. In effect, some of these options allow installation of a package when a dependency is not met, or when there is a conflict. The result is an inconsistent system from the point of view of dependencies, and the APT commands will refuse to execute any action except those that will bring the system back to a consistent state (this often consists of installing the missing dependency or removing a problematic package). This usually results in a message like this one, obtained after installing a new version of _rdesktop_ while ignoring its dependency on a newer version of _libc6_:

```
# apt full-upgrade
[...]
You might want to run 'apt-get -f install' to correct these.
The following packages have unmet dependencies:
rdesktop: Depends: libc6 (>= 2.14) but 2.3.6.ds1-13etch7 is installed
E: Unmet dependencies. Try using -f.
```

If you are a courageous administrator who is certain of the correctness of your analysis, you may choose to ignore a dependency or conflict and use the corresponding `--force-*` option. In this case, if you want to be able to continue to use `apt` or `aptitude`, you must edit `/var/lib/dpkg/status` to delete or modify the dependency, or conflict, that you have chosen to override.

This manipulation is an ugly hack and should never be used, except in the most extreme case of necessity. Quite frequently, a more fitting solution is to recompile the package that is causing the problem or use a new version (potentially corrected) from a repository providing backports (backports are newer versions especially recompiled to work in an older environment).

### 9.2.7. Frontends: aptitude and synaptic

APT is a C++ program whose code mainly resides in the `libapt-pkg` shared library. Thanks to this shared library, it opened the door for the creation of user interfaces (front-ends), since the shared library code can easily be reused. Historically, `apt-get` was only designed as a test front-end for `libapt-pkg` but its success tends to obscure this fact.

Over time, despite the popularity of command line interfaces like `apt` and `apt-get`, various graphical interfaces were developed. We will take a look at two of those interfaces in this section: `aptitude` and `synaptic`.

#### Aptitude

Aptitude, shown in Figure 1, is an interactive program that can be used in semi-graphical mode on the console. You can browse the list of installed and available packages, look up all the information, and select packages to install or remove. The program is designed specifically to be used by administrators so its default behavior is much more intelligent than APT's, and its interface much easier to understand.

![Figure 1: The aptitude package manager](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/b4074676f48f42814e683e0b4cdce53d-09_aptitude.png)

Figure 1: The aptitude package manager

When you run `aptitude`, you are shown a list of packages sorted by state (installed, not-installed, or installed but not available on the mirrors), while other sections display tasks, virtual packages, and new packages that appeared recently on mirrors. To facilitate thematic browsing, other views are available.

In all cases, `aptitude` displays a list combining categories and packages on the screen. Categories are organized through a tree structure, whose branches can respectively be unfolded or folded with the **Enter**, **[+**, and **]+** keys. The **+** key should be used to mark a package for installation, **-** to mark it for removal, and **_** to purge it. Note that these keys can also be used for categories, in which case the corresponding actions will be applied to all the packages of the category. The **u** key updates the lists of available packages and ** +Shift+ +u** prepares a global system upgrade. The **g** key switches to a summary view of the requested changes (and typing **g** again will apply the changes), and **q** quits the current view. If you are in the initial view, this will close `aptitude`.

**`aptitude`'s Documentation**

This section does not cover the finer details of using `aptitude`, it rather focuses on giving you a user survival kit. `aptitude` is rather well documented and we advise you to use its complete manual available in the `aptitude-doc-en` package (see `/usr/share/doc/aptitude/html/en/index.html`) or at:

> [https://www.debian.org/doc/manuals/aptitude/](https://www.debian.org/doc/manuals/aptitude/)

To search for a package, you can type `/` followed by a search pattern. This pattern matches the name of the package but can also be applied to the description (if preceded by `~d`), to the section (with `~s`), or to other characteristics detailed in the documentation. The same patterns can filter the list of displayed packages: type the `l` key (as in _limit_) and enter the pattern.

Managing the _automatic flag_ of Debian packages (see [_Tracking Automatically Installed Packages_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/debian-package-management/advanced-apt-configuration-and-usage/tracking-automatically-installed-packages)) is a breeze with `aptitude`. It is possible to browse the list of installed packages and mark packages as automatic with **Shift**+**m** or you can remove the mark with the `m` key. Automatic packages are displayed with an "A" in the list of packages. This feature also offers a simple way to visualize the packages in use on a machine, without all the libraries and dependencies that you don't really care about. The related pattern that can be used with `l` (to activate the filter mode) is `~i!~M`. It specifies that you only want to see installed packages (`~i`) not marked as automatic (`!~M`).

**Using `aptitude` on the Command-Line Interface**

Most of Aptitude's features are accessible via the interactive interface as well as via the command-line. These command-lines will seem familiar to regular users of `apt-get` and `apt-cache`.

The advanced features of `aptitude` are also available on the command-line. You can use the same package search patterns as in the interactive version. For example, if you want to clean up the list of manually installed packages, and if you know that none of the locally installed programs require any particular libraries or Perl modules, you can mark the corresponding packages as automatic with a single command:

```
# aptitude markauto '~slibs|~sperl'
```

Here, you can clearly see the power of the search pattern system of `aptitude`, which enables the instant selection of all the packages in the `libs` and `perl` sections.

Beware, if some packages are marked as automatic and if no other package depends on them, they will be removed immediately (after a confirmation request).

##### Managing Recommendations, Suggestions, and Tasks

Another interesting feature of `aptitude` is the fact that it respects recommendations between packages while still giving users the choice not to install them on a case-by-case basis. For example, the `gnome` package recommends `gdebi` (among others). When you select the former for installation, the latter will also be selected (and marked as automatic if not already installed on the system). Typing `g` will make it obvious: `gdebi` appears on the summary screen of pending actions in the list of packages installed automatically to satisfy dependencies. However, you can decide not to install it by deselecting it before confirming the operations.

Note that this recommendation tracking feature does not apply to upgrades. For instance, if a new version of _gnome_ recommends a package that it did not recommend formerly, the package won't be marked for installation. However, it will be listed on the upgrade screen so that the administrator can still select it for installation.

Suggestions between packages are also taken into account, but in a manner adapted to their specific status. For example, since _gnome_ suggests `dia-gnome`, the latter will be displayed on the summary screen of pending actions (in the section of packages suggested by other packages). This way, it is visible and the administrator can decide whether to take the suggestion into account or not. Since it is only a suggestion and not a dependency or a recommendation, the package will not be selected automatically—its selection requires manual intervention (thus, the package will not be marked as automatic).

In the same spirit, remember that `aptitude` makes intelligent use of the concept of tasks. Since tasks are displayed as categories in the screens of packages lists, you can either select a full task for installation or removal or browse the list of packages included in the task to select a smaller subset.

##### Better Solver Algorithms

To conclude this section, let's note that `aptitude` has more elaborate algorithms compared to `apt` when it comes to resolving difficult situations. When a set of actions is requested and when these combined actions would lead to an incoherent system, `aptitude` evaluates several possible scenarios and presents them in order of decreasing relevance. However, these algorithms are not foolproof. Fortunately, there is always the possibility to manually select the actions to perform. When the currently selected actions lead to contradictions, the upper part of the screen indicates a number of broken packages (you can directly navigate to those packages by pressing **b**). Then you can manually build a solution. In particular, you can get access to the different available versions by selecting the package with **Enter**. If the selection of one of these versions solves the problem, you should not hesitate to use the function. When the number of broken packages gets down to zero, you can safely go to the summary screen of pending actions for a last check before you apply them.

**Aptitude's Log**

Like `dpkg`, `aptitude` keeps a trace of executed actions in its logfile (`/var/log/aptitude`). However, since both commands work at a very different level, you cannot find the same information in their respective logfiles. While `dpkg` logs all the operations executed on individual packages step-by-step, `aptitude` gives a broader view of high-level operations like a system-wide upgrade.

Beware, this logfile only contains a summary of operations performed by `aptitude`. If other front-ends (or even `dpkg` itself) are occasionally used, then `aptitude`'s log will only contain a partial view of the operations, so you can't rely on it to build a trustworthy history of the system.

#### Synaptic

Synaptic is a graphical package manager that features a clean and efficient graphical interface (shown in Figure 2) based on GTK+. Its many ready-to-use filters give fast access to newly available packages, installed packages, upgradable packages, obsolete packages, and so on. If you browse through these lists, you can select the operations to be done on the packages (install, upgrade, remove, purge); these operations are not performed immediately, but put into a task list. A single click on a button then validates the operations and they are performed in one go.

![Figure 2: synaptic Package Manager](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/802fef0dbbb7b137e019e2a52052e8f6-09_synaptic.png)

Figure 2: synaptic Package Manager

## 9.3. Advanced APT Configuration and Usage

Now it is time to dive into some more advanced topics. First, we will take a look at advanced configuration of APT, which will allow you to set more permanent options that will apply to APT tools. We will then show how package priorities can be manipulated, which opens the door for advanced fine-tuned, customized updates and upgrades. We will also show how to handle multiple distributions so that you can start experimenting with packages coming from other distributions. Next, we will take a look at how to track automatically installed packages, a capability that enables you to manage packages that are installed through dependencies. We will also explain how multi-arch support opens the door for running packages built for various hardware architectures. Last but not least, we will discuss the cryptographic protocols and utilities in place that will let you validate each package's authenticity.

### 9.3.1. Configuring APT

Before we dive into the configuration of APT, let's take a moment to discuss the configuration mechanism of a Debian-based system. Historically, configuration was handled by dedicated configuration files. However, in modern Linux systems like Debian and Kali, configuration directories with the `.d` suffix are becoming more commonly used. Each directory represents a configuration file that is split into multiple files. In this sense, all of the files in `/etc/apt/apt.conf.d/` are instructions for the configuration of APT. APT processes the files in alphabetical order, so that the later files can modify configuration elements defined in the earlier files.

This structure brings some flexibility to administrators and package maintainers, allowing them to make software configuration changes through file additions without having to change an existing file. This is especially helpful for package maintainers because they can use this approach to adapt the configuration of other software to ensure that it perfectly co-exists with theirs, without breaking the Debian policy that explicitly forbids modifying configuration files of other packages. Because of the `.d` configuration mechanism, you don't have to manually follow multiple package configuration instructions typically found in the package's `/usr/share/doc/package/README.Debian` file, since the installer can drop in configuration files.

**Beware of Configuration Files Generated from `.d` Directories**

While APT has native support of its `/etc/apt/apt.conf.d` directory, this is not always the case. For some applications (like exim, for example), the `.d` directory is a Debian-specific addition used as input to dynamically generate the canonical configuration file used by the application. In those cases, the packages provide an "update-*" command (for example: `update-exim4.conf`) that will concatenate the files from the `.d` directory and overwrite the main configuration file.

In those cases, you must not manually edit the main configuration file as your changes will be lost on the next execution of the `update-*` command, and you must also not forget to run the former command after having edited a file out of the `.d` directory (or your changes will not be used).

Armed with an understanding of the `.d` configuration mechanism, let's talk about how you can leverage it to configure APT. As we have discussed, you can alter APT's behavior through command-line arguments to `dpkg` like this example, which performs a forced overwrite install of `zsh`:

```
# apt -o Dpkg::Options::="--force-overwrite" install zsh
```

Obviously this is very cumbersome, especially if you use options frequently, but you can also use the `.d` directory configuration structure to configure certain aspects of APT by adding directives to a file in the `/etc/apt/apt.conf.d/` directory. For example, this (and any other) directive can easily be added to a file in `/etc/apt/apt.conf.d/`. The name of this file is somewhat arbitrary, but a common convention is to use either `local` or `99local`:

```
$ cat /etc/apt/apt.conf.d/99local
Dpkg::Options {
   "--force-overwrite";
}
```

There are many other helpful configuration options and we certainly can't cover them all, but one we will touch on involves network connectivity. For example, if you can only access the web through a proxy, add a line like `Acquire::http::proxy "http://yourproxy:3128"`. For an FTP proxy, use `Acquire::ftp::proxy "ftp://yourproxy"`.

To discover more configuration options, read the apt.conf(5) manual page with the `man apt.conf` command (for details on manual pages, see [_Manual Pages_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/helping-yourself-and-getting-help#sect.manual-pages)).

### 9.3.2. Managing Package Priorities

One of the most important aspects in the configuration of APT is the management of the priorities associated with each package source. For instance, you might want to extend your Kali Linux system with one or two newer packages from Debian Unstable or Debian Experimental. It is possible to assign a priority to each available package (the same package can have several priorities depending on its version or the distribution providing it). These priorities will influence APT's behavior: for each package, it will always select the version with the highest priority (except if this version is older than the installed one and its priority is less than 1000).

APT defines several default priorities. Each installed package version has a priority of 100. A non-installed version has a priority of 500 by default but it can jump to 990 if it is part of the target release (defined with the `-t` command-line option or the `APT::Default-Release` configuration directive).

You can modify the priorities by adding entries in the `/etc/apt/preferences` file with the names of the affected packages, their version, their origin and their new priority.

APT will never install an older version of a package (that is, a package whose version number is lower than the one of the currently installed package) except when its priority is higher than 1000. APT will always install the highest priority package that follows this constraint. If two packages have the same priority, APT installs the newest one (whose version number is the highest). If two packages of same version have the same priority but differ in their content, APT installs the version that is not installed (this rule has been created to cover the case of a package update without the increment of the revision number, which is usually required).

In more concrete terms, a package whose priority is less than 0 will never be installed. A package with a priority ranging between 0 and 100 will only be installed if no other version of the package is already installed. With a priority between 100 and 500, the package will only be installed if there is no other newer version installed or available in another distribution. A package of priority between 501 and 990 will only be installed if there is no newer version installed or available in the target distribution. With a priority between 990 and 1000, the package will be installed except if the installed version is newer. A priority greater than 1000 will always lead to the installation of the package even if it forces APT to downgrade to an older version.

When APT checks `/etc/apt/preferences`, it first takes into account the most specific entries (often those specifying the concerned package), then the more generic ones (including for example all the packages of a distribution). If several generic entries exist, the first match is used. The available selection criteria include the package's name and the source providing it. Every package source is identified by the information contained in a `Release` file that APT downloads together with the `Packages` files. These files specify the origin, usually "Kali" for the packages from Kali's official mirrors and "Debian" for the packages from Debian's official mirrors, but the origin can also be a person's or an organization's name for third-party repositories. The `Release` file also provides the name of the distribution together with its version. Let's have a look at its syntax through some realistic case studies of this mechanism.

**Priority of Kali-Bleeding-Edge and Debian Experimental**

If you listed Debian experimental in your `sources.list` file, the corresponding packages will almost never be installed because their default APT priority is 1. This is of course a specific case, designed to keep users from installing experimental packages by mistake. The packages can only be installed by typing `apt install package/experimental`, assuming of course that you are aware of the risks and potential headaches of life on the edge. It is still possible (though _not_ recommended) to treat packages of experimental like those of other distributions by giving them a priority of 500. This is done with a specific entry in `/etc/apt/preferences`:

```
Package: *
Pin: release a=experimental
Pin-Priority: 500
```

Let's suppose that you only want to use packages from Kali and that you only want Debian packages installed when explicitly requested. You could write the following entries in the `/etc/apt/preferences` file (or in any file in `/etc/apt/preferences.d/`):

```
Package: *
Pin: release o=Kali
Pin-Priority: 900

Package: *
Pin: release o=Debian
Pin-Priority: -10
```

In the last two examples, you have seen `a=experimental`, which defines the name of the selected distribution and `o=Kali` and `o=Debian`, which limit the scope to packages whose origin are Kali and Debian, respectively.

Let's now assume that you have a server with several local programs depending on the version 5.22 of Perl and that you want to ensure that upgrades will not install another version of it. You could use this entry:

```
Package: perl
Pin: version 5.22*
Pin-Priority: 1001
```

The reference documentation for this configuration file is available in the manual page apt_preferences(5), which you can display with `man apt_preferences`.

**Adding Comments in `/etc/apt/preferences`**

There is no official syntax for comments in `/etc/apt/preferences`, but some textual descriptions can be provided by prepending one or more `Explanation` fields into each entry:

```
Explanation: The package xserver-xorg-video-intel provided
Explanation: in experimental can be used safely
Package: xserver-xorg-video-intel
Pin: release a=experimental
Pin-Priority: 500
```

### 9.3.3. Working with Several Distributions

Given that `apt` is such a marvelous tool, you will likely want to dive in and start experimenting with packages coming from other distributions. For example, after installing a Kali Rolling system, you might want to try out a software package available in Kali Dev, Debian Unstable, or Debian Experimental without diverging too much from the system's initial state.

Even if you will occasionally encounter problems while mixing packages from different distributions, `apt`manages such coexistence very well and limits risks very effectively (provided that the package dependencies are accurate). First, list all distributions used in `/etc/apt/sources.list` and define your reference distribution with the `APT::Default-Release` parameter (see [_Upgrading Kali Linux_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/debian-package-management/basic-package-interaction/installing-packages#sect.apt-upgrade)).

Let's suppose that Kali Rolling is your reference distribution but that Kali Dev and Debian Unstable are also listed in your `sources.list` file. In this case, you can use `apt install package/unstable` to install a package from Debian Unstable. If the installation fails due to some unsatisfiable dependencies, let it solve those dependencies within Unstable by adding the `-t unstable` parameter.

In this situation, upgrades (`upgrade` and `full-upgrade`) are done within Kali Rolling except for packages already upgraded to another distribution: those will follow updates available in the other distributions. We will explain this behavior with the help of the default priorities set by APT below. Do not hesitate to use `apt-cache policy` (see [_Using apt-cache policy_](https://portal.offsec.com/courses/pen-103-16306/learning/debian-package-management-16831/exercises-16872/kali-multiarch-16993#sidebar.apt-cache-policy)) to verify the given priorities.

Everything relies on the fact that APT only considers packages of higher or equal version than the installed package (assuming that `/etc/apt/preferences` has not been used to force priorities higher than 1000 for some packages).

**Using `apt-cache` policy**

To gain a better understanding of the mechanism of priority, do not hesitate to execute `apt-cache policy` to display the default priority associated with each package source. You can also use `apt-cache policy package` to display the priorities of all available versions of a given package.

Let's assume that you have installed version 1 of a first package from _Kali Rolling_ and that version 2 and 3 are available respectively in _Kali Dev_ and _Debian Unstable_. The installed version has a priority of 100 but the version available in _Kali Rolling_ (the very same) has a priority of 990 (because it is part of the target release). Packages in _Kali Dev_ and _Debian Unstable_ have a priority of 500 (the default priority of a non-installed version). The winner is thus version 1 with a priority of 990. The package stays in _Kali Rolling_.

Let's take the example of another package whose version 2 has been installed from _Kali Dev_. Version 1 is available in _Kali Rolling_ and version 3 in _Debian Unstable_. Version 1 (of priority 990—thus lower than 1000) is discarded because it is lower than the installed version. This only leaves version 2 and 3, both of priority 500. Faced with this alternative, APT selects the newest version, the one from _Debian Unstable_. If you don't want a package installed from _Kali Dev_ to migrate to _Debian Unstable_, you have to assign a priority lower than 500 (490 for example) to packages coming from _Debian Unstable_. You can modify `/etc/apt/preferences` to this effect:

```
Package: *
Pin: release a=unstable
Pin-Priority: 490
```

### 9.3.4. Tracking Automatically Installed Packages

One of the essential functionalities of `apt` is the tracking of packages installed only through dependencies. These packages are called _automatic_ and often include libraries.

With this information, when packages are removed, the package managers can compute a list of automatic packages that are no longer needed (because there are no manually installed packages depending on them). The command `apt autoremove` will get rid of those packages. Aptitude does not have this command because it removes them automatically as soon as they are identified. In all cases, the tools display a clear message listing the affected packages.

It is a good habit to mark as automatic any package that you don't need directly so that they are automatically removed when they aren't necessary anymore. You can use `apt-mark auto package` to mark the given package as automatic, whereas `apt-mark manual package` does the opposite. `aptitude markauto` and `aptitude unmarkauto` work in the same way, although they offer more features for marking many packages at once (see [_Aptitude_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/debian-package-management/basic-package-interaction/installing-packages#sect.aptitude)). The console-based interactive interface of `aptitude` also makes it easy to review the automatic flag on many packages.

You might want to know why an automatically installed package is present on the system. To get this information from the command line, you can use `aptitude why package` (`apt` and `apt-get` have no similar feature):

```
$ aptitude why python-debian
i   aptitude         Recommends apt-xapian-index
i A apt-xapian-index Depends    python-debian (>= 0.1.15)
```

### 9.3.5. Leveraging Multi-Arch Support

All Debian packages have an `Architecture` field in their control information. This field can contain either "`all`" (for packages that are architecture-independent) or the name of the architecture that it targets (like amd64, or armhf). In the latter case, by default, `dpkg` will only install the package if its architecture matches the host's architecture as returned by `dpkg --print-architecture`.

This restriction ensures that you do not end up with binaries compiled for an incorrect architecture. Everything would be perfect except that (some) computers can run binaries for multiple architectures, either natively (an amd64 system can run i386 binaries) or through emulators.

#### Enabling Multi-Arch

Multi-arch support for `dpkg` allows users to define foreign architectures that can be installed on the current system. This is easily done with `dpkg --add-architecture`, as in the example below where the i386 architecture needs to be added to the amd64 system in order to run Microsoft Windows applications using [Wine](https://www.winehq.org/). There is a corresponding `dpkg --remove-architecture` to drop support of a foreign architecture, but it can only be used when no packages of this architecture remain installed.

```
# dpkg --print-architecture
amd64
# wine
it looks like wine32 is missing, you should install it.
multiarch needs to be enabled first.  as root, please
execute "dpkg --add-architecture i386 & apt-get update &
apt-get install wine32"
Usage: wine PROGRAM [ARGUMENTS...]   Run the specified program
       wine --help                   Display this help and exit
       wine --version                Output version information and exit
# dpkg --add-architecture i386
# dpkg --print-foreign-architectures
i386
# apt update
[...]
# apt install wine32
[...]
Setting up libwine:i386 (1.8.6-5) ...
Setting up vdpau-driver-all:i386 (1.1.1-6) ...
Setting up wine32:i386 (1.8.6-5) ...
Setting up libasound2-plugins:i386 (1.1.1-1) ...
Processing triggers for libc-bin (2.24-9)
# wine
Usage: wine PROGRAM [ARGUMENTS...]   Run the specified program
     wine --help                   Display this help and exit
     wine --version                Output version information and exit
# dpkg --remove-architecture i386
dpkg: error: cannot remove architecture 'i386' currently in use by the database
# dpkg --print-foreign-architectures
i386
```

APT will automatically detect when dpkg has been configured to support foreign architectures and will start downloading the corresponding `Packages` files during its update process.

Foreign packages can then be installed with `apt install package:architecture`.

**Using Proprietary i386 Binaries on amd64**

There are multiple use cases for multi-arch, but the most popular one is the possibility to execute 32-bit binaries (i386) on 64-bit systems (amd64), in particular since several popular proprietary applications (like Skype) are only provided in 32-bit versions.

#### Multi-Arch Related Changes

To make multi-arch actually useful and usable, libraries had to be repackaged and moved to an architecture-specific directory so that multiple copies (targeting different architectures) can be installed alongside one another. Such updated packages contain the `Multi-Arch: same` header field to tell the packaging system that the various architectures of the package can be safely co-installed (and that those packages can only satisfy dependencies of packages of the same architecture).

```
$ dpkg -s libwine
dpkg-query: error: --status needs a valid package name but 'libwine' is not: ambiguous package name 'libwine' with more than one installed instance

Use --help for help about querying packages.
$ dpkg -s libwine:amd64 libwine:i386 | grep ^Multi
Multi-Arch: same
Multi-Arch: same
$ dpkg -L libgcc1:amd64 | grep .so
[...]
/usr/lib/x86_64-linux-gnu/wine/libwine.so.1
$ dpkg -S /usr/share/doc/libwine/copyright
libwine:amd64, libwine:i386: /usr/share/doc/libwine/copyright
```

It is worth noting that `Multi-Arch: same` packages must have their names qualified with their architecture to be unambiguously identifiable. These packages may also share files with other instances of the same package; `dpkg` ensures that all packages have bit-for-bit identical files when they are shared. Also, all instances of a package must have the same version, therefore they must be upgraded together.

Multi-Arch support also brings some interesting challenges in the way dependencies are handled. Satisfying a dependency requires either a package marked `Multi-Arch: foreign` or a package whose architecture matches the one of the package declaring the dependency (in this dependency resolution process, architecture-independent packages are assumed to be of the same architecture as the host). A dependency can also be weakened to allow any architecture to fulfill it, with the `package:any` syntax, but foreign packages can only satisfy such a dependency if they are marked `Multi-Arch: allowed`.

### 9.3.6. Validating Package Authenticity

System upgrades are very sensitive operations and you really want to ensure that you only install official packages from the Kali repositories. If the Kali mirror you are using has been compromised, a computer cracker could try to add malicious code to an otherwise legitimate package. Such a package, if installed, could do anything the cracker designed it to do including disclose passwords or confidential information. To circumvent this risk, Kali provides a tamper-proof seal to guarantee—at install time—that a package really comes from its official maintainer and hasn't been modified by a third party.

The seal works with a chain of cryptographic hashes and a signature. The signed file is the `Release` file, provided by the Kali mirrors. It contains a list of the `Packages` files (including their compressed forms, `Packages.gz` and `Packages.xz`, and the incremental versions), along with their MD5, SHA1, and SHA256 hashes, which ensures that the files haven't been tampered with. These `Packages` files contain a list of the Debian packages available on the mirror along with their hashes, which ensures in turn that the contents of the packages themselves haven't been altered either.

The trusted keys are managed with the `apt-key` command found in the `apt` package. This program maintains a keyring of GnuPG public keys, which are used to verify signatures in the `Release.gpg` files available on the mirrors. It can be used to add new keys manually (when non-official mirrors are needed). Generally however, only the official Kali keys are needed. These keys are automatically kept up-to-date by the `kali-archive-keyring` package (which puts the corresponding keyrings in `/etc/apt/trusted.gpg.d`). However, the first installation of this particular package requires caution: even if the package is signed like any other, the signature cannot be verified externally. Cautious administrators should therefore check the fingerprints of imported keys before trusting them to install new packages:

```
# apt-key fingerprint
Warning: apt-key is deprecated. Manage keyring files in trusted.gpg.d instead (see apt-key(8)).
/etc/apt/trusted.gpg.d/debian-archive-buster-automatic.gpg
----------------------------------------------------------
pub   rsa4096 2019-04-14 [SC] [expires: 2027-04-12]
      80D1 5823 B7FD 1561 F9F7  BCDD DC30 D7C2 3CBB ABEE
uid           [ unknown] Debian Archive Automatic Signing Key (10/buster)
sub   rsa4096 2019-04-14 [S] [expires: 2027-04-12]

/etc/apt/trusted.gpg.d/debian-archive-buster-security-automatic.gpg
-------------------------------------------------------------------
pub   rsa4096 2019-04-14 [SC] [expires: 2027-04-12]
      5E61 B217 265D A980 7A23  C5FF 4DFA B270 CAA9 6DFA
uid           [ unknown] Debian Security Archive Automatic Signing Key (10/buster)
sub   rsa4096 2019-04-14 [S] [expires: 2027-04-12]

/etc/apt/trusted.gpg.d/debian-archive-buster-stable.gpg
-------------------------------------------------------
pub   rsa4096 2019-02-05 [SC] [expires: 2027-02-03]
      6D33 866E DD8F FA41 C014  3AED DCC9 EFBF 77E1 1517
uid           [ unknown] Debian Stable Release Key (10/buster)

/etc/apt/trusted.gpg.d/debian-archive-jessie-automatic.gpg
----------------------------------------------------------
pub   rsa4096 2014-11-21 [SC] [expires: 2022-11-19]
      126C 0D24 BD8A 2942 CC7D  F8AC 7638 D044 2B90 D010
uid           [ unknown] Debian Archive Automatic Signing Key (8/jessie)

/etc/apt/trusted.gpg.d/debian-archive-jessie-security-automatic.gpg
-------------------------------------------------------------------
pub   rsa4096 2014-11-21 [SC] [expires: 2022-11-19]
      D211 6914 1CEC D440 F2EB  8DDA 9D6D 8F6B C857 C906
uid           [ unknown] Debian Security Archive Automatic Signing Key (8/jessie)

/etc/apt/trusted.gpg.d/debian-archive-jessie-stable.gpg
-------------------------------------------------------
pub   rsa4096 2013-08-17 [SC] [expires: 2021-08-15]
      75DD C3C4 A499 F1A1 8CB5  F3C8 CBF8 D6FD 518E 17E1
uid           [ unknown] Jessie Stable Release Key

/etc/apt/trusted.gpg.d/debian-archive-stretch-automatic.gpg
-----------------------------------------------------------
pub   rsa4096 2017-05-22 [SC] [expires: 2025-05-20]
      E1CF 20DD FFE4 B89E 8026  58F1 E0B1 1894 F66A EC98
uid           [ unknown] Debian Archive Automatic Signing Key (9/stretch)
sub   rsa4096 2017-05-22 [S] [expires: 2025-05-20]

/etc/apt/trusted.gpg.d/debian-archive-stretch-security-automatic.gpg
--------------------------------------------------------------------
pub   rsa4096 2017-05-22 [SC] [expires: 2025-05-20]
      6ED6 F5CB 5FA6 FB2F 460A  E88E EDA0 D238 8AE2 2BA9
uid           [ unknown] Debian Security Archive Automatic Signing Key (9/stretch)
sub   rsa4096 2017-05-22 [S] [expires: 2025-05-20]

/etc/apt/trusted.gpg.d/debian-archive-stretch-stable.gpg
--------------------------------------------------------
pub   rsa4096 2017-05-20 [SC] [expires: 2025-05-18]
      067E 3C45 6BAE 240A CEE8  8F6F EF0F 382A 1A7B 6500
uid           [ unknown] Debian Stable Release Key (9/stretch)

/etc/apt/trusted.gpg.d/kali-archive-keyring.gpg
-----------------------------------------------
pub   rsa4096 2012-03-05 [SC] [expires: 2023-01-16]
      44C6 513A 8E4F B3D3 0875  F758 ED44 4FF0 7D8D 0BF6
uid           [ unknown] Kali Linux Repository
sub   rsa4096 2012-03-05 [E] [expires: 2023-01-16]
```

When a third-party package source is added to the `sources.list` file, APT needs to be told to trust the corresponding GPG authentication key (otherwise it will keep complaining that it can't ensure the authenticity of the packages coming from that repository). The first step is of course to get the public key. More often than not, the key will be provided as a small text file, which we will call `key.asc` in the following examples.

To add the key to the trusted keyring, the administrator can run `apt-key add < key.asc`. Another way is to use the `synaptic` graphical interface: its Authentication tab in the `Settings → Repositories` menu provides the ability to import a key from the `key.asc` file.

For people who prefer a dedicated application and more details on the trusted keys, it is possible to use `gui-apt-key` (in the package of the same name), a small graphical user interface that manages the trusted keyring.

Once the appropriate keys are in the keyring, APT will check the signatures before any risky operation, so that front-ends will display a warning if asked to install a package whose authenticity can't be ascertained.

## 9.4. APT Package Reference: Digging Deeper into the Debian Package System

Now it is time to dive really deep into Debian and Kali's package system. At this point, we are going to move beyond tools and syntax and focus more on the nuts and bolts of the packaging system. This behind-the-scenes view will help you understand how APT works at its foundation and will give you insight into how to seriously streamline and customize your Kali system. You may not necessarily memorize all the material in this section, but the walk-through and reference material will serve you well as you grow in your mastery of the Kali Linux system.

So far, you have interacted with APT's package data through the various tools designed to interface with it. Next, we will dig deeper and take a look inside the packages and look at the internal _meta-information_ (or information about other information) used by the package management tools.

This combination of a file archive and of meta-information is directly visible in the structure of a `.deb` file, which is simply an `ar` archive, concatenating three files:

```
$ ar t /var/cache/apt/archives/apt_1.4~beta1_amd64.deb
debian-binary
control.tar.gz
data.tar.xz
```

The `debian-binary` file contains a single version number describing the format of the archive:

```
$ ar p /var/cache/apt/archives/apt_1.4~beta1_amd64.deb debian-binary
2.0
```

The `control.tar.gz` archive contains meta-information:

```
$ ar p /var/cache/apt/archives/apt_1.4~beta1_amd64.deb control.tar.gz | tar -tzf -
./
./conffiles
./control
./md5sums
./postinst
./postrm
./preinst
./prerm
./shlibs
./triggers
```

And finally, the `data.tar.xz` archive (the compression format might vary) contains the actual files to be installed on the file system:

```
$ ar p /var/cache/apt/archives/apt_1.4~beta1_amd64.deb data.tar.xz | tar -tJf -
./
./etc/
./etc/apt/
./etc/apt/apt.conf.d/
./etc/apt/apt.conf.d/01autoremove
./etc/apt/preferences.d/
./etc/apt/sources.list.d/
./etc/apt/trusted.gpg.d/
./etc/cron.daily/
./etc/cron.daily/apt-compat
./etc/kernel/
./etc/kernel/postinst.d/
./etc/kernel/postinst.d/apt-auto-removal
./etc/logrotate.d/
./etc/logrotate.d/apt
./lib/
./lib/systemd/
[...]
```

Note that in this example, you are viewing a `.deb` package in APT's archive cache and that your archive may contain files with different version numbers than what is shown.

In this section, we will introduce this meta-information contained in each package and show you how to leverage it.

### 9.4.1. The control File

We will begin by looking at the `control` file, which is contained in the `control.tar.gz` archive. The `control` file contains the most vital information about the package. It uses a structure similar to email headers and can be viewed with the `dpkg -I` command. For example, the `control` file for `apt` looks like this:

```
$ dpkg -I apt_1.4~beta1_amd64.deb control
Package: apt
Version: 1.4~beta1
Architecture: amd64
Maintainer: APT Development Team
Installed-Size: 3478
Depends: adduser, gpgv | gpgv2 | gpgv1, debian-archive-keyring, init-system-helpers (>= 1.18~), libapt-pkg5.0 (>= 1.3~rc2), libc6 (>= 2.15), libgcc1 (>= 1:3.0), libstdc++6 (>= 5.2)
Recommends: gnupg | gnupg2 | gnupg1
Suggests: apt-doc, aptitude | synaptic | wajig, dpkg-dev (>= 1.17.2), powermgmt-base, python-apt
Breaks: apt-utils (<< 1.3~exp2~)
Replaces: apt-utils (<< 1.3~exp2~)
Section: admin
Priority: important
Description: commandline package manager
 This package provides commandline tools for searching and
 managing as well as querying information about packages
 as a low-level access to all features of the libapt-pkg library.
 .
 These include:
  * apt-get for retrieval of packages and information about them
    from authenticated sources and for installation, upgrade and
    removal of packages together with their dependencies
  * apt-cache for querying available information about installed
    as well as installable packages
  * apt-cdrom to use removable media as a source for packages
  * apt-config as an interface to the configuration settings
  * apt-key as an interface to manage authentication keys
```

In this section, we will walk you through the control file and explain the various fields. Each of these will give you a better understanding of the packaging system, give you more fine-tuned configuration control, and provide you with insight needed to troubleshoot problems that may occur.

#### Dependencies: the Depends Field

The package dependencies are defined in the `Depends` field in the package header. This is a list of conditions to be met for the package to work correctly—this information is used by tools such as `apt` in order to install the required libraries, in appropriate versions fulfilling the dependencies of the package to be installed. For each dependency, you can restrict the range of versions that meet that condition. In other words, it is possible to express the fact that you need the package libc6 in a version equal to or greater than "2.15" (written "`libc6 (>= 2.15)`"). Version comparison operators are as follows:

- `<<` - less than.
- `<=` - less than or equal to.
- `=` - equal to (note that "`2.6.1`" is not equal to "`2.6.1-1`").
- `>=` - greater than or equal to.
- `>>` - greater than.

In a list of conditions to be met, the comma serves as a separator, interpreted as a logical "AND." In conditions, the vertical bar ("|") expresses a logical "OR" (it is an inclusive "OR," not an exclusive "either/or"). Carrying greater priority than "AND," you can use it as many times as necessary. Thus, the dependency "(A OR B) AND C" is written `A | B, C`. In contrast, the expression "A OR (B AND C)" should be written as "(A OR B) AND (A OR C)", since the `Depends` field does not tolerate parentheses that change the order of priorities between the logical operators "OR" and "AND". It would thus be written `A | B, A | C`. See [https://www.debian.org/doc/debian-policy/ch-relationships.html](https://www.debian.org/doc/debian-policy/ch-relationships.html) for more information.

The dependencies system is a good mechanism for guaranteeing the operation of a program but it has another use with metapackages. These are empty packages that only describe dependencies. They facilitate the installation of a consistent group of programs preselected by the metapackage maintainer; as such, `apt install metapackage` will automatically install all of these programs using the metapackage's dependencies. The `gnome`, `kali-tools-wireless`, and `kali-linux-large` packages are examples of metapackages. For more information on Kali's metapackages, see [https://tools.kali.org/kali-metapackages](https://tools.kali.org/kali-metapackages)

#### Pre-Depends, a More Demanding Depend

Pre-dependencies, which are listed in the `Pre-Depends` field in the package headers, complete the normal dependencies; their syntax is identical. A normal dependency indicates that the package in question must be unpacked and configured before configuration of the package declaring the dependency. A pre-dependency stipulates that the package in question must be unpacked and configured before execution of the pre-installation script of the package declaring the pre-dependency, that is before its installation.

A pre-dependency is very demanding for `apt` because it adds a strict constraint on the ordering of the packages to install. As such, pre-dependencies are discouraged unless absolutely necessary. It is even recommended to consult other developers on `debian-devel@lists.debian.org` before adding a pre-dependency as it is generally possible to find another solution as a work-around.

#### Recommends, Suggests, and Enhances Fields

The `Recommends` and `Suggests` fields describe dependencies that are not compulsory. The recommended dependencies, the most important, considerably improve the functionality offered by the package but are not indispensable to its operation. The suggested dependencies, of secondary importance, indicate that certain packages may complement and increase their respective utility, but it is perfectly reasonable to install one without the others.

You should always install the recommended packages unless you know exactly why you do not need them. Conversely, it is not necessary to install suggested packages unless you know why you need them.

The `Enhances` field also describes a suggestion, but in a different context. It is indeed located in the suggested package, and not in the package that benefits from the suggestion. Its interest lies in that it is possible to add a suggestion without having to modify the package that is concerned. Thus, all add-ons, plug-ins, and other extensions of a program can then appear in the list of suggestions related to the software. Although it has existed for several years, this last field is still largely ignored by programs such as `apt` or `synaptic`. The original goal was to let a package like `xul-ext-adblock-plus` (a Firefox extension) declare `Enhances: firefox, firefox-esr` and thus appear in the list of suggested packages associated to `firefox` and `firefox-esr`.

#### Conflicts: the Conflicts Field

The `Conflicts` field indicates when a package cannot be installed simultaneously with another. The most common reasons for this are that both packages include a file of the same name, provide the same service on the same transmission control protocol (TCP) port, or would hinder each other's operation.

If it triggers a conflict with an already installed package, `dpkg` will refuse to install a package, except if the new package specifies that it will replace the installed package, in which case `dpkg` will choose to replace the old package with the new one. APT always follows your instructions: if you choose to install a new package, it will automatically offer to uninstall the package that poses a problem.

#### Incompatibilities: the Breaks Field

The `Breaks` field has an effect similar to that of the `Conflicts` field, but with a special meaning. It signals that the installation of a package will break another package (or particular versions of it). In general, this incompatibility between two packages is transitory and the `Breaks` relationship specifically refers to the incompatible versions.

When a package breaks an already installed package, `dpkg` will refuse to install it, and `apt` will try to resolve the problem by updating the package that would be broken to a newer version (which is assumed to be fixed and, thus, compatible again).

This type of situation may occur in the case of updates without backwards compatibility: this is the case if the new version no longer functions with the older version and causes a malfunction in another program without making special provisions. The `Breaks` field helps prevent these types of problems.

#### Provided Items: the Provides Field

This field introduces the very interesting concept of a _virtual package_. It has many roles, but two are of particular importance. The first role consists in using a virtual package to associate a generic service with it (the package provides the service). The second indicates that a package completely replaces another and that for this purpose, it can also satisfy the dependencies that the other would satisfy. It is thus possible to create a substitution package without having to use the same package name.

**Metapackage and Virtual Package**

It is essential to clearly distinguish metapackages from virtual packages. The former are real packages (including real `.deb` files), whose only purpose is to express dependencies.

Virtual packages, however, do not exist physically; they are only a means of identifying real packages based on common, logical criteria (for example, service provided, or compatibility with a standard program or a pre-existing package).

##### Providing a Service

Let's discuss the first case in greater detail with an example: all mail servers, such as `postfix` or `sendmail` are said to provide the `mail-transport-agent` virtual package. Thus, any package that needs this service to be functional (e.g. a mailing list manager, such as smartlist or sympa) simply states in its dependencies that it requires a `mail-transport-agent` instead of specifying a large yet incomplete list of possible solutions. Furthermore, it is useless to install two mail servers on the same machine, which is why each of these packages declares a conflict with the `mail-transport-agent` virtual package. A conflict between a package and itself is ignored by the system, but this technique will prohibit the installation of two mail servers side by side.

##### Interchangeability with Another Package

The `Provides` field is also interesting when the content of a package is included in a larger package. For example, the `libdigest-md5-perl` Perl module was an optional module in Perl 5.6, and has been integrated as standard in Perl 5.8. As such, the package `perl` has since version 5.8 declared `Provides: libdigest-md5-perl` so that the dependencies on this package are met if the system has Perl 5.8 (or newer). The `libdigest-md5-perl` package itself was deleted, since it no longer had any purpose when old Perl versions were removed.

![Figure 3: Use of a Provides Field in Order to Not Break Dependencies](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/a5915a24709751dff74fdbb8f83e4005-09_virtual-package.png)

Figure 3: Use of a Provides Field in Order to Not Break Dependencies

This feature is very useful, since it is never possible to anticipate the vagaries of development and it is necessary to be able to adjust to renaming, and other automatic replacement, of obsolete software.

#### Replacing Files: The Replaces Field

The `Replaces` field indicates that the package contains files that are also present in another package, but that the package is legitimately entitled to replace them. Without this specification, `dpkg` fails, stating that it cannot overwrite the files of another package (technically, it is possible to force it to do so with the `--force-overwrite` option, but that is not considered standard operation). This allows identification of potential problems and requires the maintainer to study the matter prior to choosing whether to add such a field.

The use of this field is justified when package names change or when a package is included in another. This also happens when the maintainer decides to distribute files differently among various binary packages produced from the same source package: a replaced file no longer belongs to the old package, but only to the new one.

If all of the files in an installed package have been replaced, the package is considered to be removed. Finally, this field also encourages `dpkg` to remove the replaced package where there is a conflict.

### 9.4.2. Configuration Scripts

In addition to the `control` file, the `control.tar.gz` archive for each Debian package may contain a number of scripts (`postinst`, `postrm`, `preinst`, `prerm`) called by `dpkg` at different stages in the processing of a package. We can use `dpkg -I` to show these files as they reside in a `.deb` package archive:

```
$ dpkg -I /var/cache/apt/archives/zsh_5.3-1_amd64.deb | head
 new debian package, version 2.0.
 size 814486 bytes: control archive=2557 bytes.
     838 bytes,    20 lines      control
    3327 bytes,    43 lines      md5sums
     969 bytes,    41 lines   *  postinst             #!/bin/sh
     348 bytes,    20 lines   *  postrm               #!/bin/sh
     175 bytes,     5 lines   *  preinst              #!/bin/sh
     175 bytes,     5 lines   *  prerm                #!/bin/sh
 Package: zsh
 Version: 5.3-1
$ dpkg -I zsh_5.3-1_amd64.deb preinst
#!/bin/sh
set -e
# Automatically added by dh_installdeb
dpkg-maintscript-helper symlink_to_dir /usr/share/doc/zsh zsh-common 5.0.7-3 -- "$@"
# End automatically added section
```

The [Debian Policy](https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html) describes each of these files in detail, specifying the scripts called and the arguments they receive. These sequences may be complicated, since if one of the scripts fails, `dpkg` will try to return to a satisfactory state by canceling the installation or removal in progress (insofar as it is possible).

**The `pkg` Database**

You can traverse the `dpkg` database on the filesystem at `/var/lib/dpkg/`. This directory contains a running record of all the packages that have been installed on the system. All of the configuration scripts for installed packages are stored in the `/var/lib/dpkg/info/` directory, in the form of a file prefixed with the package's name:

```
$ ls /var/lib/dpkg/info/zsh.*
/var/lib/dpkg/info/zsh.list
/var/lib/dpkg/info/zsh.md5sums
/var/lib/dpkg/info/zsh.postinst
/var/lib/dpkg/info/zsh.postrm
/var/lib/dpkg/info/zsh.preinst
/var/lib/dpkg/info/zsh.prerm
```

This directory also includes a file with the `.list` extension for each package, containing the list of files that belong to that package:

```
$ head /var/lib/dpkg/info/zsh.list
/.
/bin
/bin/zsh
/bin/zsh5
/usr
/usr/lib
/usr/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu/zsh
/usr/lib/x86_64-linux-gnu/zsh/5.2
/usr/lib/x86_64-linux-gnu/zsh/5.2/zsh
[...]
```

The `/var/lib/dpkg/status` file contains a series of data blocks (in the format of the famous mail headers request for comment, RFC 2822) describing the status of each package. The information from the `control` file of the installed packages is also replicated there.

```
$ more /var/lib/dpkg/status
Package: gnome-characters
Status: install ok installed
Priority: optional
Section: gnome
Installed-Size: 1785
Maintainer: Debian GNOME Maintainers
Architecture: amd64
Version: 3.20.1-1
[...]
```

Let's discuss the configuration files and see how they interact. In general, the `preinst` script is executed prior to installation of the package, while the `postinst` follows it. Likewise, `prerm` is invoked before removal of a package and `postrm` afterwards. An update of a package is equivalent to removal of the previous version and installation of the new one. It is not possible to describe in detail all the possible scenarios here but we will discuss the most common two: an installation/update and a removal.

These sequences can be quite confusing, but a visual representation may help. [Manoj Srivastava made some diagrams](https://people.debian.org/~srivasta/MaintainerScripts.html) explaining how the configuration scripts are called by `dpkg`. [Similar diagrams have also been developed by the Debian Women project](https://wiki.debian.org/MaintainerScripts) ; they are a bit simpler to understand, but less complete.

**Caution: Symbolic Names of the Scripts**

The sequences described in this section call configuration scripts by specific names, such as `old-prerm` or `new-postinst`. They are, respectively, the `prerm` script contained in the old version of the package (installed before the update) and the `postinst` script contained in the new version (installed by the update).

#### Installation and Upgrade Script Sequence

Here is what happens during an installation (or an update):

1. For an update, `dpkg` calls the `old-prerm upgrade new-version`.
2. Still for an update, `dpkg` then executes `new-preinst upgrade old-version`; for a first installation, it executes `new-preinst install`. It may add the old version in the last parameter if the package has already been installed and removed (but not purged, the configuration files having been retained).
3. The new package files are then unpacked. If a file already exists, it is replaced, but a backup copy is made and temporarily stored.
4. For an update, `dpkg` executes `old-postrm upgrade new-version`.
5. `dpkg` updates all of the internal data (file list, configuration scripts, etc.) and removes the backups of the replaced files. This is the point of no return: `dpkg` no longer has access to all of the elements necessary to return to the previous state.
6. `dpkg` will update the configuration files, prompting you to decide if it is unable to automatically manage this task. The details of this procedure are discussed in [_Checksums, Conffiles_](https://portal.offsec.com/courses/pen-103-16306/learning/debian-package-management-16831/exercises-16872/kali-multiarch-16993#sect.conffiles).
7. Finally, `dpkg` configures the package by executing `new-postinst configure last-version-configured`.

#### Package Removal

Here is what happens during a package removal.

1. `dpkg` calls `prerm remove`.
2. `dpkg` removes all of the package's files, with the exception of the configuration files and configuration scripts.
3. `dpkg` executes `postrm remove`. All of the configuration scripts, except `postrm`, are removed. If you have not used the purge option, the process stops here.
4. For a complete purge of the package (command issued with `dpkg --purge` or `dpkg -P`), the configuration files are also deleted, as well as a certain number of copies (`*.dpkg-tmp`, `*.dpkg-old`, `*.dpkg-new`) and temporary files; `dpkg` then executes `postrm purge`.

In some cases, a package might use `debconf` to require configuration information from you: the four scripts detailed above are then complemented by a `config` script designed to acquire that information. During installation, this script defines in detail what questions `debconf` will ask. The responses are recorded in the `debconf` database for future reference. The script is generally executed by `apt` prior to installing packages one by one in order to group all the questions together at the beginning of the process. The pre- and post-installation scripts can then use this information to operate according to your wishes.

**The `debconf` Tool**

The `debconf` tool was created to resolve a recurring problem in Debian. All Debian packages unable to function without a minimum of configuration used to ask questions with calls to the `echo` and `read` commands in `postinst` shell scripts (and other similar scripts). This forced the installer to babysit large installations or updates in order to respond to various configuration queries as they arose. These manual interactions have now been almost entirely dispensed with, thanks to `debconf`.

The `debconf` tool has many interesting features: It requires the developer to specify user interaction; it allows localization of all the displayed strings (all translations are stored in the `templates` file describing the interactions); it provides different frontends for questions (text mode, graphical mode, non-interactive); and it allows creation of a central database of responses to share the same configuration with several computers. The most important feature is that all of the questions can be presented in a row, all at once, prior to starting a long installation or update process. Now, you can go about your business while the system handles the installation on its own, without having to stay there staring at the screen, waiting for questions to pop up.

### 9.4.3. Checksums, Conffiles

In addition to the maintainer scripts and control data already mentioned in the previous sections, the `control.tar.gz` archive of a Debian package may contain other interesting files:

```
# ar p /var/cache/apt/archives/bash_4.4-2_amd64.deb control.tar.gz | tar -tzf -
./
./conffiles
./control
./md5sums
./postinst
./postrm
./preinst
./prerm
```

The first—**md5sums**—contains the MD5 checksums for all of the package's files. Its main advantage is that it allows `dpkg --verify` to check if these files have been modified since their installation. Note that when this file doesn't exist, `dpkg` will generate it dynamically at installation time (and store it in the dpkg database just like other control files).

`conffiles` lists package files that must be handled as configuration files. Configuration files can be modified by the administrator, and `dpkg` will try to preserve those changes during a package update.

In effect, in this situation, `dpkg` behaves as intelligently as possible: if the standard configuration file has not changed between the two versions, it does nothing. If, however, the file has changed, it will try to update this file. Two cases are possible: either the administrator has not touched this configuration file, in which case `dpkg` automatically installs the new version; or the file has been modified, in which case `dpkg` asks the administrator which version they wish to use (the old one with modifications, or the new one provided with the package). To assist in making this decision, `dpkg` offers to display a `diff` that shows the difference between the two versions. If you choose to retain the old version, the new one will be stored in the same location in a file with the `.dpkg-dist` suffix. If you choose the new version, the old one is retained in a file with the `.dpkg-old` suffix. Another available action consists of momentarily interrupting `dpkg` to edit the file and attempt to reinstate the relevant modifications (previously identified with `diff`).

`dpkg` handles configuration file updates, but, while doing so, regularly interrupts its work to ask for input from the administrator. This can be time consuming and inconvenient. Fortunately, you can instruct `dpkg` to respond to these prompts automatically. The `--force-confold` option retains the old version of the file, while `--force-confnew` will use the new version. These choices are respected, even if the file has not been changed by the administrator, which only rarely has the desired effect. Adding the `--force-confdef` option tells `dpkg` to decide by itself when possible (in other words, when the original configuration file has not been touched), and only uses `--force-confnew` or `--force-confold` for other cases.

These options apply to `dpkg`, but most of the time the administrator will work directly with the `aptitude` or `apt` programs. It is, thus, necessary to know the syntax used to indicate the options to pass to the `dpkg` command (their command line interfaces are very similar).

```
# apt -o DPkg::options::="--force-confdef" -o DPkg::options::="--force-confold" full-upgrade
```

These options can be stored directly in `apt`'s configuration. To do so, simply write the following line in the `/etc/apt/apt.conf.d/local` file:

```
DPkg::options { "--force-confdef"; "--force-confold"; }
```

Including this option in the configuration file means that it will also be used in a graphical interface such as `aptitude`.

Conversely, you can also force `dpkg` to ask configuration file questions. The `--force-confask` option instructs `dpkg` to display the questions about the configuration files, even in cases where they would not normally be necessary. Thus, when reinstalling a package with this option, `dpkg` will ask the questions again for all of the configuration files modified by the administrator. This is very convenient, especially for reinstalling the original configuration file if it has been deleted and no other copy is available: a normal re-installation won't work, because `dpkg` considers removal as a form of legitimate modification, and, thus, doesn't install the desired configuration file.

## 9.5. Summary

In this section, we learned more about the Debian package system, discussed the Advanced Package Tool (APT) and `dpkg`, learned about basic package interaction, advanced APT configuration and usage, and dug deeper into the Debian package system with a brief reference of the `.deb` file format. We looked at the `control` file, configuration scripts, checksums, and the `conffiles` file.

Summary Tips:

A Debian package is a compressed archive of a software application. It contains the application's files as well as other metadata including the names of the dependencies that the application needs plus any scripts that enable the execution of commands at different stages in the package's lifecycle (installation, removal, upgrades).

The `dpkg` tool, contrary to `apt` and `apt-get` (of the APT family), has no knowledge of all the available packages that could be used to fulfill package dependencies. Thus, to manage Debian packages, you will likely use the latter tools as they are able to automatically resolve dependency issues.

You can use APT to install and remove applications, update packages, and even upgrade your entire system. Here are the key points that you should know about APT and its configuration:

- The `sources.list` file is the key configuration file for defining package sources (or repositories that contain packages).
- Debian and Kali use three sections to differentiate packages according to the licenses chosen by the authors of each work: `main` contains all packages that fully comply with the [Debian Free Software Guidelines](https://www.debian.org/social_contract#guidelines); `non-free` contains software that does not (entirely) conform to the Free Software Guidelines but can nevertheless be distributed without restrictions; and `contrib` (contributions) includes open source software that cannot function without some non-free elements.
- Kali maintains several repositories including: `kali-rolling`, which is the main repository for end-users and should always contain installable and recent packages; and `kali-dev`, which is used by Kali developers and is not for public use.
- When working with APT, you should first download the list of currently-available packages with `apt update`.
- You can add a package to the system with a simple `apt install package`. APT will automatically install the necessary dependencies.
- To remove a package use `apt remove package`. It will also remove the reverse dependencies of the package (i.e. packages that depend on the package to be removed).
- To remove all data associated with a package, you can "purge" the package with the `apt purge package` command. Unlike a removal, this will not only remove the package but also its configuration files and sometimes the associated user data.

We recommend regular upgrades to install the latest security updates. To upgrade, use `apt update` followed by either `apt upgrade`, `apt-get upgrade`, or `aptitude safe-upgrade`. These commands look for installed packages that can be upgraded without removing any packages.

For more important upgrades, such as major version upgrades, use `apt full-upgrade`. With this instruction, `apt` will complete the upgrade even if it has to remove some obsolete packages or install new dependencies. This is also the command that you should use for regular upgrades of your Kali Rolling system. Review the pros and cons of updates we outlined in this chapter.

Several tools can be used to inspect Debian packages:

- `dpkg --listfiles package` (or `-L`) - lists the files that were installed by the specified package.
- `dpkg --search file` (or `-S`) - finds any packages containing the file or path passed in the argument.
- `dpkg --list` (or `-l`) - displays the list of packages known to the system and their installation status.
- `dpkg --contents file.deb` (or `-c`) - lists all the files in a particular `.deb` file.
- `dpkg --info file.deb` (or `-I`) - displays the headers of the specified `.deb` file.
- The various `apt-cache` subcommands display much of the information stored in APT's internal database.

To avoid excessive disk usage, you should regularly sort through `/var/cache/apt/archives/`. Two commands can be used for this: `apt clean` (or `apt-get clean`) entirely empties the directory; `apt autoclean` (`apt-get autoclean`) only removes packages that can no longer be downloaded because they have disappeared from the mirror and are therefore useless.

`aptitude` is an interactive program that can be used in semi-graphical mode on the console. It is an extremely robust program that can help you install and troubleshoot packages.

`synaptic` is a graphical package manager that features a clean and efficient graphical interface.

As an advanced user, you can create files in `/etc/apt/apt.conf.d/` to configure certain aspects of APT. You can also manage package priorities, track automatically installed packages, work with several distributions or architectures at once, use cryptographic signatures to validate packages, and upgrade files using the techniques outlined in this chapter.

In spite of the Debian or Kali maintainers' best efforts, a system upgrade isn't always as smooth as we would hope. When this happens, you can look at the [Kali bug tracker](https://bugs.kali.org/) and at the [Debian bug tracking system](https://bugs.debian.org/) at `https://bugs.debian.org/package` to check whether the problem has already been reported. You can also try to downgrade the package or to debug and repair a failed package maintainer script.

### 9.6.1. Mirror redirection

#### Exercise:

1. Find out which mirror would serve your ISO download request, if you were to try to download a Kali ISO from [cdimage.kali.org](https://cdimage.kali.org/).
2. Configure a source entry in your sources.list file. Update your package cache.
3. Add the kali-bleeding-edge repository to your system and install the bleeding-edge version of the `set` package

---

#### Exercise solution:

1. Check the mirror with:

```
kali@kali:~$ curl -sI https://cdimage.kali.org/README
kali@kali:~$
```

2. Ensure source repositories are enabled through this line in /etc/apt/sources.list:

```
deb-src https://http.kali.org/kali kali-rolling main contrib non-free
```

If it is commented out, uncomment the line.

3. To enable the kali-bleeding edge repos, add this line to /etc/apt/sources.list:

```
deb https://http.kali.org/kali kali-bleeding-edge contrib non-free main
```

Next, sync with apt-get update:

```
kali@kali:~$ sudo apt-get update
kali@kali:~$
```

Then install the bleeding edge version of set:

```
kali@kali:~$ sudo apt install set/kali-bleeding-edge
kali@kali:~$
```

### 9.6.2. Getting to know dpkg

#### Exercise:

1. Find the path to the `atk6-alive6` binary.
2. Determine the package that installed it and the other files included in the package.
3. Search for locally installed packages which have "wifi" in their name.
4. Search for tools in the Kali repository which have "wifi" in their name.
5. List the installed files which originated from the **nmap** package.

---

#### Exercise solution:

1. Find the path:

```
kali@kali:~$ which atk6-alive6
kali@kali:~$
```

2. Determine what installed atk-alive6 and other files include in the package:

```
kali@kali:~$ sudo dpkg -S atk6-alive6
kali@kali:~$
```

3. Search for locally install packages with "wifi" in the name:

```
kali@kali:~$ dpkg -l | grep wifi
kali@kali:~$
```

4. Search for tools in the Kali repository which have "wifi" in their name:

```
kali@kali:~$ sudo apt-cache search wifi | grep wifi
kali@kali:~$
```

5. List the files that originated from the nmap package:

```
kali@kali:~$ sudo dpkg -L nmap
kali@kali:~$
```

### 9.6.3. Playing with dpkg-deb

#### Exercise:

In this exercise, we want to install Nessus. Nessus is not a simple apt-get installation. It is a process:

1. Downloading the .deb file from Nessus
2. Install .deb with dpkg
3. Register Nessus and get an activation code by email
4. Generate a challenge code with nessuscli in Kali
5. Submit the challenge and activation to get access to plugins
6. Download plugins and install them

This is a long process and isn't simple. Using the skills we demonstrated in this chapter, download and install Nessus and create a package that includes the plugins and installs them, automatically.

1. Find, download, install and register the Free Nessus Debian package.
2. Instead of programmatically installing the plugins through the Nessus web interface, save the plugins to a local file.
3. Slipstream the signatures into the Nessus **.deb** package so that you will be able to install Nessus (say across multiple computers), without having each computer re-download the signatures.
4. Create a new Nessus **.deb** package that automatically installs the plugins.

---

#### Exercise solution:

First, you'll have to install Nessus the "standard" way. There are lots of steps. [This video solution](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses//KLR/videos/5dfd49fe8125e92303059981dc2b280c-Nessus-1280-fixed-1.mp4) shows the process in more detail.

The details for the packages are on [this page](https://www.tenable.com/downloads/nessus#tos) and [this page](https://docs.tenable.com/nessus/Content/OfflineUpdatePageDetails.htm).

Next, with Nessus properly installed, we can modify the package.

1. Extract the package. Are you copy and pasting? _Note that your version numbers may differ._

```
kali@kali:~/Downloads$ sudo dpkg-deb -R Nessus-6.9.0-debian6_amd64.deb nessus #Raw extract the package
```

2. List the contents of the package:

```
kali@kali:~$ ls -lR ./nessus
kali@kali:~$
```

4. Copy the plugins file to **nessus/opt/nessus/var/nessus**:

```
kali@kali:~$ cp ~/Downloads/all-2.0.tar.gz nessus/opt/nessus/var/nessus
kali@kali:~$
```

Edit the Debian postinst file, find this section, make changes as appropriate:

```
kali@kali:~$ nano nessus/DEBIAN/postinst
kali@kali:~$
```

5. Edit the postinst file to import the offline signatures. Add somewhere in **postinst**:

```
echo "UBERHAX - Updating plugins from local file..."
rm -f ${NESSUS_PREFIX}/lib/nessus/plugins/MD5
${NESSUS_PREFIX}/sbin/nessuscli update ${NESSUS_PREFIX}/var/nessus/all-2.0.tar.gz
${NESSUS_PREFIX}/sbin/nessusd -R

test -f ${NESSUS_PREFIX}/etc/nessus/nessus-fetch.rc && {
        echo "Fetching the newest plugins from nessus.org..."
        rm -f ${NESSUS_PREFIX}/lib/nessus/plugins/MD5
        ${NESSUS_PREFIX}/sbin/nessuscli update --plugins-only
        ${NESSUS_PREFIX}/sbin/nessusd -R
}
```

Let's clean up after ourselves by deleting the signature file to save space. We will do this in the **postrm** file:

```
kali@kali:~$ rm -f ${NESSUS_PREFIX}/var/nessus/all-2.0.tar.gz
kali@kali:~$
```

Repackage the deb file. Your version may vary:

```
kali@kali:~$ dpkg-deb -b nessus nessus_6.9.0_amd64.deb
kali@kali:~$
```

### 9.6.4. Kali multiarch

This will be a fun exercise because it is fairly simple, uses some of the package commands you've learned and allows you to run Windows programs from within Kali, thanks to Wine. However, it may sound a lot more complicated than it is because you will have to install a foreign architecture (i386).

#### Exercise:

1. Add the 32-bit architecture option to your Kali instance using dpkg.
2. Install wine32
3. Run the Windows [ipscan](https://kali.training/downloads/ipscan221.exe) program using Wine.

---

#### Exercise solution:

The solution is fairly straight-forward. However, do not miss the i386 command. This is the turning point of the exercise, where we operate in a shell that imitates the i386 environment.

```
kali@kali:~$ sudo apt install wine
kali@kali:~$
kali@kali:~$ wine
it looks like wine32 is missing, you should install it.
multiarch needs to be enabled first.  With sudo, please
execute "dpkg --add-architecture i386 && apt-get update &&
apt-get install wine32"
Usage: wine PROGRAM [ARGUMENTS...]   Run the specified program
       wine --help                   Display this help and exit
       wine --version                Output version information and exit
kali@kali:~$
kali@kali:~$ sudo dpkg --print-architecture
kali@kali:~$
kali@kali:~$ sudo dpkg --add-architecture i386
kali@kali:~$
kali@kali:~$ sudo dpkg --print-foreign-architectures
kali@kali:~$
kali@kali:~$ i386 # change architecture in new program environment
$
$ sudo apt update
$
$ sudo apt install wine32
$
$ wget https://sourceforge.net/projects/ipscan/files/ipscan2-binary/2.21/ipscan221.exe/download -O ipscan221.exe
$
$ wine ipscan221.exe
```

![Figure 4: wine](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/fbf57934e70e394ffdc1f8682be3240c-wine-1.png)

Figure 4: wine

---

#### Questions

Run the following command:

`apt-cache search nmap`

Why is the tool "atac" in the results?

---

#### Answers:

This is due to the long description of the package.

Next Module -> 