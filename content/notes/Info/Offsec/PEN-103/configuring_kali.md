---
title: Configuring Kali Linux 🛸
tags:
  - Offsec
  - PEN-103
---
- *All the info was extracted from [Offsec, Pen-103](https://portal.offsec.com/courses/pen-103-16306/)*, under the following [licencese](https://creativecommons.org/licenses/by-sa/3.0/)

# 6. Configuring Kali Linux

In this chapter, we will take a look at various ways you can configure Kali Linux. First, in [_Configuring the Network_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/configuring-kali-linux/configuring-the-network/on-the-desktop-with-network-manager), we will show you how to configure your network settings using a graphical environment and the command line. In [_Managing Unix Users and Unix Groups_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/configuring-kali-linux/managing-unix-users-and-unix-groups/managing-unix-users-and-unix-groups), we will talk about users and groups, showing you how to create and modify user accounts, set passwords, disable accounts, and manage groups. Finally, we will discuss services in [_Configuring Services_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/configuring-kali-linux/configuring-services/configuring-a-specific-program) and explain how to set up and maintain generic services and also focus on three very important and specific services: SSH, PostgreSQL, and Apache.

### 6.1.1. On the Desktop with NetworkManager

In a typical desktop installation, you'll have _NetworkManager_ already installed and it can be controlled and configured through Xfce's system settings and through the top-right menu as shown in Figure 1.

![Figure 1: Network Configuration Screen](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/6c208c0d172cb807c97b755bd65bbc18-06_network_manager.png)

Figure 1: Network Configuration Screen

The default network configuration relies on DHCP to obtain an IP address, DNS server, and gateway, but you can use the gear icon in the lower-left corner to alter the configuration in many ways (for example: set the MAC address, switch to a static setup, enable or disable IPv6, and add additional routes). You can create profiles to save multiple wired network configurations and easily switch between them. For wireless networks, their settings are automatically tied to their public identifier (SSID).

NetworkManager also handles connections by mobile broadband (Wireless Wide Area Network WWAN) and by modems using point-to-point protocol over ethernet (PPPoE). Last but not least, it provides integration with many types of virtual private networks (VPN) through dedicated plugins: SSH, OpenVPN, Cisco's VPNC, PPTP, Strongswan. Check out the _network-manager-*_ packages; most of them are not installed by default.

### 6.1.2. On the Command Line with Ifupdown

Alternatively, when you prefer not to use (or don't have access to) a graphical desktop, you can configure the network with the already-installed `ifupdown` package, which includes the `ifup` and `ifdown` tools. These tools read definitions from the `/etc/network/interfaces` configuration file and are at the heart of the `/etc/init.d/networking` init script that configures the network at boot time.

#### Using sudo to access Administrative Privileges

The `sudo` (super user do) command allows privileged users to run commands with administrative permissions. This gives full access to items that may be restricted to only the root user, such as programs in `/sbin/` or access to network options that are useful for common penetration testing tools.

The command takes one argument, being the subsequent command that will be run with administrative permissions. One useful use case when dealing with services is to elevate to the root user account. To elevate to root user, we will use the command `su` (substitute user) to create a shell under the root user. The substitute user command takes a user account as an argument. Additionally, the `su` command has a useful flag (`--login`, or `-l`, or `-`) to use the substituted user's login environment. Multiple commands in the following chapter require the use of `sudo`, as such we will elevate to the root user to seamlessly execute these commands.

```
$ sudo su --login
[sudo] password for kali:
root@kali:~#
```

Each network device managed by _ifupdown_ can be deconfigured at any time with `ifdown network-device`. You can then modify `/etc/network/interfaces` and bring the network back up (with the new configuration) with `ifup network-device`.

Let's take a look at what we can put in ifupdown's configuration file. There are two main directives: `auto network-device`, which tells _ifupdown_ to automatically configure the network interface once it is available, and `iface network-device inet/inet6 type` to configure a given interface. For example, a plain DHCP configuration looks like this:

```
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
```

Note that the special configuration for the loopback device should always be present in this file. For a fixed IP address configuration, you have to provide more details such as the IP address, the network, and the IP of the gateway:

```
auto eth0
iface eth0 inet static
address 192.168.0.3
netmask 255.255.255.0
broadcast 192.168.0.255
network 192.168.0.0
gateway 192.168.0.1
```

For wireless interfaces, you must have the `wpasupplicant` package (included in Kali by default), which provides many `wpa-*` options that can be used in `/etc/network/interfaces`. Have a look at `/usr/share/doc/wpasupplicant/README.Debian.gz` for examples and explanations. The most common options are `wpa-ssid` (which defines the name of the wireless network to join) and `wpa-psk` (which defines the passphrase or the key protecting the network).

```
iface wlan0 inet dhcp
wpa-ssid MyNetWork
wpa-psk plaintextsecret
```

### 6.1.3. On the Command Line with systemd-networkd

While _ifupdown_ is the historical tool used by Debian and Kali, and while it is still the default for minimal installations, there is a newer tool worth considering: _systemd-networkd_. Its integration with the _systemd_ init system makes it a very attractive choice. It is not specific to Debian-based distributions (contrary to _ifupdown_) and has been designed to be very small, efficient, and relatively easy to configure if you understand the syntax of systemd unit files. This is an especially attractive choice if you consider _NetworkManager_ bloated and hard to configure.

You configure `systemd-networkd` by placing `.network` files into the `/etc/systemd/network/` directory. Alternatively, you can use `/lib/systemd/network/` for packaged files or `/run/systemd/network/` for files generated at run-time. The format of those files is documented in systemd.network(5) (see [_Manual Pages_](https://portal.offsec.com/courses/pen-103-16306/learning/configuring-kali-linux-16830/exercises-16873/getting-help.html#sect.manual-pages)). The [`Match`] section indicates the network interfaces the configuration applies to. You can specify the interface in many ways, including by media access control (MAC) address or device type. The [`Network`] section defines the network configuration.

**Example 5.1. Static Configuration in `/etc/systemd/network/50-static.network`**

```
[Match]
Name=enp2s0

[Network]
Address=192.168.0.15/24
Gateway=192.168.0.1
DNS=8.8.8.8
```

**Example 5.2. DHCP-based Configuration in `/etc/systemd/network/80-dhcp.network`**

```
[Match]
Name=en*

[Network]
DHCP=yes
```

Note that `system-networkd` is disabled by default, so if you want to use it, you should enable it. It also depends on `systemd-resolved` for proper integration of DNS resolution, which in turn requires you to replace `/etc/resolv.conf` with a symlink to `/run/systemd/resolve/resolv.conf`, which is managed by `systemd-resolved`.

```
systemctl enable systemd-networkd
systemctl enable systemd-resolved
systemctl start systemd-networkd
systemctl start systemd-resolved
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
```

Although `systemd-networkd` suffers from some limitations, like the lack of integrated support for wireless networks, you can rely on a pre-existing external `wpa_supplicant` configuration for wireless support. However, it is particularly useful in containers and virtual machines, and was originally developed for environments in which a container's network configuration depended on its host's network configuration. In this scenario, `systemd-networkd` makes it easier to manage both sides in a consistent manner while still supporting all sorts of virtual network devices that you might need in this type of scenario (see systemd.netdev(5) in [_Manual Pages_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/helping-yourself-and-getting-help/documentation-sources/manual-pages)).

## 6.2. Managing Unix Users and Unix Groups

The database of Unix users and groups consists of the textual files `/etc/passwd` (list of users), `/etc/shadow` (encrypted passwords of users), `/etc/group` (list of groups), and `/etc/gshadow` (encrypted passwords of groups). Their formats are documented in passwd(5), shadow(5), group(5), and gshadow(5) respectively (see [Manual Pages](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/helping-yourself-and-getting-help/documentation-sources/manual-pages). While these files can be manually edited with tools like `vipw` and `vigr`, there are higher level tools to perform the most common operations.

**Using `getent` to Consult the User Database**

The `getent` (get entries) command checks the system databases (including those of users and groups) using the appropriate library functions, which in turn call the name service switch (NSS) modules configured in the `/etc/nsswitch.conf` file. The command takes one or two arguments: the name of the database to check, and a possible search key. Thus, the command `getent passwd kaliuser1` will return the information from the user database regarding the user `kaliuser1`.

```
root@kali:~# getent passwd kaliuser1
kaliuser1:x:1001:1001:Kali User,4444,123-867-5309,321-867-5309:/home/kaliuser1:/bin/bash
```

### 6.2.1. Creating User Accounts

Although Kali is most often run while privileged with sudo permissions, you may often need to create non-privileged user accounts for various reasons, particularly if you are using Kali as a primary operating system. The most typical way to add a user is with the `adduser` command, which takes a required argument: the username for the new user that you would like to create.

The `adduser` command asks a few questions before creating the account but its usage is fairly straightforward. Its configuration file, `/etc/adduser.conf`, includes many interesting settings. You can, for example, define the range of user identifiers (UIDs) that can be used, dictate whether or not users share a common group or not, define default shells, and more.

The creation of an account triggers the population of the user's home directory with the contents of the `/etc/skel/` template. This provides the user with a set of standard directories and configuration files.

In some cases, it will be useful to add a user to a group (other than their default main group) in order to grant additional permissions. For example, a user who is included in the _docker_ group has full access to docker commands and services. This can be achieved with a command such as `adduser user group`.

### 6.2.2. Modifying an Existing Account or Password

The following commands allow modification of the information stored in specific fields of the user databases:

- `passwd`—permits a regular user to change their password, which in turn, updates the `/etc/shadow` file.
- `chfn`—(CHange Full Name), reserved for the super-user (root), modifies the `GECOS`, or "general information" field.
- `chsh`—(CHange SHell) changes the user's login shell. However, available choices will be limited to those listed in `/etc/shells`; the administrator, on the other hand, is not bound by this restriction and can set the shell to any program chosen.
- `chage`—(CHange AGE) allows the administrator to change the password expiration settings by passing the user name as an argument or list current settings using the `-l user` option. Alternatively, you can also force the expiration of a password using the `passwd -e user` command, which forces the user to change their password the next time they log in.

### 6.2.3. Disabling an Account

You may find yourself needing to disable an account (lock out a user) as a disciplinary measure, for the purposes of an investigation, or simply in the event of a prolonged or definitive absence of a user. A disabled account means the user cannot login or gain access to the machine. The account remains intact on the machine and no files or data are deleted; it is simply inaccessible. This is accomplished by using the command `passwd -l user` (lock). Re-enabling the account is done in similar fashion, with the `-u` option (unlock).

### 6.2.4. Managing Unix Groups

The `addgroup` and `delgroup` commands add or delete a group, respectively. The `groupmod` command modifies a group's information (its `gid` or identifier). The command `gpasswd group` changes the password for the group, while the `gpasswd -r group` command deletes it.

**Working with Several Groups**

Each user may be a member of many groups. A user's main group is, by default, created during initial user configuration. By default, each file that a user creates belongs to the user, as well as to the user's main group. This is not always desirable; for example, when the user needs to work in a directory shared by a group other than their main group. In this case, the user needs to change groups using one of the following commands: `newgrp`, which starts a new shell, or `sg`, which simply executes a command using the supplied alternate group. These commands also allow the user to join a group to which they do not currently belong. If the group is password protected, they will need to supply the appropriate password before the command is executed.

Alternatively, the user can set the `setgid` bit on the directory, which causes files created in that directory to automatically belong to the correct group. For more details, see [SECURITY `setgid` directory and sticky bit](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/linux-fundamentals/useful-commands/displaying-and-modifying-text-files).

The `id` command displays the current state of a user, with their personal identifier (`uid` variable), current main group (`gid` variable), and the list of groups to which they belong (`groups` variable).

## 6.3. Configuring Services

In this section we will take a look at services (sometimes called daemons), or programs that run as a background process and perform various functions for the system. We will start by discussing configuration files and will proceed to explain how some important services (such as SSH, PostgreSQL, and Apache) function and how they can be configured.

Kali Linux's policy is to have any network services disabled by default, which is a different behavior to other Linux operating systems. For more information see [_Kali Linux Policies_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/about-kali-linux/kali-linux-policies/network-services-disabled-by-default).

### 6.3.1. Configuring a Specific Program

When you want to configure an unknown package, you must proceed in stages. First, you should read what the package maintainer has documented. The `/usr/share/doc/package/README.Debian` file is a good place to start. This file will often contain information about the package, including pointers that may refer you to other documentation. You will often save yourself a lot of time, and avoid a lot of frustration, by reading this file first since it often details the most common errors and solutions to most common problems.

Next, you should look at the software's official documentation. Refer to [_Documentation Sources_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/helping-yourself-and-getting-help) for tips on how to find various documentation sources. The `dpkg -L package` command gives a list of files included in the package; you can therefore quickly identify the available documentation (as well as the configuration files, located in `/etc/`). Also, `dpkg -s package` displays the package meta-data and shows any possible recommended or suggested packages; in there, you can find documentation or perhaps a utility that will ease the configuration of the software.

Finally, the configuration files are often self-documented by many explanatory comments detailing the various possible values for each configuration setting. In some cases, you can get software up and running by uncommenting a single line in the configuration file. In other cases, examples of configuration files are provided in the `/usr/share/doc/package/examples/` directory. They may serve as a basis for your own configuration file.

### 6.3.2. Configuring SSH for Remote Logins

SSH allows you to remotely log into a machine, transfer files, or execute commands. It is an industry standard tool (`ssh`) and service (`sshd`) for connecting to machines remotely.

While the `openssh-server` package is installed by default, the _SSH_ service is disabled by default and thus is not started at boot time. You can manually start the SSH service with `systemctl start ssh` or configure it to start at boot time with `systemctl enable ssh`.

The SSH service has a relatively sane default configuration, but given its powerful capabilities and sensitive nature, it is good to know what you can do with its configuration file, `/etc/ssh/sshd_config`. All the options are documented in sshd_config(5) (see [_Manual Pages_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/helping-yourself-and-getting-help/documentation-sources/manual-pages)).

The default configuration allows password-based logins. If this is not wanted, you can disable this by setting `PasswordAuthentication` to `no`. Doing so will mean that and SSH key will need to be generated. The SSH service listens by default on port 22 but you can change this with the `Port` directive.

To apply the new settings, you should run `systemctl reload ssh`.

**Generating New SSH Host Keys**

Each SSH server has its own cryptographic keys; they are named "SSH host keys" and are stored in `/etc/ssh/ssh_host_*`. They must be kept private if you want confidentiality and they should not be shared by multiple machines.

When you install your system by copying a full disk image (instead of using debian-installer such as ARM images), the image might contain pre-generated SSH host keys that you should thus replace with newly-generated keys. The image probably also comes with a default user password that you want to reset at the same time. You can do all this with the following commands:

```
# passwd
[...]
# rm /etc/ssh/ssh_host_*
# dpkg-reconfigure openssh-server
# systemctl restart ssh
```

### 6.3.3. Configuring PostgreSQL Databases

PostgreSQL is a database server. It is rarely useful on its own but is used by many other services to store data. Those services will generally access the database server over the network and usually require authentication credentials to be able to connect. Setting up those services thus requires creating PostgreSQL databases and user accounts with appropriate privileges on the database. To be able to do that, we need the service to be running, so let's start it with `systemctl start postgresql`.

**Multiple PostgreSQL versions supported**

The PostgreSQL packaging allows for multiple versions of the database server to be co-installed. It is also possible to handle multiple _clusters_ (a cluster is a collection of databases served by the same `postmaster`). To achieve this, the configuration files are stored in `/etc/postgresql/version/cluster-name/`.

In order for clusters to run side-by-side, each new cluster gets assigned the next available port number (usually 5433 for the second cluster). The `postgresql.service` file is an empty shell, making it easy to act on all clusters together as each cluster has its own unit (`postgresql@version-cluster.service`).

#### Connection Type and Client Authentication

By default, PostgreSQL listens for incoming connections in two ways: on TCP port 5432 of the localhost interface and on file-based socket `/var/run/postgresql/.s.PGSQL.5432`. This can be configured in `postgresql.conf` with various directives: `listen_addresses` for the addresses to listen to, `port` for the TCP port, and `unix_socket_directories` to define the directory where the file-based sockets are created.

Depending on how they connect, clients are authenticated in different ways. The `pg_hba.conf` configuration file defines who is allowed to connect on each socket and how they are authenticated. By default, connections on the file-based socket use the Unix user account as the name of the PostgreSQL user, and it assumes that no further authentication is required. On the TCP connection, PostgreSQL requires the user to authenticate with a username and a password (though not a Unix username/password but rather one managed by PostgreSQL itself).

The `postgres` user is special and has full administrative privileges over all databases. We will use this identity to create new users and new databases.

#### Creating Users and Databases

The `createuser` command adds a new user and `dropuser` removes one. Likewise, the `createdb` command adds a new database and `dropdb` removes one. Each of these commands have their own manual pages but we will discuss some of the options here. Each command acts on the default cluster (running on port 5432) but you can pass `--port=port` to modify users and databases of an alternate cluster.

These commands must connect to the PostgreSQL server to do their job and they must be authenticated as a user with sufficient privileges to be able to execute the specified operation. The easiest way to achieve this is to use the `postgres` Unix account and connect over the file-based socket:

```
# su - postgres
postgres@kali:~$ createuser -P king_phisher
Enter password for new role:
Enter it again:
postgres@kali:~$ createdb -T template0 -E UTF-8 -O king_phisher king_phisher
postgres@kali:~$ exit
```

In the example above, the `-P` option asks `createuser` to query for a password once it creates the new `king_phisher` user. Looking at the `createdb` command, the `-O` defines the user owning the new database (which will thus have full rights to create tables and grant permissions and so on). We also want to be able to use Unicode strings, so we add the `-E UTF-8` option to set the encoding, which in turn requires us to use the `-T` option to pick another database template.

We can now test that we can connect to the database over the socket listening on localhost (`-h localhost`) as the king_phisher user (`-U king_phisher`):

```
# psql -h localhost -U king_phisher king_phisher
Password for user king_phisher:
psql (9.5.2)
SSL connection (protocol: TLSv1.2, cipher: ECDHE-RSA-AES256-GCM-SHA384, bits: 256, compression: off)
Type "help" for help.

king_phisher=>
```

As you can see, the connection was successful.

#### Managing PostgreSQL Clusters

First, it is worth noting that the concept of "PostgreSQL cluster" is a [Debian-specific addition](https://wiki.debian.org/PostgreSql) and that you will not find any reference to this term in the [official PostgreSQL documentation](https://www.postgresql.org/docs/). From the point of view of the PostgreSQL tools, such a cluster is just an instance of a database server running on a specific port.

That said, Debian's `postgresql-common` package provides multiple tools to manage such clusters: `pg_createcluster`, `pg_dropcluster`, `pg_ctlcluster`, `pg_upgradecluster`, `pg_renamecluster`, and `pg_lsclusters`. We won't cover all those tools here, but you can refer to their respective manual pages for more information.

What you must know is that when a new major version of PostgreSQL gets installed on your system, it will create a new cluster that will run on the next port (usually 5433) and you will keep using the old version until you migrate your databases from the old cluster to the new one.

You can retrieve a list of all the clusters and their status with `pg_lsclusters`. More importantly, you can automate the migration of your cluster to the latest PostgreSQL version with `pg_upgradecluster old-version cluster-name`. For this to succeed, you might have to first remove the (empty) cluster created for the new version (with `pg_dropcluster new-version cluster-name`). The old cluster is not dropped in the process, but it also won't be started automatically. You can drop it once you have checked that the upgraded cluster works fine.

### 6.3.4. Configuring Apache

A typical Kali Linux installation includes the Apache web server, provided by the `apache2` package. Being a network service, it is disabled by default. You can manually start it with `systemctl start apache2`.

With more and more applications being distributed as web applications, it is important to have some knowledge of Apache in order to host those applications, whether for local usage or for making them available over the network.

Apache is a modular server and many features are implemented by external modules that the main program loads during its initialization. The default configuration only enables the most common modules, but enabling new modules is easily done by running `a2enmod _module_`. Use `a2dismod module` to disable a module. These programs actually only create (or delete) symbolic links in `/etc/apache2/mods-enabled/`, pointing at the actual files (stored in `/etc/apache2/mods-available/`).

There are many modules available, but two are worth initial consideration: PHP and SSL (used for TLS). Web applications written with PHP are executed by the Apache web server with the help of the dedicated module provided by the `libapache-mod-php` package, and its installation automatically enables the module.

Apache 2.4 includes the SSL module required for Hypertext Transfer Protocol Secure (HTTPS) out of the box. It first needs to be enabled with `a2enmod ssl`, then the required directives must be added to the configuration files. A configuration example is provided in `/etc/apache2/sites-available/default-ssl.conf`. See [https://httpd.apache.org/docs/2.4/mod/mod_ssl.html](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html) for more information.

The full list of standard Apache modules can be found online at [https://httpd.apache.org/docs/2.4/mod/index.html](https://httpd.apache.org/docs/2.4/mod/index.html).

With its default configuration, the web server listens on port 80 (as configured in `/etc/apache2/ports.conf`), and serves pages from the `/var/www/html/` directory by default (as configured in `/etc/apache2/sites-enabled/000-default.conf`).

#### Configuring Virtual Hosts

A virtual host is an extra identity for the web server. The same Apache process can serve multiple websites (say `www.kali.org` and `www.offsec.com`) because the HTTP requests embed both the name of the website requested and the URL localpart (this feature is known as _name-based virtual hosts_).

The default configuration for Apache 2 enables name-based virtual hosts. In addition, a default virtual host is defined in the `/etc/apache2/sites-enabled/000-default.conf` file; this virtual host will be used if no host matching the request sent by the client is found.

**Important**

Requests concerning unknown virtual hosts will always be served by the first defined virtual host, which is why the package ships a `000-default.conf` configuration file, which is sorted first among all other files that you might create.

Each extra virtual host is then described by a file stored in `/etc/apache2/sites-available/`. The file is usually named after the hostname of the website followed by a `.conf` suffix (for example: `www.kali.org.conf`). You can then enable the new virtual host with `a2ensite www.kali.org`. Here is a minimal virtualhost configuration for a website whose files are stored in `/srv/www.kali.org/www/` (defined with the `DocumentRoot` option):

```
<VirtualHost *:80>
ServerName www.kali.org
ServerAlias kali.org
DocumentRoot /srv/www.kali.org/www
</VirtualHost>
```

You might also consider adding `CustomLog` and `ErrorLog` directives to configure Apache to output logs in files dedicated to the virtual host.

#### Common Directives

This section briefly reviews some of the commonly-used Apache configuration directives.

The main configuration file usually includes several `Directory` blocks; they allow specifying different behaviors for the server depending on the location of the file being served. Such a block commonly includes `Options` and `AllowOverride` directives:

```
<Directory /var/www>
Options Includes FollowSymLinks
AllowOverride All
DirectoryIndex index.php index.html index.htm
</Directory>
```

The `DirectoryIndex` directive contains a list of files to try when the client request matches a directory. The first existing file in the list is used and sent as a response.

The `Options` directive is followed by a list of options to enable. The `None` value disables all options; correspondingly, `All` enables them all except `MultiViews`. Available options include:

- `ExecCGI` - indicates that CGI scripts can be executed.
- `FollowSymLinks` - tells the server that symbolic links can be followed, and that the response should contain the contents of the target of such links.
- `SymLinksIfOwnerMatch` - also tells the server to follow symbolic links, but only when the link and its target have the same owner.
- `Includes` - enables _Server Side Includes_ (SSI). These are directives embedded in HTML pages and executed on the fly for each request.
- `Indexes` - tells the server to list the contents of a directory if the HTTP request sent by the client points to a directory without an index file (that is, when no files mentioned by the `DirectoryIndex` directive exist in this directory).
- `MultiViews` - enables content negotiation; this can be used by the server to return a web page matching the preferred language as configured in the browser.

##### Requiring Authentication

In some circumstances, access to part of a website needs to be restricted, so only legitimate users who provide a username and a password are granted access to the contents.

The `.htaccess` file contains Apache configuration directives enforced each time a request concerns an element from the directory where the `.htaccess` file is stored. These directives are recursive, expanding the scope to all subdirectories.

Most of the directives that can occur in a `Directory` block are also legal in an `.htaccess` file. The `AllowOverride` directive lists all the options that can be enabled or disabled by way of `.htaccess`. A common use of this option is to restrict `ExecCGI`, so that the administrator chooses which users are allowed to run programs under the web server's identity (the `www-data` user).

**Example 5.3. `.htaccess` File Requiring Authentication**

```
Require valid-user
AuthName "Private directory"
AuthType Basic
AuthUserFile /etc/apache2/authfiles/htpasswd-private
```

**Basic Authentication Offers No Security**

The authentication system used in the above example (`Basic`) has minimal security as the password is sent in clear text (it is only encoded as _base64_, which is a simple encoding rather than an encryption method). It should also be noted that the documents protected by this mechanism also go over the network in the clear. If security is important, the entire HTTP session should be encrypted with Transport Layer Security (TLS).

The `/etc/apache2/authfiles/htpasswd-private` file contains a list of users and passwords; it is commonly manipulated with the `htpasswd` command. For example, the following command is used to add a user or change their password:

```
# htpasswd /etc/apache2/authfiles/htpasswd-private user
New password:
Re-type new password:
Adding password for user user
```

##### Restricting Access

The `Require` directive controls access restrictions for a directory (and its subdirectories, recursively).

It can be used to restrict access based on many criteria; we will stop at describing access restriction based on the IP address of the client but it can be made much more powerful than that, especially when several `Require` directives are combined within a `RequireAll` block.

For instance, you could restrict access to the local network with the following directive:

```
Require ip 192.168.0.0/16
```

## 6.4. Managing Services

Kali uses `systemd` as its init system, which is not only responsible for the boot sequence, but also permanently acts as a full featured service manager, starting and monitoring services.

`systemd` can be queried and controlled with `systemctl`. Without any argument, it runs the `systemctl list-units` command, which outputs a list of the active _units_. If you run `systemctl status`, the output shows a hierarchical overview of the running services. Comparing both outputs, you immediately see that there are multiple kinds of units and that services are only one among them.

Each service is represented by a **service unit**, which is described by a service file usually shipped in `/lib/systemd/system/` (or `/run/systemd/system/`, or `/etc/systemd/system/`; they are listed by increasing order of importance, and the last one wins). Each is possibly modified by other `service-name.service.d/*.conf` files in the same set of directories. Those unit files are plain text files whose format is inspired by the well-known "*.ini" files of Microsoft Windows, with `key = value` pairs grouped between `[section]` headers. Here we see a sample service file for `/lib/systemd/system/ssh.service`:

```
[Unit]
Description=OpenBSD Secure Shell server
After=network.target auditd.service
ConditionPathExists=!/etc/ssh/sshd_not_to_be_run

[Service]
EnvironmentFile=-/etc/default/ssh
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255
Type=notify

[Install]
WantedBy=multi-user.target
Alias=sshd.service
```

Target units are another part of systemd's design. They represent a desired state that you want to attain in terms of activated units (which means a running service in the case of service units). They exist mainly as a way to group dependencies on other units. When the system starts, it enables the units required to reach the `default.target` (which is a symlink to `graphical.target`, and which in turn depends on `multi-user.target`). So all the dependencies of those targets get activated during boot.

Such dependencies are expressed with the `Wants` directive on the target unit. But you don't have to edit the target unit to add new dependencies, you can also create a symlink pointing to the dependent unit in the `/etc/systemd/system/target-name.target.wants/` directory. And this is exactly what `systemctl enable foo.service` does. When you enable a service, you tell systemd to add a dependency on the targets listed in the `WantedBy` entry of the `[Install]` section of the service unit file. Conversely, `systemctl disable foo.service` drops the same symlink and thus the dependency.

The `enable` and `disable` commands do not change anything regarding the current status of the services. They only influence what will happen at next boot. If you want to run the service immediately, you should execute `systemctl start foo.service`. Conversely, you can stop it with `systemctl stop foo.service`. You can also inspect the current status of a service with `systemctl status foo.service`, which usefully includes the latest lines of the associated log. After having changed the configuration of a service, you may wish to reload it or restart it: those operations are done with `systemctl reload foo.service` and `systemctl restart foo.service` respectively.

```
# systemctl status postgresql
● postgresql.service - PostgreSQL RDBMS
   Loaded: loaded (/lib/systemd/system/postgresql.service; disabled; vendor preset: disabled)
   Active: inactive (dead)
# ls -al /etc/systemd/system/multi-user.target.wants/postgresql.service
ls: cannot access '/etc/systemd/system/multi-user.target.wants/postgresql.service': No such file or directory
# systemctl enable postgresql
[...]
# ls -al /etc/systemd/system/multi-user.target.wants/postgresql.service
lrwxrwxrwx 1 root root 38 Jan 26 19:09 /etc/systemd/system/multi-user.target.wants/postgresql.service -> /lib/systemd/system/postgresql.service
# systemctl status postgresql
● postgresql.service - PostgreSQL RDBMS
   Loaded: loaded (/lib/systemd/system/postgresql.service; enabled; vendor preset: disabled)
   Active: inactive (dead)
# systemctl start postgresql
# systemctl status postgresql
● postgresql.service - PostgreSQL RDBMS
     Loaded: loaded (/lib/systemd/system/postgresql.service; enabled; vendor preset: disabled)
     Active: active (exited) since Tue 2021-01-26 19:10:31 EST; 5s ago
    Process: 1495 ExecStart=/bin/true (code=exited, status=0/SUCCESS)
   Main PID: 1495 (code=exited, status=0/SUCCESS)

Jan 26 19:10:31 kali-rolling systemd[1]: Starting PostgreSQL RDBMS...
Jan 26 19:10:31 kali-rolling systemd[1]: Started PostgreSQL RDBMS.
```

## 6.5. Summary

In this chapter, we learned how to configure Kali Linux. We configured network settings, talked about users and groups, and discussed how to create and modify user accounts, set passwords, disable accounts, and manage groups. Finally, we discussed services and explained how to set up and maintain generic services, specifically SSH, PostgreSQL, and Apache.

Summary Tips:

- In a typical desktop installation, you will have _NetworkManager_ already installed and it can be controlled and configured through Xfce's system settings and through the top-right menu.
- You can configure the network from the command line with the `ifup` and `ifdown` tools, which read their instructions from the `/etc/network/interfaces` configuration file. An even newer tool, _systemd-networkd_ works with the _systemd_ init system.
- By default, the database of Unix users and groups consists of the textual files `/etc/passwd` (list of users), `/etc/shadow` (encrypted passwords of users), `/etc/group` (list of groups), and `/etc/gshadow` (encrypted passwords of groups).
- You can use the `getent` command to consult the user database and other system databases.
- The `adduser` command asks a few questions before creating the account, but is a straightforward way to create a new user account.
- Several commands can be used to modify specific fields in the user database including: `passwd` (change password), `chfn` (change full name and the `GECOS`, or general information field), `chsh` (change login shell), `chage` (change password age), and `passwd -e user` (forces the user to change their password the next time they log in).
- Each user can be a member of one or multiple groups. Several commands can be used to modify group identity: `newgrp` changes the current group ID, `sg` executes a command using the supplied alternate group, the `setgid` bit can be placed on a directory, causing files created in that directory to automatically belong to the correct group. In addition, the `id` command displays the current state of a user including a list of their group membership.
- You can manually start SSH with `systemctl start ssh` or permanently enable it with `systemctl enable ssh`.
- PostgreSQL is a database server. It is rarely useful on its own but is used by many other services to store data.
- A typical Kali Linux installation includes the Apache web server, provided by the `apache2` package. Being a network service, it is disabled by default. You can manually start it with `systemctl start apache2`.
- With its default configuration, Apache listens on port 80 (as configured in `/etc/apache2/ports.conf`), and serves pages from the `/var/www/html/` directory by default (as configured in `/etc/apache2/sites-enabled/000-default.conf`).

Now that we have tackled Linux fundamentals and Kali Linux installation and configuration, let's discuss how to troubleshoot Kali and teach you some tools and tricks to get you back up and running when you run into problems.

### 6.6.1. Configuring users in Kali

#### Exercise:

1. Create a standard user account. Add the new user to the **sudo** group
2. Change the default login shell to be bash

---

#### Exercise solution:

Use commands similar to the following:

```
kali@kali:~$ sudo adduser username
kali@kali:~$
kali@kali:~$ sudo passwd username
kali@kali:~$
kali@kali:~$ sudo usermod -a -G sudo username
kali@kali:~$
kali@kali:~$ sudo chsh -s /bin/bash username
kali@kali:~$
```

### 6.6.2. Configuring the network

#### Exercise:

1. Stop the Network Manager service and completely disable it at boot time.
2. Configure your Kali machine for DHCP on eth0.
3. Bring down the eth0 interface.
4. Connect to the wireless network using your wireless USB dongle by configuring `/etc/network/interfaces` accordingly.

---

#### Exercise solution:

1. Network Manager is handy, but for pentesting you really need to get hold of your interfaces and bend them to your will without any surprises. To stop Network Manager and disable it at boot time:

```
kali@kali:~$ sudo systemctl stop NetworkManager.service
kali@kali:~$
kali@kali:~$ sudo systemctl disable NetworkManager.service
kali@kali:~$
```

You can check the status of Network Manager managed interfaces with:

```
kali@kali:~$ nmcli dev status
kali@kali:~$
```

Pro tip: Stop Network Manager from adding dns-servers to `/etc/resolv.conf` file:

```
kali@kali:~$ sudo nano /etc/NetworkManager/NetworkManager.conf
kali@kali:~$
```

Add _dns=none_ to the [main] section.

2. Configure eth0 for DHCP. Change the `/etc/network/interfaces` file to include:

```
auto eth0
iface eth0 inet dhcp
```

You can also set up a static address with something like the following:

```
auto eth0
iface eth0 inet static
	address 192.168.1.160
	netmask 255.255.255.0
	gateway 192.168.1.1
```

3. Bringing down the eth0 interface:

```
kali@kali:~$ sudo ifconfig eth0 down
kali@kali:~$
```

4. Connecting to a wireless network. Note that if you're in a VM you'll need a USB wireless adapter. This example assumes WPA2. Generate a PSK using the following command:

```
kali@kali:~$ wpa_passphrase myssid wpa-password
kali@kali:~$
```

Now insert the PSK together with the following into your `/etc/network/interfaces` file:

```
auto wlan0
iface wlan0 inet dhcp
     wpa-ssid myssid
     wpa-psk {whatever the PSK hash was}
```

Spin up the interface:

```
kali@kali:~$ sudo ifup wlan0
kali@kali:~$
```

### 6.6.3. Configuring services (part 1)

#### Exercise:

1. Start the SSH service and connect to it from your host system as the **kali** user.
2. Configure the SSH service to start at boot time.
3. Change the default password and generate new SSH host keys.

---

#### Exercise solution:

1. Start sshd:

```
kali@kali:~$ sudo systemctl start ssh
kali@kali:~$
```

Connect to it from your host system:

```
user@host:~$ ssh kali@192.168.1.12
kali@kali:~$
```

2. Enable sshd at boot:

```
kali@kali:~$ sudo systemctl enable ssh
kali@kali:~$
```

3. For security reasons, change the password and generate new SSH host keys:

```
kali@kali:~$ passwd
[...]
kali@kali:~$
kali@kali:~$ sudo rm /etc/ssh/ssh_host_*
kali@kali:~$
kali@kali:~$ sudo dpkg-reconfigure openssh-server
kali@kali:~$
kali@kali:~$ sudo service ssh restart
kali@kali:~$
```

### 6.6.4. Configuring services (part 2)

#### Exercise:

In this exercise, we'll install masscan. This is a cool tool and the full installation will help review some of the configuration concepts we've explored in this chapter. The process is broken into several steps:

1. Install and start the Apache the PostgreSQL services.
2. Configure Apache and PostgreSQL to start at boot time.
3. Install masscan, its prerequisites, and OffSec's masscan web interface. Use an Apache / PostgreSQL stack.
4. Import a previous scan and view the results.
5. Protect the Apache installation with a htaccess username / password.

---

#### Exercise solution:

This solution will be a bit out of order. To begin, checkout a copy of the masscan-web-ui repository:

```
kali@kali:~$ cd ~
kali@kali:~$
kali@kali:~$ git clone https://github.com/offensive-security/masscan-web-ui
kali@kali:~$
```

Next, make sure all the massscan prerequisites are in place and copy over the masscan web ui files to the web root. Note that if you're copying and pasting the apt-get line, it is long. Be sure to grab it all:

```
kali@kali:~$ sudo apt-get install apache2 php libapache2-mod-php php-xml postgresql php-pgsql
kali@kali:~$
kali@kali:~$ sudo mv masscan-web-ui/* /var/www/html/
kali@kali:~$
kali@kali:~$ sudo rm /var/www/html/index.html
kali@kali:~$
```

Start up Apache and Postgres:

```
kali@kali:~$ sudo systemctl start apache2
kali@kali:~$
kali@kali:~$ sudo systemctl start postgresql
kali@kali:~$
```

With Apache and PostgreSQL started, masscan installed and Apache's default index.html out of the way, you can browse to your Apache server to see masscan. However, it rightly complains about password authentication failures. Let's fix that. Create the masscan user, and create the masscan database.

```
kali@kali:~$ sudo su - postgres
postgres@kali:~$
postgres@kali:~$ createuser -P masscan
Enter password for new role:
Enter it again:
postgres@kali:~$
postgres@kali:~$ createdb -T template0 -E UTF-8 -O masscan masscandb
postgres@kali:~$
postgres@kali:~$ exit
postgres@kali:~$
```

Next, modify the password you set and the database name (masscandb) in the **define** lines:

```
kali@kali:~$ sudo nano /var/www/html/config.php
[...]
kali@kali:~$
kali@kali:~$ grep ^define /var/www/html/config.php
define('DB_DRIVER',	    'pgsql');
define('DB_HOST',	    '127.0.0.1');
define('DB_USERNAME',	'masscan');
define('DB_PASSWORD', 	'toortoor');
define('DB_DATABASE', 	'masscandb');
kali@kali:~$
```

Browse to http://localhost on your local machine (or the remote address if browsing from outside the VM) which should indicate that masscan is set up properly:

![Figure 2: Massscan success](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/c8707de7767b6625bffaa4d04b0410f6-masscan_success-1.png)

Figure 2: Massscan success

Next, let's import some scan results from a previously run scan. We'll clear the database since this is the first time we've used masscan:

```
kali@kali:~$ wget https://kali.training/downloads/masscan.xml
kali@kali:~$
kali@kali:~$ php /var/www/html/import.php /home/kali/masscan.xml
Do you want to clear the database before importing (yes/no)?: yes

Clearing the db
Reading file
Parsing file
Processing data (This may take some time depending on file size)

Summary:
Total records:4646
Inserted records:4646
Took about:10 seconds
kali@kali:~$
```

Next, browse to your http://localhost to view the imported data. Since this is "sensitive data" we want to password-protect the root web directory. To do this we must start with Apache directives:

```
kali@kali:~$ sudo nano /etc/apache2/sites-enabled/000-default.conf
kali@kali:~$
```

Add these lines:

```
AuthType Basic
AuthName "Restricted Content"
AuthUserFile /etc/apache2/htpasswd
Require valid-user
```

And let's create credentials for a new user:

```
kali@kali:~$ sudo htpasswd -c /etc/apache2/htpasswd myuser
kali@kali:~$
```

Lastly, browse to your http://localhost, enter your credentials and view the report.

**Did you know?**

The Kali Linux policy of disabling network services by default is configured by **/lib/systemd/system-preset/{95-kali.preset,99-default.preset}**.

### 6.6.5. Raspberry Pi access point

If you don't have a Raspberry Pi 3 (RPi 3), you should really get one. They are super cool and relatively inexpensive. In this exercise, you will configure a Raspberry Pi 3 to run as a Wireless Access Point, granting connected users access to the Internet. This exercise is great because you will install Kali to the Raspberry Pi, edit files, change file permissions, configure network interfaces, install and configure services, configure iptables rules and more. It's a great overview.

#### Exercise:

1. Install Kali on the Raspberry Pi 3. You could use a custom image, but if you do, you might have more troubleshooting to do. If you're unsure, use the stock image, which this solution was written for.
2. Implement WPA2 security on the AP.
3. Configure **eth0** as DHCP, and **wlan0** as static.
4. Configure the Raspberry Pi as a DHCP server for any wireless clients and assign a DHCP pool with 12-hour leases.
5. Have the SSH server start up at boot time so you can SSH to the Raspberry Pi once it's booted.
6. Forward all outbound traffic, including DNS, from **wlan0** to **eth0**.
7. Allow inbound established (stateful) connections from **eth0** to **wlan0**.
8. Hint: Although you have not learned about **hostapd** or **dnsmasq**, you will use them in this exercise.

---

#### Exercise solution:

This will require a few things:

- Raspberry Pi 3. You can use an older model with a USB wifi but you're on your own when it comes to configuring **wlan0**.
- hostapd: This creates an access point
- dnsmasq: This does DNS forwarding and provides a DHCP sever
- dhcpcd5: A DHCP client (which also does other cool network management stuff)

Grab the required packages:

```
kali@kali:~$ sudo apt-get install dnsmasq hostapd dhcpcd5
kali@kali:~$
```

First, let's tell dhcpcd to ignore wlan0's setup. We'll configure a static IP later:

```
kali@kali:~$ sudo nano /etc/dhcpcd.conf
kali@kali:~$
```

Put this above any interface lines that may be in the file:

```
denyinterfaces wlan0
```

Now, let's set up our Wi-Fi interface. If you have a Pi 2 with a USB Wi-Fi adapter, go ahead and plug it in now. Edit the interfaces file:

```
kali@kali:~$ sudo nano /etc/network/interfaces
kali@kali:~$
```

Add this section:

```
allow-hotplug wlan0
iface wlan0 inet static
    address 172.24.1.1
    netmask 255.255.255.0
    network 172.24.1.0
    broadcast 172.24.1.255
```

Restart dhcpcd with:

```
kali@kali:~$ sudo service dhcpcd restart
kali@kali:~$
```

and then reload the configuration for wlan0 with:

```
kali@kali:~$ sudo ifdown wlan0; sudo ifup wlan0
kali@kali:~$
```

Next, let's configure hostapd with a new configuration file. Note that an SSID and passphrase are configured for your access point.

```
kali@kali:~$ sudo nano /etc/hostapd/hostapd.conf
[...]
kali@kali:~$
kali@kali:~$ cat /etc/hostapd/hostapd.conf

# This is the name of the WiFi interface we configured above
interface=wlan0

# Use the nl80211 driver with the brcmfmac driver
driver=nl80211

# This is the name of the network
ssid=Kali-Pi3

# Use the 2.4GHz band
hw_mode=g

# Use channel 6
channel=6

# Enable 802.11n
ieee80211n=1

# Enable WMM
wmm_enabled=1

# Enable 40MHz channels with 20ns guard interval
ht_capab=[HT40][SHORT-GI-20][DSSS_CCK-40]

# Accept all MAC addresses
macaddr_acl=0

# Use WPA authentication
auth_algs=1

# Require clients to know the network name
ignore_broadcast_ssid=0

# Use WPA2
wpa=2

# Use a pre-shared key
wpa_key_mgmt=WPA-PSK

# The network passphrase
wpa_passphrase=raspberrytoor

# Use AES, instead of TKIP
rsn_pairwise=CCMP
kali@kali:~$
```

At this point, we can test things out. Run:

```
kali@kali:~$ sudo /usr/sbin/hostapd /etc/hostapd/hostapd.conf
```

This shows a successful run. Note that the errors pertaining to monitor mode are not relevant to us. For a RPi3 using the nexmon firmware, we would need _nexutil -m2_.

```
kali@kali:~$ sudo /usr/sbin/hostapd /etc/hostapd/hostapd.conf
Configuration file: /etc/hostapd/hostapd.conf
Failed to create interface mon.wlan0: -95 (Operation not supported)
wlan0: Could not connect to kernel driver
Using interface wlan0 with hwaddr b6:ae:d7:42:a1:70 and ssid "Kali-Pi3"
wlan0: interface state UNINITIALIZED->ENABLED
wlan0: AP-ENABLED
kali@kali:~$
```

You can connect to this access point and hostapd will show some output:

```
wlan0: STA 78:4f:43:7c:6d:32 IEEE 802.11: associated
```

And once you enter the passphrase you should see something like this:

```
wlan0: AP-STA-CONNECTED 78:4f:43:7c:6d:32
wlan0: STA 78:4f:43:7c:6d:32 RADIUS: starting accounting session 5991CC2F-00000000
wlan0: STA 78:4f:43:7c:6d:32 WPA: pairwise key handshake completed (RSN)
wlan0: STA 78:4f:43:7c:6d:32 IEEE 802.11: disassociated
wlan0: AP-STA-DISCONNECTED 78:4f:43:7c:6d:32
wlan0: INTERFACE-DISABLED
wlan0: STA 00:00:00:00:00:00 IEEE 802.11: disassociated
wlan0: INTERFACE-ENABLED
wlan0: STA 78:4f:43:7c:6d:32 IEEE 802.11: associated
```

Note that your client may disconnect and reconnect because it didn't get an IP address. This is normal. You won't get an IP address until we configure dnsmasq. Have fun with this! It gives you an idea of how this process works, behind the scenes.

Press Ctrl-C to stop **hostapd**.

Next, we'll tell hostapd where to find its config file:

```
kali@kali:~$ sudo nano /etc/default/hostapd
kali@kali:~$
```

Find the line `#DAEMON_CONF=""` and replace it with `DAEMON_CONF="/etc/hostapd/hostapd.conf"`.

Let's get **dnsmasq** set up:

```
kali@kali:~$ sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig
kali@kali:~$
kali@kali:~$ sudo nano /etc/dnsmasq.conf
kali@kali:~$
```

The file should look like this:

```
interface=wlan0      # Use interface wlan0
listen-address=172.24.1.1 # Set our listening address
bind-interfaces      # Bind to the interface to make sure we aren't sending things elsewhere
server=8.8.8.8       # Forward DNS requests to Google DNS
domain-needed        # Don't forward short names
bogus-priv           # Never forward addresses in the non-routed address spaces.
dhcp-range=172.24.1.50,172.24.1.150,12h # Assign IP addresses between 172.24.1.50 and 172.24.1.150 with a 12 hour lease time
```

Now, we have two interfaces active, and we have a DHCP client for our Pi and a DHCP server for our wireless guests. Now we need to forward traffic between the Wi-Fi and Ethernet interfaces. We can make this happen immediately with a simple command to update /proc:

```
kali@kali:~$ echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
kali@kali:~$
kali@kali:~$ cat /proc/sys/net/ipv4/ip_forward
1
kali@kali:~$
```

However, this change won't stick between reboots. We need to make it permanent through sysctl:

```
kali@kali:~$ sudo nano /etc/sysctl.conf
kali@kali:~$
```

Uncomment the line containing **net.ipv4.ip_forward=1**:

```
kali@kali:/var/www/html$ grep ip_forward /etc/sysctl.conf
net.ipv4.ip_forward = 1
kali@kali:~$
```

The forward isn't quite enough to give our wifi guests Internet access (through our eth0 interface). We need iptables to help us do this.

```
kali@kali:~$ sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
kali@kali:~$
kali@kali:~$ sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
kali@kali:~$
kali@kali:~$ sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
kali@kali:~$
```

Let's unwrap these commands:

- Whenever a new connection is encountered (-t nat), we want to alter the packets as they are about to go out (-A POSTROUTING) on our Ethernet interface (-o eth0). The -j MASQUERADE target masks the private IP address of the client with the external IP address of the firewall/gateway (Kali Pi).
- Next, we append (-A) a rule to the FORWARD chain (packets being routed through the Pi) which accepts (-j ACCEPT) packets from eth0 to wlan0 (-i eth0 -o wlan0) that belong to (ESTABLISHED) or are related to (RELATED) an existing connection.
- Lastly, we will forward (and accept) all packets from wlan0 to eth0.

Check out our rules:

```
kali@kali:~$ sudo iptables -S
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i wlan0 -o eth0 -j ACCEPT
kali@kali:~$
```

Output our rules to a file:

```
kali@kali:~$ iptables-save | sudo tee /etc/iptables.ipv4.nat
kali@kali:~$
```

Apply these rules every time we boot the Pi by editing the **/etc/rc.local** file:

```
kali@kali:~$ sudo nano /etc/rc.local
[...]
kali@kali:~$ more /etc/rc.local
#!/bin/sh -e
iptables-restore < /etc/iptables.ipv4.nat
```

Make the file executable:

```
kali@kali:~$ sudo chmod 711 /etc/rc.local
kali@kali:~$ ls -l /etc/rc.local
-rwx--x--x 1 root root 57 Aug 10 19:37 /etc/rc.local
kali@kali:~$
```

As we've seen, **hostapd** and **dnsmasq** ship with all the _init system_ goodies (see /etc/init.d), so let's start the services up and check that they are happy:

```
kali@kali:~$ sudo systemctl start hostapd dnsmasq
kali@kali:~$ sudo systemctl status hostapd dnsmasq
● hostapd.service - LSB: Advanced IEEE 802.11 management daemon
   Loaded: loaded (/etc/init.d/hostapd; generated; vendor preset: disabled)
   Active: active (running) since Mon 2017-08-14 19:24:43 UTC; 2s ago
[...]
● dnsmasq.service - dnsmasq - A lightweight DHCP and caching DNS server
   Loaded: loaded (/lib/systemd/system/dnsmasq.service; disabled; vendor preset:
   Active: active (running) since Mon 2017-08-14 19:24:43 UTC; 2s ago
kali@kali:~$
```

And let's set them to run on next reboot:

```
kali@kali:~$ sudo systemctl enable hostapd dnsmasq
hostapd.service is not a native service, redirecting to systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable hostapd
Synchronizing state of dnsmasq.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable dnsmasq
kali@kali:~$
```

Finally, reboot and make sure the rules stick after a reboot. Once rebooted, you should be able to connect to the "Kali Pi" and surf!

Next Module -> [Configuring Kali Linux 🛸](configuring_kali.md)