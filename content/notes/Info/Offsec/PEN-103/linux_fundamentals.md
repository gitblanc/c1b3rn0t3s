---
title: Linux Fundamentals 🦜
tags:
  - Offsec
  - PEN-103
---
- *All the info was extracted from [Offsec, Pen-103](https://portal.offsec.com/courses/pen-103-16306/)*, under the following [licencese](https://creativecommons.org/licenses/by-sa/3.0/)

# 1. Linux Fundamentals

Before you can master Kali Linux, you must be at ease with a generic Linux system. Linux proficiency will serve you well, because a large percentage of web, email, and other Internet services run on Linux servers.

In this section, we strive to cover the basics of Linux, but we assume that you already know about computer systems in general, including components such as the CPU, RAM, motherboard, and hard disk, as well as device controllers and their associated connectors.

## 1.1. What Is Linux and What Is It Doing?

The term "Linux" is often used to refer to the entire operating system, but in reality, Linux is the operating system kernel, which is started by the boot loader, which is itself started by the BIOS/UEFI. The kernel assumes a role similar to that of a conductor in an orchestra—it ensures coordination between hardware and software. This role includes managing hardware, processes, users, permissions, and the file system. The kernel provides a common base to all other programs on the system and typically runs in _ring zero_, also known as _kernel space_.

**The User Space**

We use the term _user space_ to lump together everything that happens outside of the kernel.

Among the programs running in user space are many core utilities from the [GNU project](https://www.gnu.org/), most of which are meant to be run from the command line. You can use them in scripts to automate many tasks. Refer to [_Useful Commands_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/linux-fundamentals/useful-commands/displaying-and-modifying-text-files) for more information about the most important commands.

Let's quickly review the various tasks handled by the Linux kernel.

### 1.1.1. Driving Hardware

The kernel is tasked, first and foremost, with controlling the computer's hardware components. It detects and configures them when the computer powers on, or when a device is inserted or removed (for example, a USB device). It also makes them available to higher-level software, through a simplified programming interface, so applications can take advantage of devices without having to address details such as which extension slot an option board is plugged into. The programming interface also provides an abstraction layer; this allows video-conferencing software, for example, to use a webcam regardless of its maker and model. The software can use the _Video for Linux_ (V4L) interface and the kernel will translate function calls of the interface into actual hardware commands needed by the specific webcam in use.

The kernel exports data about detected hardware through the `/proc/` and `/sys/` virtual file systems. Applications often access devices by way of files created within `/dev/`. Specific files represent disk drives (for instance, `/dev/sda`), partitions (`/dev/sda1`), mice (`/dev/input/mouse0`), keyboards (`/dev/input/event0`), sound cards (`/dev/snd/*`), serial ports (`/dev/ttyS*`), and other components.

There are two types of device files: _block_ and _character_. The former has characteristics of a block of data: It has a finite size, and you can access bytes at any position in the block. The latter behaves like a flow of characters. You can read and write characters, but you cannot seek to a given position and change arbitrary bytes. To find out the type of a given device file, inspect the first letter in the output of `ls -l`. It is either `b`, for block devices, or `c`, for character devices:

```shell
$ ls -l /dev/sda /dev/ttyS0
brw-rw---- 1 root disk    8,  0 Mar 21 08:44 /dev/sda
crw-rw---- 1 root dialout 4, 64 Mar 30 08:59 /dev/ttyS0
```

As you might expect, disk drives and partitions use block devices, whereas mouse, keyboard, and serial ports use character devices. In both cases, the programming interface includes device-specific commands that can be invoked through the _ioctl_ system call.

### 1.1.2. Unifying File Systems

File systems are a prominent aspect of the kernel. Unix-like systems merge all the file stores into a single hierarchy, which allows users and applications to access data by knowing its location within that hierarchy.

The starting point of this hierarchical tree is called the root, represented by the "`/`" character. This directory can contain named subdirectories. For instance, the `home` subdirectory of `/` is called `/home/`. This subdirectory can, in turn, contain other subdirectories, and so on. Each directory can also contain files, where the data will be stored. Thus, `/home/kali/Desktop/hello.txt` refers to a file named `hello.txt` stored in the `Desktop` subdirectory of the `kali` subdirectory of the `home` directory, present in the root. The kernel translates between this naming system and the storage location on a disk.

Unlike other systems, Linux possesses only one such hierarchy, and it can integrate data from several disks. One of these disks becomes the root, and the others are _mounted_ on directories in the hierarchy (the Linux command is called `mount`). These other disks are then available under the _mount points_. This allows storing users' home directories (traditionally stored within `/home/`) on a separate hard disk, which will contain the `kali` directory (along with home directories of other users). Once you mount the disk on `/home/`, these directories become accessible at their usual locations, and paths such as `/home/kali/Desktop/hello.txt` keep working.

There are many file system formats, corresponding to many ways of physically storing data on disks. The most widely known are _ext2_, _ext3_, and _ext4_, but others exist. For instance, _VFAT_ is the filesystem that was historically used by DOS and Microsoft Windows operating systems. Linux's support for VFAT allows hard disks to be accessible under Kali as well as under Microsoft Windows. In any case, you must prepare a file system on a disk before you can mount it and this operation is known as _formatting_. Commands such as `mkfs.ext4` (where `mkfs` stands for _MaKe FileSystem_) handle formatting. These commands require, as a parameter, a device file representing the partition to be formatted (for instance, `/dev/sda1`, the first partition on the first drive). This operation is destructive and should be run only once, unless you want to wipe a filesystem and start fresh.

There are also network filesystems such as NFS, which do not store data on a local disk. Instead, data is transmitted through the network to a server that stores and retrieves them on demand. Thanks to the file system abstraction, you don't have to worry about how this disk is connected, since the files remain accessible in their usual hierarchical way.

### 1.1.3. Managing Processes

A process is a running instance of a program, which requires memory to store both the program itself and its operating data. The kernel is in charge of creating and tracking processes. When a program runs, the kernel first sets aside some memory, loads the executable code from the file system into it, and then starts the code running. It keeps information about this process, the most visible of which is an identification number known as the _process identifier_ (PID).

Like most modern operating systems, those with Unix-like kernels, including Linux, are capable of multi-tasking. In other words, they allow the system to run many processes at the same time. There is actually only one running process at any one time, but the kernel divides CPU time into small slices and runs each process in turn. Since these time slices are very short (in the millisecond range), they create the appearance of processes running in parallel, although they are active only during their time interval and are idle the rest of the time. The kernel's job is to adjust its scheduling mechanisms to keep that appearance, while maximizing global system performance. If the time slices are too long, the application may not appear as responsive as desired. Too short, and the system loses time by switching tasks too frequently. These decisions can be refined with process priorities, where high-priority processes will run for longer periods and with more frequent time slices than low-priority processes.

**Multi-Processor Systems (and Variants)**

The limitation described above, of only one process running at a time, doesn't always apply: the actual restriction is that there can be only one running process _per processor core_. Multi-processor, multi-core, or _hyper-threaded_ systems allow several processes to run in parallel. The same time-slicing system is used, though, to handle cases where there are more active processes than available processor cores. This is not unusual: a basic system, even a mostly idle one, almost always has tens of running processes.

The kernel allows several independent instances of the same program to run, but each is allowed to access only its own time slices and memory. Their data thus remains independent.

### 1.1.4. Rights Management

Unix-like systems support multiple users and groups and allow control of permissions. Most of the time, a process is identified by the user who started it. That process is only permitted to take actions permitted for its owner. For instance, opening a file requires the kernel to check the process identity against access permissions (for more details on this particular example, see [_Managing Rights_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/linux-fundamentals/useful-commands/displaying-and-modifying-text-files#sect.rights-management)).

## 1.2. The Command Line

By "command line", we mean a text-based interface that allows you to enter commands, execute them, and view the results. You can run a terminal (a textual screen within the graphical desktop, or the text console itself outside of any graphical interface) and a command interpreter inside it (_the shell_).

### 1.2.1. How To Get a Command Line

When your system is working properly, the easiest way to access the command line is to run a terminal in your graphical desktop session.

![Figure 1: Starting QTerminal](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/96f244d42aef4e5ad2b1289efa4f774b-04_start-terminal.png)

Figure 1: Starting QTerminal

For instance, on a default Kali Linux system, QTerminal can be started from the list of favorite applications. You can also type "terminal" while in the applications menu (the one that gets activated when you move the mouse to the top-left corner) and click on the correct application icon that appears Figure 1).

In the event that your graphical interface is broken, you can still get a command line on virtual consoles (up to six of them can be accessible through the six key combinations of **CTRL+ALT+F1** through **CTRL+ALT+F6** — the **CTRL** key can be omitted if you are already in text mode, outside of Xorg or Wayland's graphical interface). You get a very basic login screen where you enter your login and password before being granted access to the command line with its shell:

```shell
Kali GNU/Linux Rolling kali tty3

kali login: kali
Password:
Linux kali 5.7.0-kali1-amd64 #1 SMP Debian 5.7.6-1kali2 (2020-07-01) X86_64

The programs included with the Kali GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
kali@kali:~$
```

The program handling your input and executing your commands is called a _shell_ (or a command-line interpreter). The default shell provided in Kali Linux is _ZSH_ (it stands for _Z SHell_). The trailing "$" or "#" character indicates that the shell is awaiting your input. It also indicates whether ZSH recognizes you as a normal user (the former case with the dollar, $) or as a super user (the latter case with the hash, #).

### 1.2.2. Command Line Basics: Browsing the Directory Tree and Managing Files

This section only provides a brief overview of the covered commands, all of which have many options not described here, so please refer to the abundant documentation available in their respective manual pages. In penetration tests, you will most often receive shell access to a system after a successful exploit, rather than a graphical user interface. Proficiency with the command line is essential for your success as a security professional.

Once a session is open, the `pwd` command (which stands for _print working directory_) displays your current location in the filesystem. The current directory is changed with the `cd directory` command (`cd` is for _change directory_). When you don't specify the target directory, you are taken to your home directory. When you use `cd -` (dash), you go back to the former working directory (the one in use before the last `cd` call). The parent directory is always called `..` (two dots), whereas the current directory is also known as `.` (one dot). The `ls` command allows _listing_ the contents of a directory. If you don't provide parameters, `ls` operates on the current directory.

```shell
$ pwd
/home/kali
$ cd Desktop
$ pwd
/home/kali/Desktop
$ cd .
$ pwd
/home/kali/Desktop
$ cd ..
$ pwd
/home/kali
$ ls
Desktop    Downloads  Pictures  Templates
Documents  Music      Public    Videos
```

You can create a new directory with `mkdir directory`, and remove an existing (empty) directory with `rmdir directory`. The `mv` command allows _moving_ and renaming files and directories; _removing_ a file is achieved with `rm file`, and copying a file is done with `cp source-file target-file`.

```shell
$ mkdir test
$ ls
Desktop    Downloads  Pictures  Templates  Videos
Documents  Music      Public    test
$ mv test new
$ ls
Desktop    Downloads  new       Public     Videos
Documents  Music      Pictures  Templates
$ rmdir new
$ ls
Desktop    Downloads  Pictures  Templates  Videos
Documents  Music      Public
```

The shell executes each command by running the first program of the given name that it finds in a directory listed in the `PATH` environment variable. Most often, these programs are in `/bin`, `/sbin`, `/usr/bin`, or `/usr/sbin`. For example, the `ls` command is found in `/bin/ls`; the `which` command reports the location of a given executable. Sometimes the command is directly handled by the shell, in which case, it is called a shell built-in command (`cd` and `pwd` are among those); the `type` command lets you query the type of each command.

```shell
$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$ which ls
/bin/ls
$ type rm
rm is /bin/rm
$ type cd
cd is a shell builtin
```

Note the usage of the `echo` command, which simply displays a string on the terminal. In this case, it is used to print the contents of an environment variable since the shell automatically substitutes variables with their values before executing the command line.

**Environment Variables**

Environment variables allow storage of global settings for the shell or various other programs. They are contextual but inheritable. For example, each process has its own set of environment variables (they are contextual). Shells, like login shells, can declare variables, which will be passed down to other programs they execute (they are inheritable).

These variables can be defined system-wide in `/etc/profile` or per-user in `~/.profile` but variables that are not specific to command line interpreters are better put in `/etc/environment`, since those variables will be injected into all user sessions thanks to a Pluggable Authentication Module (PAM) – even when no shell is executed.

### 1.3.1. The Filesystem Hierarchy Standard

As with other Linux distributions, Kali Linux is organized to be consistent with the _Filesystem Hierarchy Standard_ (FHS), allowing users of other Linux distributions to easily find their way around Kali. The FHS defines the purpose of each directory. The top-level directories are described as follows:

- `/bin/`: basic programs.
- `/boot/`: Kali Linux kernel and other files required for its early boot process.
- `/dev/`: device files.
- `/etc/`: configuration files.
- `/home/`: user's personal files.
- `/lib/`: basic libraries.
- `/media/`: mount points for removable devices (CD/DVD-ROM, USB keys, and so on).
- `/mnt/`: temporary mount point.
- `/opt/`: extra applications provided by third parties.
- `/root/`: administrator's (root's) personal files.
- `/run/`: volatile runtime data that does not persist across reboots (not yet included in the FHS).
- `/sbin/`: system programs.
- `/srv/`: data used by servers hosted on this system.
- `/tmp/`: temporary files (this directory is often emptied at boot).
- `/usr/`: applications (this directory is further subdivided into `bin`, `sbin`, `lib` according to the same logic as in the root directory) Furthermore, `/usr/share/` contains architecture-independent data. The `/usr/local/` directory is meant to be used by the administrator for installing applications manually without overwriting files handled by the packaging system (`dpkg`).
- `/var/`: variable data handled by services. This includes log files, queues, spools, and caches.
- `/proc/` and `/sys/` are specific to the Linux kernel (and not part of the FHS). They are used by the kernel for exporting data to user space.

### 1.3.2. The User's Home Directory

The contents of a user's home directory are not standardized but there are still a few noteworthy conventions. One is that a user's home directory is often referred to by a tilde (`~`). That is useful to know because command interpreters automatically replace a tilde with the correct directory (which is stored in the `HOME` environment variable, and whose usual value is `/home/user/`).

Traditionally, application configuration files are often stored directly under your home directory, but the filenames usually start with a dot (for instance, the `mutt` email client stores its configuration in `~/.muttrc`). Note that filenames that start with a dot are hidden by default; the `ls` command only lists them when the `-a` option is used and graphical file managers need to be explicitly configured to display hidden files.

Some programs also use multiple configuration files organized in one directory (for instance, `~/.ssh/`). Some applications (such as the Firefox web browser) also use their directory to store a cache of downloaded data. This means that those directories can end up consuming a lot of disk space.

These configuration files stored directly in your home directory, often collectively referred to as _dotfiles_, have long proliferated to the point that these directories can be quite cluttered with them. Fortunately, an effort led collectively under the [FreeDesktop.org](https://www.freedesktop.org/) umbrella has resulted in the XDG Base Directory Specification, a convention that aims at cleaning up these files and directories. This specification states that configuration files should be stored under `~/.config`, cache files under `~/.cache`, and application data files under `~/.local` (or subdirectories thereof). This convention is slowly gaining traction.

Graphical desktops usually have shortcuts to display the contents of the `~/Desktop/` directory (or whatever the appropriate translation is for systems not configured in English).

Finally, the email system sometimes stores incoming emails into a `~/Mail/` directory.

### 1.4.1. Displaying and Modifying Text Files

The `cat file` command (intended to _concatenate_ files to the standard output device) reads a file and displays its contents on the terminal. If the file is too big to fit on a screen, you can use a pager such as `less` (or `more`) to display it page by page.

The `editor` command starts a text editor (such as **Vi** or **Nano**) and allows creating, modifying, and reading text files. The simplest files can sometimes be created directly from the command interpreter thanks to redirection: `command > file` creates a file named file containing the output of the given command. `command >> file` is similar except that it appends the output of the command to the file rather than overwriting it.

```shell
$ echo "Kali rules!" > kali-rules.txt
$ cat kali-rules.txt
Kali rules!
$ echo "Kali is the best!" >> kali-rules.txt
$ cat kali-rules.txt
Kali rules!
Kali is the best!
```

### 1.4.2. Searching for Files and within Files

The `find directory criteria` command searches for files in the hierarchy under directory according to several criteria. The most commonly used criterion is `-name filename`, which allows searching for a file by name. You can also use common wildcards such as "`*`" in the filename search.

```shell
$ find /etc -name hosts
/etc/hosts
/etc/avahi/hosts
$ find /etc -name "hosts*"
/etc/hosts
/etc/hosts.allow
/etc/hosts.deny
/etc/avahi/hosts
```

The `grep expression files` command searches the contents of the files and extracts lines matching the regular expression. Adding the `-r` option enables a recursive search on all files contained in the directory. This allows you to look for a file when you only know a part of its contents.

### 1.4.3. Managing Processes

The `ps aux` command lists the processes currently running and helps to identify them by showing their PID. Once you know the _PID_ of a process, the `kill -signal pid` command allows you to send it a signal (if you own the process). Several signals exist; most commonly used are `TERM` (a request to terminate gracefully) and `KILL` (a forced kill).

The command interpreter can also run programs in the background if the command is followed by `&`. By using the ampersand, you resume control of the shell immediately even though the command is still running (hidden from view as a background process). The `jobs` command lists the processes running in the background; running `fg %job-number` (for _foreground_) restores a job to the foreground. When a command is running in the foreground (either because it was started normally, or brought back to the foreground with `fg`), the **Control+Z** key combination pauses the process and resumes control of the command line. The process can then be restarted in the background with `bg %job-number` (for _background_).

### 1.4.4. Managing Rights

Linux is a multi-user system so it is necessary to provide a permissions system to control the set of authorized operations on files and directories, which includes all the system resources and devices (on a Unix system, any device is represented by a file or directory). This principle is common to all Unix-like systems.

Each file or directory has specific permissions for three categories of users:

- Its owner (symbolized by `u`, as in User).
- Its owner group (symbolized by `g`, as in Group), representing all the members of the group.
- The others (symbolized by `o`, as in Other).

Three types of rights can be combined:

- Reading (symbolized by `r`, as in Read).
- Writing (or modifying, symbolized by `w`, as in Write).
- Executing (symbolized by `x`, as in eXecute).

In the case of a file, these rights are easily understood: read access allows reading the content (including copying), write access allows changing it, and execute access allows running it (which will only work if it is a program).

**setuid and setgid executables**

Two particular rights are relevant to executable files: `setuid` and `setgid` (symbolized with the letter `s`). Note that we frequently speak of bit, since each of these boolean values can be represented by a 0 or a 1. These two rights allow any user to execute the program with the rights of the owner or the group, respectively. This mechanism grants access to features requiring higher level permissions than those you would usually have.

Since a `setuid` root program is systematically run under the super-user identity, it is very important to ensure it is secure and reliable. Any user who manages to subvert a setuid root program to call a command of their choice could then impersonate the root user and have all rights on the system. Penetration testers regularly search for these types of files when they gain access to a system as a way of escalating their privileges.

A directory is handled differently from a file. Read access gives the right to consult the list of its contents (files and directories); write access allows creating or deleting files; and execute access allows crossing through the directory to access its contents (for example, with the `cd` command). Being able to cross through a directory without being able to read it gives the user permission to access the entries therein that are known by name, but not to find them without knowing their exact name.

**SECURITY setgid directory and sticky bit**

The `setgid` bit also applies to directories. Any newly-created item in such directories is automatically assigned the owner group of the parent directory, instead of inheriting the creator's main group as usual. Because of this, you don't have to change your main group (with the `newgrp` command) when working in a file tree shared between several users of the same dedicated group.

The _sticky bit_ (symbolized by the letter "t") is a permission that is only useful in directories. It is especially used for temporary directories where everybody has write access (such as `/tmp/`): it restricts deletion of files so that only their owner or the owner of the parent directory can delete them. Lacking this, everyone could delete other users' files in `/tmp/`.

Three commands control the permissions associated with a file:

- `chown user file` changes the owner of the file.
- `chgrp group file` alters the owner group.
- `chmod rights file` changes the permissions for the file.

**_TIP_ Changing the user and group**

Frequently you want to change the group of a file at the same time that you change the owner. The `chown` command has a special syntax for that: `chown user:group file`

There are two ways of representing rights. Among them, the symbolic representation is probably the easiest to understand and remember. It involves the letter symbols mentioned above. You can define rights for each category of users (`u`/`g`/`o`), by setting them explicitly (with `=`), by adding (`+`), or subtracting (`-`). Thus the `u=rwx,g+rw,o-r` formula gives the owner read, write, and execute rights, adds read and write rights for the owner group, and removes read rights for other users. Rights not altered by the addition or subtraction in such a command remain unmodified. The letter `a`, for all, covers all three categories of users, so that `a=rx` grants all three categories the same rights (read and execute, but not write).

The (octal) numeric representation associates each right with a value: 4 for read, 2 for write, and 1 for execute. We associate each combination of rights with the sum of the three figures, and a value is assigned to each category of users, in the usual order (owner, group, others).

For instance, the `chmod 754 file` command will set the following rights: read, write and execute for the owner (since 7 = 4 + 2 + 1); read and execute for the group (since 5 = 4 + 1); read-only for others. The `0` means no rights; thus `chmod 600 file` allows for read and write permissions for the owner, and no rights for anyone else. The most frequent right combinations are `755` for executable files and directories, and `644` for data files.

To represent special rights, you can prefix a fourth digit to this number according to the same principle, where the `setuid`, `setgid`, and `sticky` bits are 4, 2, and 1, respectively. The command `chmod 4754` will associate the `setuid` bit with the previously described rights.

Note that the use of octal notation only allows you to set all the rights at once on a file; you cannot use it to add a new right, such as read access for the group owner, since you must take into account the existing rights and compute the new corresponding numerical value.

The octal representation is also used with the `umask` command, which is used to restrict permissions on newly created files. When an application creates a file, it assigns indicative permissions, knowing that the system automatically removes the rights defined with `umask`. Enter `umask` in a shell; you will see a mask such as `0022`. This is simply an octal representation of the rights to be systematically removed (in this case, the write rights for the group and other users).

If you give it a new octal value, the `umask` command modifies the mask. Used in a shell initialization file (for example, `~/.bash_profile`), it will effectively change the default mask for your work sessions.

**_TIP_ Recursive operation**

Sometimes we have to change rights for an entire file tree. All the commands above have a `-R` option to operate recursively in sub-directories.

The distinction between directories and files sometimes causes problems with recursive operations. That is why the "X" letter has been introduced in the symbolic representation of rights. It represents a right to execute which applies only to directories (and not to files lacking this right). Thus, `chmod -R a+X directory` will only add execute rights for all categories of users (`a`) for all of the sub-directories and files for which at least one category of user (even if their sole owner) already has execute rights.

### 1.4.5. Getting System Information and Logs

The `free` command displays information on memory; (`df` (for _disk free*) reports on the available disk space on each of the disks mounted in the file system. Its `-h` option (for *human readable_) converts the sizes into a more legible unit (usually mebibytes or gibibytes). In a similar fashion, the `free` command supports the `-m` and `-g` options, and displays its data either in mebibytes or in gibibytes, respectively.

```shell
$ free
              total        used        free      shared  buff/cache   available
Mem:        2052944      661232      621208       10520      770504     1359916
Swap:             0           0           0
$ df
Filesystem     1K-blocks     Used Available Use% Mounted on
udev             1014584        0   1014584   0% /dev
tmpfs             205296     8940    196356   5% /run
/dev/vda1       30830588 11168116  18073328  39% /
tmpfs            1026472      456   1026016   1% /dev/shm
tmpfs               5120        0      5120   0% /run/lock
tmpfs            1026472        0   1026472   0% /sys/fs/cgroup
tmpfs             205296       36    205260   1% /run/user/132
tmpfs             205296       24    205272   1% /run/user/0
```

The `id` command displays the identity of the user running the session along with the list of groups they belong to. Since access to some files or devices may be limited to group members, checking available group membership may be useful.

```shell
$ id
uid=1000(kali) gid=1000(kali) groups=1000(kali),27(sudo)
```

The `uname -a` command returns a single line documenting the kernel name (`Linux`), the hostname, the kernel release, the kernel version, the machine type (an architecture string such as `x86_64`), and the name of the operating system (`GNU/Linux`). The output of this command should usually be included in bug reports as it clearly defines the kernel in use and the hardware platform you are running on.

```shell
$ uname -a
Linux kali 5.8.0-kali3-amd64 #1 SMP Debian 5.8.14-1kali1 (2020-10-13) x86_64 GNU/Linux
```

All these commands provide run-time information, but often you need to consult logs to understand what happened on your computer. In particular, the kernel emits messages that it stores in a ring buffer whenever something interesting happens (such as a new USB device being inserted, a failing hard disk operation, or initial hardware detection on boot). You can retrieve the kernel logs with the `dmesg` command.

Systemd's journal also stores multiple logs (stdout/stderr output of services, syslog messages, kernel logs) and makes it easy to query them with `journalctl`. Without any arguments, it just dumps all the available logs in a chronological way. With the `-r` option, it will reverse the order so that newer messages are shown first. With the `-f` option, it will continuously print new log entries as they are appended to its database. The `-u` option can limit the messages to those emitted by a specific systemd unit (ex: `journalctl -u ssh.service`).

### 1.4.6. Discovering the Hardware

The kernel exports many details about detected hardware through the `/proc/` and `/sys/` virtual filesystems. Several tools summarize those details. Among them, `lspci` (in the _pciutils* package) lists PCI devices, `lsusb` (in the _usbutils* package) lists USB devices, and `lspcmcia` (in the _pcmciautils_ package) lists PCMCIA cards. These tools are very useful for identifying the exact model of a device. This identification also allows more precise searches on the web, which in turn, lead to more relevant documents. Note that the _pciutils_ and _usbutils_ packages are already installed on the base Kali system but _pcmciautils_ must be installed with `apt update` followed by `apt install pcmciautils`. We will discuss more about package installation and management in [_Basic Package Interaction_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/debian-package-management/basic-package-interaction/basic-package-interaction).

**Example of information provided by lspci and lsusb**

```shell
$ lspci
[...]
00:02.1 Display controller: Intel Corporation Mobile 915GM/GMS/910GML Express Graphics Controller (rev 03)
00:1c.0 PCI bridge: Intel Corporation 82801FB/FBM/FR/FW/FRW (ICH6 Family) PCI Express Port 1 (rev 03)
00:1d.0 USB Controller: Intel Corporation 82801FB/FBM/FR/FW/FRW (ICH6 Family) USB UHCI #1 (rev 03)
[...]
01:00.0 Ethernet controller: Broadcom Corporation NetXtreme BCM5751 Gigabit Ethernet PCI Express (rev 01)
02:03.0 Network controller: Intel Corporation PRO/Wireless 2200BG Network Connection (rev 05)
$ lsusb
Bus 005 Device 004: ID 413c:a005 Dell Computer Corp.
Bus 005 Device 008: ID 413c:9001 Dell Computer Corp.
Bus 005 Device 007: ID 045e:00dd Microsoft Corp.
Bus 005 Device 006: ID 046d:c03d Logitech, Inc.
[...]
Bus 002 Device 004: ID 413c:8103 Dell Computer Corp. Wireless 350 Bluetooth
```

These programs have a `-v` option that lists much more detailed (but usually unnecessary) information. Finally, the `lsdev` command (in the _procinfo_ package) lists communication resources used by devices.

The `lshw` program is a combination of the above programs and displays a long description of the hardware discovered in a hierarchical manner. You should attach its full output to any report about hardware support problems.

- Next Module -> [About Kali Linux 🍳](about_kali.md)