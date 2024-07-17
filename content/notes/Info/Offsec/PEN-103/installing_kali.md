---
title: Installing Kali Linux ✏️
tags:
  - Offsec
  - PEN-103
---
- *All the info was extracted from [Offsec, Pen-103](https://portal.offsec.com/courses/pen-103-16306/)*, under the following [licencese](https://creativecommons.org/licenses/by-sa/3.0/)

# 5. Installing Kali Linux

In this chapter, we will focus on the Kali Linux installation process. First, we will discuss the minimum installation requirements ([_Minimal Installation Requirements_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/installing-kali-linux/minimal-installation-requirements/minimal-installation-requirements)) to ensure that your real or virtual system is well-configured to handle the type of installation that you will pursue. Then we will go through each step of the installation process ([_Step-by-Step Installation on a Hard Drive_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/installing-kali-linux/step-by-step-installation-on-a-hard-drive/step-by-step-installation-on-a-hard-drive)) for a plain installation, as well as for a more secure installation involving a fully encrypted file system. We will also discuss _preseeding_, which allows unattended installations ([_Unattended Installations_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/installing-kali-linux/unattended-installations/unattended-installations)) by providing predetermined answers to installation questions. We will also show you how to install Kali Linux on various ARM devices ([_ARM Installations_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/installing-kali-linux/arm-installations/arm-installations)), which expands Kali's capabilities far beyond the desktop. Finally, we will show you what to do in the rare case of an installation failure ([_Troubleshooting Installations_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/installing-kali-linux/troubleshooting-installations/troubleshooting-installations)), so you can work through the issue and successfully finish a tough install.

## 5.1. Minimal Installation Requirements

The installation requirements for Kali Linux vary depending on what you would like to install. On the low end, you can set up Kali as a basic Secure Shell (SSH) server with no desktop, using as little as 128 MB of RAM (512 MB recommended) and 2 GB of disk space. On the higher end, if you opt to install the default Xfce desktop and the _kali-linux-default_ metapackage, you should really aim for at least 2048 MB of RAM and 20 GB of disk space.

Besides the RAM and hard disk requirements, your computer needs to have a CPU supported by at least one of the amd64, i386, or arm64 architectures.

## 5.2. Step-by-Step Installation on a Hard Drive

In this section, we assume that you have a bootable USB drive or DVD (see [_Copying the Image on a DVD-ROM or USB Key_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/getting-started-with-kali-linux/downloading-a-kali-iso-image/where-to-download#sect.copying-the-image) for details on how to prepare such a drive) and that you booted from it to start the installation process.

### 5.2.1. Plain Installation

First, we will take a look at a standard Kali installation, with an unencrypted file system.

#### Booting and Starting the Installer

Once the BIOS/UEFI has begun booting from the USB drive or DVD-ROM, the isolinux boot loader menu appears, as shown in Figure 1. At this stage, the Linux kernel is not yet loaded; this menu allows you to choose the kernel to boot and enter optional parameters to be transferred to it in the process.

Using the arrow keys todo a standard installation, either choose Graphical Install or Install (for classic text-mode), then press the **Enter** key to initiate the remainder of the installation process.

Each menu entry hides a specific boot command line, which can be configured as needed by pressing the **Tab** key before validating the entry and booting.

![Figure 1: Boot Screen](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/0e0071fb612554a67d399f77423f3ef8-05_install-boot-screen.png)

Figure 1: Boot Screen

Once booted, the installation program guides you step-by-step through the process. We will take a look at each of these steps in detail. We will cover installation from a standard Kali Linux live image; installations from a `mini.iso` may look slightly different. We will also address graphical mode installation, but the only difference from classic text-mode installation is the appearance. The versions pose identical questions and present identical options.

#### Selecting the Language

As shown in Figure 2, the installation program begins in English but the first step allows you to choose the language that will be used for the rest of the installation process. This language choice is also used to define more relevant default choices in subsequent stages (notably the keyboard layout).

**Navigating with the Keyboard**

Some steps in the installation process require you to enter information. These screens have several areas that may gain focus (text entry area, checkboxes, list of choices, OK and Cancel buttons), and the **Tab** key allows you to move from one to another.

In graphical installation mode, you can use the mouse as you would normally on an installed graphical desktop.

![Figure 2: Selecting the Language](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/27536080760613cd64a95b654dd403a0-05_install-step-01-language.png)

Figure 2: Selecting the Language

#### Selecting the Country

The second step Figure 3) consists of choosing your country. Combined with the language, this information enables the installation program to offer the most appropriate keyboard layout. This will also influence the configuration of the time zone. In the United States, a standard QWERTY keyboard is suggested and the installer presents a choice of appropriate time zones.

![Figure 3: Selecting the Country](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/a618563a694b26c23a74a06c32e40127-05_install-step-02-country.png)

Figure 3: Selecting the Country

#### Selecting the Keyboard Layout

The proposed American English keyboard corresponds to the usual QWERTY layout as shown in Figure 4.

![Figure 4: Choice of Keyboard](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/de0bf02c27ab6fa8596e19738fba8f4e-05_install-step-03-keyboard.png)

Figure 4: Choice of Keyboard

#### Detecting Hardware

In the vast majority of cases, the hardware detection step is completely automatic. The installer detects your hardware and tries to identify the boot device used in order to access its content. It loads the modules corresponding to the various hardware components detected and then mounts the boot device in order to read it. The previous steps were completely contained in the boot image included on the boot device, a file of limited size and loaded into memory by the bootloader when booting from the boot device.

#### Loading Components

With the contents of the boot device now available, the installer loads all the files necessary to continue with its work. This includes additional drivers for the remaining hardware (especially the network card), as well as all the components of the installation program.

#### Detecting Network Hardware

In this step, the installer will try to automatically identify the network card and load the corresponding module. If automatic detection fails, you can manually select the module to load. If all else fails, you can load a specific module from a removable device. This last solution is usually only needed if the appropriate driver is not included in the standard Linux kernel, but available elsewhere, such as the manufacturer's website.

This step must absolutely be successful for network installations (such as those done when booting from a `mini.iso`), since the Debian packages must be loaded from the network.

#### Configuring the Network

In order to automate the process as much as possible, the installer attempts an automatic network configuration using Dynamic Host Configuration Protocol (DHCP) (for IPv4 and IPv6) and ICMPv6's Neighbor Discovery Protocol (for IPv6), as shown in Figure 5.

![Figure 5: Network Autoconfiguration](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/a501367d152ff2a702cb3af82c6449d0-05_install-step-05-configure-network.png)

Figure 5: Network Autoconfiguration

If the automatic configuration fails, the installer offers more choices: try again with a normal DHCP configuration, attempt DHCP configuration by declaring the name of the machine, or set up a static network configuration.

This last option requires an IP address, a subnet mask, an IP address for a potential gateway, a machine name, and a domain name.

**Configuration without DHCP**

If the local network is equipped with a DHCP server that you do not wish to use because you prefer to define a static IP address for the machine during installation, you can add the `netcfg/use_dhcp=false` option when booting. You just need to edit the desired menu entry by pressing the **Tab** key and adding the desired option before pressing the **Enter** key.

#### User Creation

The installer prompts to create a new user Figure 6) since it automatically creates a user account in the "sudo" group. This means that the user has full administrative privileges through the `sudo` command. This is helpful due to the fact that multiple items are only available through administrative privileges.

The installer also asks for a username for the account as well as a password. The installer will request confirmation of the password to prevent any input error.

![Figure 6: Create User The Default User Password](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/dcf03115350f6e770ea97dea2704a8cf-05_install-step-08-user-creation.png)

Figure 6: Create User The Default User Password

The default user's password should be long (eight characters or more) and impossible to guess, since attackers target Internet-connected computers and servers with automated tools, attempting to log in with obvious passwords. Sometimes attackers leverage dictionary attacks, using many combinations of words and numbers as passwords. Avoid using the names of children or parents and dates of birth, because these are easily guessed.

These remarks are equally applicable to other user passwords but the consequences of a compromised account are less drastic for users without sudo privileges.

If you are lacking inspiration, don't hesitate to use a password generator, such as `pwgen` (found in the package of the same name, which is already included in the base Kali installation).

#### Configuring the Clock

If the network is available, the system's internal clock will be updated from a network time protocol (NTP) server. This is beneficial because it ensures timestamps on logs will be correct from the first boot.

If your country spans multiple timezones, you will be asked to select the timezone that you want to use, as shown in Figure 7.

![Figure 7: Timezone Selection](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/7fa3505e1e767b86a08d1a474a791545-05_install-step-09-timezone.png)

Figure 7: Timezone Selection

#### Detecting Disks and Other Devices

This step automatically detects the hard drives on which Kali may be installed, each of which will be presented in the next step: partitioning.

#### Partitioning

_Partitioning_ is an indispensable step in installation, which consists of dividing the available space on the hard drives into discrete sections (_partitions_) according to the intended function of the computer and those partitions. Partitioning also involves choosing the file systems to be used. All of these decisions will have an influence on performance, data security, and server administration.

The partitioning step is traditionally difficult for new users. However, the Linux file systems and partitions, including virtual memory (or _swap_ partitions) must be defined as they form the foundation of the system. This task can become complicated if you have already installed another operating system on the machine and you want the two to coexist. In this case, you must make sure not to alter its partitions, or if need be, resize them without causing damage.

To accommodate more common (and simpler) partition schemes, most users will prefer the _Guided_ mode that recommends partition configurations and provides suggestions each step of the way. More advanced users will appreciate the _Manual_ mode, which allows for more advanced configurations. Each mode shares certain capabilities.

##### Guided Partitioning

The first screen in the partitioning tool Figure 8) presents entry points for the guided and manual partitioning modes. "Guided - use entire disk" is the simplest and most common partition scheme, which will allocate an entire disk to Kali Linux.

The next two selections use Logical Volume Manager (LVM) to set up logical (instead of physical), optionally encrypted, partitions. We will discuss LVM and encryption later in this chapter with [_Installation on a Fully Encrypted File System_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/installing-kali-linux/step-by-step-installation-on-a-hard-drive/installation-on-a-fully-encrypted-file-system).

Finally, the last choice initiates manual partitioning, which allows for more advanced partitioning schemes, such as installing Kali Linux alongside other operating systems. We will discuss manual mode in the next section (Beware: The Boot Loader and Dual Boot)

In this example, we will allocate an entire hard disk to Kali, so we select "**Guided - use entire disk**" to proceed to the next step.

![Figure 8: Choice of Partitioning Mode](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/e5ed7d0fad92ca527cbaf8c9b9e21882-05_install-step-10-guided-partitioning-default.png)

Figure 8: Choice of Partitioning Mode

The next screen (shown in Figure 9) allows you to choose the disk where Kali will be installed by selecting the corresponding entry (for example, "SCSI3 (0,0,0) (sda) - 21.5 GB VMware, VMware Virtual S"). Once selected, guided partitioning will continue. This option will erase all of the data on this disk, so choose wisely.

![Figure 9: Disk to use for guided partitioning](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/d2b68c8e0cb61ed4604fba444198fb17-05_install-step-11-select-disk.png)

Figure 9: Disk to use for guided partitioning

Next, the guided partitioning tool offers three partitioning methods, which correspond to different usages, as shown in Figure 10.

![Figure 10: Guided Partition Allocation](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/735fe1c5599ff7c981b5c613b29776e5-05_install-step-12-partitioning-scheme.png)

Figure 10: Guided Partition Allocation

The first method is called "All files in one partition." The entire Linux system tree is stored in a single file system, corresponding to the root ("`/`") directory. This simple and robust partitioning scheme works perfectly well for personal or single-user systems. Despite the name, two partitions will actually be created: the first will house the complete system, the second the virtual memory (or "swap").

The second method, "Separate `/home/` partition," is similar, but splits the file hierarchy in two: one partition contains the Linux system (`/`), and the second contains "home directories" (meaning user data, in files and subdirectories available under `/home/`). One benefit to this method is that it is easy to preserve the users' data if you have to reinstall the system.

The last partitioning method, called "Separate `/home`, `/var`, and `/tmp` partitions," is appropriate for servers and multi-user systems. It divides the file tree into many partitions: in addition to the root (`/`) and user accounts (`/home/`) partitions, it also has partitions for server software data (`/var/`), and temporary files (`/tmp/`). One benefit to this method is that end users cannot lock up the server by consuming all available hard drive space (they can only fill up `/tmp/` and `/home/`). At the same time, service data (especially logs) can no longer clog up the rest of the system.

After choosing the type of partition, the installer presents a summary of your selections on the screen as a partition map [Figure 11. You can modify each partition individually by selecting a partition. For example, you could choose another file system if the standard (_ext4_) isn't appropriate. In most cases, however, the proposed partitioning is reasonable and you can accept it by selecting "Finish partitioning and write changes to disk." It may go without saying, but choose wisely as this will erase the contents of the selected disk.

![Figure 11: Validating Partitioning](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/6acd6267989f7852e742c2cb6b5caf75-05_install-step-13-partitioning-summary-default.png)

Figure 11: Validating Partitioning

##### Manual Partitioning

Selecting Manual at the main "Partition disks" screen Figure 8) permits greater flexibility, allowing you to choose more advanced configurations and specifically dictate the purpose and size of each partition. For example, this mode allows you to install Kali alongside other operating systems, enable a software-based redundant array of independent disks (RAID) to protect data from hard disk failures, and safely resize existing partitions without losing data, among other things.

If you are a less experienced user working on a system with existing data, please be very careful with this setup method as it is very easy to make mistakes that could lead to data loss.

**Shrinking a Windows Partition**

To install Kali Linux alongside an existing operating system (Microsoft Windows or other), you will need available, unused hard drive space for the partitions dedicated to Kali. In most cases, this means shrinking an existing partition and reusing the freed space.

If you are using the manual partitioning mode, the installer can shrink a Microsoft Windows partition quite easily. You only need to choose the Microsoft Windows partition and enter its new size (this works the same with both FAT and NTFS partitions).

The first screen in the manual installer is actually the same as the one shown in Figure 11, except that it doesn't include any new partitions to create. It is up to you to add those.

First, you will see an option to enter "Guided partitioning" followed by several configuration options. Next, the installer will show the available disks, their partitions, and any possible free space that has not yet been partitioned. You can select each displayed element and press the **Enter** key to interact with it, as usual.

If the disk is entirely new, you might have to create a partition table. You can do this by selecting the disk. Once done, you should see free space available within the disk.

To make use of this free space, you should select it and the installer will offer you two ways to create partitions in that space.

![Figure 12: Creating Partitions in the Free Space](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/85eaf301da6afc1e19d4aa3a5bf8148b-05_install-step-13bis-partition-free-space-1.png)

Figure 12: Creating Partitions in the Free Space

The first entry will create a single partition with the characteristics (including the size) of your choice. The second entry will use all the free space and will create multiple partitions in it with the help of the guided partitioning wizard (see [_Guided Partitioning_](https://portal.offsec.com/courses/pen-103-16306/learning/installing-kali-linux-16821/exercises-16869/kali-linux-arm-chroot-17117#sect.install-autopartman-mode)). This option is particularly interesting when you want to install Kali alongside another operating system but when you don't want to micro-manage the partition layout. The last entry will show the cylinder/head/sector numbers of the start and of the end of the free space.

When you select to "Create a new partition," you will enter into the meat of the manual partitioning sequence. After selecting this option, you will be prompted for a partition size. If the disk uses an MSDOS partition table, you will be given the option to create a primary or logical partition. (Things to know: You can only have four primary partitions but many more logical partitions. The partition containing `/boot`, and thus the kernel, must be a primary one, logical partitions reside in an extended partition, which consumes one of the four primary partitions.) Then you should see the generic partition configuration screen:

![Figure 13: Partition Configuration Screen](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/79c4dea95965620f4388139fa1dc9d9a-05_install-step-13bis-partition-free-space-2.png)

Figure 13: Partition Configuration Screen

To summarize this step of manual partitioning, let's take a look at what you can do with the new partition. You can:

- Format it and include it in the file tree by choosing a mount point. The mount point is the directory that will house the contents of the file system on the selected partition. Thus, a partition mounted at `/home/` is traditionally intended to contain user data, while "**/**" is known as the _root_ of the file tree, and therefore the root of the partition that will actually host the Kali system.
- Use it as a _swap partition_. When the Linux kernel lacks sufficient free memory, it will store inactive parts of RAM in a special swap partition on the hard disk. The virtual memory subsystem makes this transparent to applications. To simulate the additional memory, Microsoft Windows uses a swap (paging) file that is directly contained in a file system. Conversely, Linux uses a partition dedicated to this purpose, hence the term swap partition.
- Make it into a "physical volume for encryption" to protect the confidentiality of data on certain partitions. This case is automated in the guided partitioning. See [_Installation on a Fully Encrypted File System_](https://portal.offsec.com/courses/pen-103-16306/learning/installing-kali-linux-16821/exercises-16869/kali-linux-arm-chroot-17117#sect.install-encrypted) for more information.
- Make it a "physical volume for LVM" (not covered in this course). Note that this feature is used by the guided partitioning when you set up encrypted partitions.
- Use it as a RAID device (not covered in this course).
- Choose not to use the partition, and leave it unchanged.

When finished, you can either back out of manual partitioning by selecting "Undo changes to partitions" or write your changes to the disk by selecting "Finish partitioning and write changes to disk" from the manual installer screen Figure 11).

#### Copying the Live Image

This next step, which doesn't require any user interaction, copies the contents of the live image to the target file system, as shown in Figure 14.

![Figure 14: Copying the Data from the Live Image](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/666df08bda85ea9a3d16fc69788f9973-05_install-step-15-copying-live-system.png)

Figure 14: Copying the Data from the Live Image

#### Configuring the Package Manager (apt)

If you want to use a local mirror instead of `http.kali.org`, you can pass its name on the kernel command line (at boot-time) with a syntax like this: `mirror/http/hostname=my.own.mirror`.

The installer program proposes to use an _HTTP proxy_ as shown in Figure 15. An HTTP proxy is a server that forwards HTTP requests for network users. It sometimes helps to speed up downloads by keeping a copy of files that have been transferred through it (we then speak of a caching proxy). In some cases, it is the only means of accessing an external web server; in such cases the installer will only be able to download the Debian packages if you properly fill in this field during installation. If you do not provide a proxy address, the installer will attempt to connect directly to the Internet.

![Figure 15: Use an HTTP Proxy](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/6a0c2f5e6a477b2d35afd413a253791c-05_install-step-17-http-proxy.png)

Figure 15: Use an HTTP Proxy

Next, the `Packages.xz` and `Sources.xz` files will be automatically downloaded to update the list of packages recognized by APT.

#### Installing Metapackages

If you are installing the system from either the installer or netinstaller images, you will now be given the option to pick which packages you would like to install. Keep in mind that this will require Internet access if you are using the netinstaller image. You are given the choice of Desktop Environment and which tool selection you would like to be included. You can also change these selections at any time after Kali Linux has been installed, even if you use the live image to install Kali.

![Figure 16: Installing Metapackages](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/2141d2801f97b191b3c22ad5f865c5a0-05_install-step-16-metapackages.png)

Figure 16: Installing Metapackages

Next, the `Packages.xz` and `Sources.xz` files will be automatically downloaded to update the list of packages recognized by APT.

#### Installing the GRUB Boot Loader

The boot loader is the first program started by the BIOS. This program loads the Linux kernel into memory and then executes it. The boot loader often offers a menu that allows you to choose the kernel to load or the operating system to boot.

Due to its technical superiority, GRUB is the default boot loader installed by Kali: it works with most file systems and therefore doesn't require an update after each installation of a new kernel, since it reads its configuration during boot and finds the exact position of the new kernel.

You should install GRUB to the Master Boot Record (MBR) unless you already have another Linux system installed that knows how to boot Kali Linux. As noted in Figure 17, modifying the MBR will make unrecognized operating systems that depend on it unbootable until you fix GRUB's configuration.

![Figure 17: Install the GRUB Boot Loader on a Hard Disk](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/d752a1f59c6c1dac339009e4c67eb0da-05_install-step-19-install-grub.png)

Figure 17: Install the GRUB Boot Loader on a Hard Disk

In this step Figure 18), you must select which device GRUB will be installed on. This should be your current boot drive.

![Figure 18: Device for Boot Loader Installation](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/04a878dcd0f5fc7305bc0f3ed1857b56-05_install-step-20-device-for-bootloader.png)

Figure 18: Device for Boot Loader Installation

By default, the boot menu proposed by GRUB shows all the installed Linux kernels, as well as any other operating systems that were detected. This is why you should accept the offer to install it in the Master Boot Record. Keeping older kernel versions preserves the ability to boot the system if the most recently installed kernel is defective or poorly adapted to the hardware. We thus recommend that you keep a few older kernel versions installed.

**Beware: The Boot Loader and Dual Boot**

This phase in the installation process detects the operating systems that are already installed on the computer and will automatically add corresponding entries in the boot menu. However, not all installation programs do this.

In particular, if you install (or reinstall) Microsoft Windows thereafter, the boot loader will be erased. Kali will still be on the hard drive, but will no longer be accessible from the boot menu. You would then have to start the Kali installer with the `rescue/enable=true` parameter on the kernel command line to reinstall the boot loader. This operation is described in detail in the [Debian installation manual](https://www.debian.org/releases/stable/amd64/ch08s06.en.html)

#### Finishing the Installation and Rebooting

Now that installation is complete, the program asks you to unplug your USB drive or remove the DVD-ROM from the reader so that your computer can boot into your new Kali system after the installer restarts the system Figure 19).

Finally, the installer will do some cleanup work, like removing packages that are specific to creating the live environment. It will also detect if Kali Linux has been installed in a Virtual Machine (VM) and automatically install any guest tools to help integrate between the host and Kali guest.

![Figure 19: Installation Complete](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/0c12dcde78d259ad86038253469edd89-05_install-step-22-installation-complete.png)

Figure 19: Installation Complete

### 5.2.2. Installation on a Fully Encrypted File System

To guarantee the confidentiality of your data, you can set up encrypted partitions. This will protect your data if your laptop or hard drive is lost or stolen. The partitioning tool can help you in this process, both in guided and manual mode.

The guided partitioning mode will combine the use of two technologies: Linux Unified Key Setup (LUKS) for encrypting partitions and Logical Volume Management (LVM) for managing storage dynamically. Both features can also be set up and configured through manual partitioning mode.

#### Introduction to LVM

Let's discuss LVM first. Using LVM terminology, a _virtual partition_ is a logical volume, which is part of a _volume group_, or an association of several physical volumes. Physical volumes are real partitions (or virtual partitions exported by other abstractions, such as a software RAID device or an encrypted partition).

With its lack of distinction between "physical" and "logical" partitions, LVM allows you to create "virtual" partitions that span several disks. The benefits are twofold: the size of the partitions is no longer limited by individual disks but by their cumulative volume, and you can resize existing partitions at any time, such as after adding an additional disk.

This technique works in a very simple way: each volume, whether physical or logical, is split into blocks of the same size, which LVM correlates. The addition of a new disk will cause the creation of a new physical volume providing new blocks that can be associated to any volume group. All of the partitions in the volume group can then take full advantage of the additional allocated space.

#### Introduction to LUKS

To protect your data, you can add an encryption layer underneath your file system of choice. Linux (and more particularly the _dm-crypt_ driver) uses the device mapper to create the virtual partition (whose contents are protected) based on an underlying partition that will store the data in an encrypted form (thanks to LUKS). LUKS standardizes the storage of the encrypted data as well as meta-information that indicates the encryption algorithms used.

We will be setting up LUKS as part for our "nuke" feature later in [Adding a Nuke Password for Extra Safety](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/advanced-usage/adding-persistence-to-the-live-iso-with-a-usb-key/using-multiple-persistence-stores).

**Encrypted Swap Partition**

When an encrypted partition is used, the encryption key is stored in memory (RAM), and when hibernating, a laptop will copy the key, along with other contents of RAM, to the hard disk's swap partition. Since anyone with access to the swap file (including a technician or a thief) could extract the key and decrypt your data, the swap file must be protected with encryption.

Because of this, the installer will warn you if you try to use an encrypted partition alongside an unencrypted swap partition.

#### Setting Up Encrypted Partitions

The installation process for encrypted LVM is the same as a standard installation except for the partitioning step Figure 20) where you will instead select "Guided - use entire disk and set up encrypted LVM." The net result will be a system that cannot be booted or accessed until the encryption passphrase is provided. This will encrypt and protect the data on your disk.

![Figure 20: Guided Partitioning with Encrypted LVM](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/85498fa7225c655009470620f091f658-05_install-step-10-guided-partitioning-encrypted.png)

Figure 20: Guided Partitioning with Encrypted LVM

The guided partitioning installer will automatically assign a physical partition for the storage of encrypted data, as shown in Figure 21. At this point, the installer will confirm the changes before they are written on the disk.

![Figure 21: Confirm Changes to the Partition Table](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/d406cfe5f293e2e0771fc24af8660410-05_install-step-12bis-confirm-write-for-encrypted-lvm.png)

Figure 21: Confirm Changes to the Partition Table

This new partition is then initialized with random data, as shown in Figure 22. This makes the areas that contain data indistinguishable from the unused areas, making it more difficult to detect, and subsequently attack, the encrypted data.

![Figure 22: Erasing Data on Encrypted Partition](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/ea98bf31dae788761372501d95b5e461-05_install-step-12ter-erase-partition-for-encrypted-lvm.png)

Figure 22: Erasing Data on Encrypted Partition

Next, the installer asks you to enter an encryption passphrase Figure 23). In order to view the contents of the encrypted partition, you will need to enter this passphrase every time you reboot the system. Note the warning in the installer: your encrypted system will only be as strong as this passphrase.

![Figure 23: Enter Your Encryption Passphrase](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/d3f0985370a375c2f2791c8e7b63a21e-05_install-step-12quarto-encryption-passphrase.png)

Figure 23: Enter Your Encryption Passphrase

The partitioning tool now has access to a new virtual partition whose contents are stored encrypted in the underlying physical partition. Since LVM uses this new partition as a physical volume, it can protect several partitions (or LVM logical volumes) with the same encryption key, including the swap partition (see sidebar [Encrypted Swap Partition](https://portal.offsec.com/courses/pen-103-16306/learning/installing-kali-linux-16821/exercises-16869/kali-linux-arm-chroot-17117#sidebar.encrypted-swap-partition)). Here, LVM is not used to make it easy to extend the storage size, but just for the convenience of the indirection allowing to split a single encrypted partition into multiple logical volumes.

#### End of the Guided Partitioning with Encrypted LVM

Next, the resulting partitioning scheme is displayed Figure 24) so you can tweak settings as needed.

![Figure 24: Validating Partitioning for Encrypted LVM Installation](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/7377b0065d860201a6d047edfc0ad80d-05_install-step-13-partitioning-summary-encrypted-lvm.png)

Figure 24: Validating Partitioning for Encrypted LVM Installation

Finally, after validating the partition setup, the tool asks for confirmation to write the changes on the disks, as shown in Figure 25.

![Figure 25: Confirm Partitions to be Formatted](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/f651e10a0ab2c24d6a06a2773e8e880e-05_install-step-14-confirm-write-encrypted-lvm.png)

Figure 25: Confirm Partitions to be Formatted

Finally, the installation process continues as usual as documented in [_Configuring the Package Manager (apt)_](https://portal.offsec.com/courses/pen-103-16306/learning/installing-kali-linux-16821/exercises-16869/kali-linux-arm-chroot-17117#sect.install-config-apt).

## 5.3. Unattended Installations

The Debian and Kali installers are very modular: at the basic level, they are just executing many scripts (packaged in tiny packages called udeb—for μdeb or micro-deb) one after another. Each script relies on `debconf` (see [The **debconf** Tool](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/debian-package-management/apt-package-reference:-digging-deeper-into-the-debian-package-system/configuration-scripts), which interacts with you, the user, and stores installation parameters. Because of this, the installer can also be automated through debconf preseeding, a function that allows you to provide unattended answers to installation questions.

### 5.3.1. Preseeding Answers

There are multiple ways to preseed answers to the installer. Each method has its own advantages and disadvantages. Depending on when the preseeding happens, the questions that can be preseeded vary.

#### With Boot Parameters

You can preseed any installer question with boot parameters that end up in the kernel command-line, accessible through `/proc/cmdline`. Some bootloaders will let you edit these parameters interactively (which is practical for testing purposes), but if you want to make the changes persistent, you will have to modify the bootloader configuration.

You can directly use the full identifier of the debconf questions (such as `debian-installer/language=en`) or you can use abbreviations for the most common questions (like `language=en` or `hostname=kali`). See the [full list](https://www.debian.org/releases/stable/amd64/apbs02#preseed-aliases) of aliases in the Debian installation manual.

There is no restriction on which questions you can preseed since boot parameters are available from the start of the installation process and they are processed very early. However, the number of boot parameters is limited to 32 and a number of those are already used by default. It is also important to realize that changing the boot loader configuration can be non-trivial at times.

In [_Building Custom Kali Live ISO Images_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/advanced-usage/building-custom-kali-live-iso-images/building-custom-kali-live-iso-images) you will also learn how to modify the isolinux configuration when you generate your own Kali ISO image.

#### With a Preseed File in the Initrd

You can add a file named `preseed.cfg` at the root of the installer's `initrd` (this is the initrd which is used to start the installer). Usually, this requires rebuilding the debian-installer source package to generate new versions of the initrd. However, `live-build` offers a convenient way to do this, which is detailed in [_Building Custom Kali Live ISO Images_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/advanced-usage/building-custom-kali-live-iso-images/building-custom-kali-live-iso-images).

This method also does not have any restrictions on the questions that you can preseed as the preseed file is available immediately after boot. In Kali, we already make use of this feature to customize the behavior of the official Debian installer.

#### With a Preseed File in the Boot Media

You can add a preseed file on the boot media (DVD or USB key); preseeding then happens as soon as the media is mounted, which means right after the questions about language and keyboard layout. The `preseed/file` boot parameter can be used to indicate the location of the preseeding file (for instance, `/cdrom/preseed.cfg` when installing from a DVD-ROM, or `/hd-media/preseed.cfg` when installing from a USB key).

You may not preseed answers to language and country options as the preseeding file is loaded later in the process, once the hardware drivers have been loaded. On the positive side, `live-build` makes it easy to put a supplementary file in the generated ISO images (see [_Building Custom Kali Live ISO Images_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/advanced-usage/building-custom-kali-live-iso-images/building-custom-kali-live-iso-images)).

#### With a Preseed File Loaded from the Network

You can make a preseed file available on the network through a web server and tell the installer to download that preseed file by adding the boot parameter `preseed/url=http://server/preseed.cfg` (or by using the `url` alias).

However, when using this method, remember that the network must first be configured. This means that network-related debconf questions (in particular hostname and domain name) and all the preceding questions (like language and country) cannot be preseeded with this method. This method is most often used in combination with boot parameters preseeding those specific questions.

This preseeding method is the most flexible one as you can change the installation configuration without changing the installation media.

**Delaying the Language, Country, Keyboard Questions**

To overcome the limitation of not being able to preseed the language, country, and keyboard questions, you can add the boot parameter `auto-install/enable=true` (or `auto=true`). With this option the questions will be asked later in the process, after the network has been configured and thus after download of the preseed file.

The downside is that the first steps (notably network configuration) will always happen in English and if there are errors the user will have to work through English screens (with a keyboard configured in QWERTY).

### 5.3.2. Creating a Preseed File

A preseed file is a plain text file in which each line contains the answer to one Debconf question. A line is split across four fields separated by white space (spaces or tabs). For instance, `d-i mirror/suite string kali-rolling`:

- The first field indicates the owner of the question. For example, "d-i" is used for questions relevant to the installer. You may also see a package name, for questions coming from Debian packages (as in this example: `atftpd atftpd/use_inetd boolean false`).
- The second field is an identifier for the question.
- The third field lists the type of question.
- The fourth and final field contains the value for the expected answer. Note that it must be separated from the third field with a single space; additional space characters are considered part of the value.

The simplest way to write a preseed file is to install a system by hand. Then the `debconf-get-selections --installer` command will provide the answers you provided to the installer. You can obtain answers directed to other packages with `debconf-get-selections`. However, a cleaner solution is to write the preseed file by hand, starting from an example and then going through the documentation. With this approach, only questions where the default answer needs to be overridden can be preseeded. Provide the `priority=critical` boot parameter to instruct Debconf to only ask critical questions, and to use the default answer for others.

**Installation Guide Appendix**

The Debian installation guide, available online, includes detailed documentation on the use of a preseed file in an appendix. It also includes a detailed and commented sample file, which can serve as a base for local customizations.

> [https://www.debian.org/releases/stable/amd64/apb](https://www.debian.org/releases/stable/amd64/apb)
> 
> [https://www.debian.org/releases/stable/example-preseed.txt](https://www.debian.org/releases/stable/example-preseed.txt)

Note however, that the above links document the stable version of Debian and that Kali uses the testing version so you may encounter slight differences. You can also consult the installation manual hosted on the Debian-installer project's website. It may be more up-to-date.

## 5.4. ARM Installations

Kali Linux runs on a wide variety of ARM-based devices (laptops, embedded computers, and developer boards, for example) but you cannot use the traditional Kali installer on these devices since they often have specific requirements in terms of kernel or boot loader configuration.

To make those devices more accessible to Kali users, OffSec developed [scripts to build disk images](https://gitlab.com/kalilinux/build-scripts/kali-arm) that are ready for use with various ARM devices. They provide these images pre-generated, ready to download on their website:

> [https://www.offsec.com/kali-linux-arm-images/](https://www.offsec.com/kali-linux-arm-images/)

Since these images are available, your task of installing Kali on an ARM device is greatly simplified. Here are the basic steps:

1. Download the image for your ARM device and ensure that the checksum matches the one provided on the website (see [_Verifying Integrity and Authenticity_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/getting-started-with-kali-linux/downloading-a-kali-iso-image/where-to-download) for explanations on how to do that). Note that the images are usually xz-compressed; make sure to uncompress them with `unxz`.
    
2. Depending on the storage expansion slot available on your specific ARM device, acquire an SD card, micro SD card, or embedded multi-media controller (eMMC) module that has a capacity of at least 8 GB.
    
3. Copy the downloaded image to the storage device with `dd`. This is similar to the process of copying an ISO image onto a USB key (see [_Copying the Image on a DVD-ROM or USB Key_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/getting-started-with-kali-linux/downloading-a-kali-iso-image/where-to-download#sect.copying-the-image)).
    

```
# dd if=kali-image.img of=/dev/something bs=512k
```

4. Plug the SD-card/eMMC into your ARM device.
    
5. Boot your ARM device and log into it _(user `kali`, password `kali`)_. If you don't have a screen connected, then you will have to discover the IP address that has been assigned via DHCP and connect to that address over SSH. Some DHCP servers have tools or web interfaces to show the current leases. If you don't have this as an option, use a sniffer to look for DHCP lease traffic, or either a ICMP/ARP scan of the local network.
    
6. Change the default user password and generate new SSH host keys, especially if the device will be permanently running on a public network! These steps are relatively straightforward, see [_Generating New SSH Host Keys_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/configuring-kali-linux/configuring-services/configuring-ssh-for-remote-logins).
    
7. Enjoy your new ARM device running Kali Linux!
    

**Special Cases and More Detailed Documentation**

These instructions are generic and while they work for most devices, there are always exceptions. For example, Chromebooks require _developer mode_ and other devices require a special keypress in order to boot from external media.

Since ARM devices are added relatively frequently and their specifications are so dynamic, we won't cover specific installation instructions for various ARM devices here. Instead, refer to the dedicated "Kali on ARM" section of the Kali documentation website for information about each ARM device supported by OffSec:

> [https://www.kali.org/docs/arm/](https://www.kali.org/docs/arm/)

## 5.5. Troubleshooting Installations

The installer is quite reliable, but you may encounter bugs or face external problems such as: network problems, bad mirrors, and insufficient disk space. Because of this, it is quite useful to be able to troubleshoot problems that appear in the installation process.

When the installer fails, it will show you a rather unhelpful screen such as the one shown in Figure 26.

![Figure 26: Installation Step Failed](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/62b8c92137483f4c0791aa48f1efef8a-05_install-failure-message.png)

Figure 26: Installation Step Failed

At this point, it is good to know that the installer makes use of multiple virtual consoles: the main screen that you see is running either on the fifth console (for the graphical installer, **CTRL+ALT+F5**) or on the first console (for the classic text-mode installer, **CTRL+ALT+F1**). In both cases, the fourth console (**CTRL+ALT+F4**) displays logs of what is happening and you can usually see a more useful error message there, such as the one in Figure 27, which reveals that the installer has run out of disk space.

![Figure 27: Log Screen of the Installer](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/e7111540b292ab61298ba99bc8bf6cea-05_install-failure-log-screen.png)

Figure 27: Log Screen of the Installer

**Figure 4.27. The Log Screen of the Installer**

The second and third consoles (**CTRL+ALT+F2** and **CTRL+ALT+F3**, respectively) host shells that you can use to investigate the current situation in more detail. Most of the command line tools are provided by BusyBox so the feature set is rather limited, but it is enough to figure out most of the problems that you are likely to encounter.

**What Can be Done in the Installer Shell**

You can inspect and modify the debconf database with `debconf-get` and `debconf-set`. These commands are especially convenient for testing preseeding values.

You can inspect any file (such as the full installation log available in `/var/log/syslog`) with `cat` or `less`. You can edit any file with `nano`, including all files being installed onto the system. The root file system will be mounted on `/target` once the partitioning step of the installation process has completed.

Once network access has been configured, you can use `wget` and `nc` (netcat) to retrieve and export data over the network.

Once you click **Continue** from the main installer failure screen Figure 28), you will be returned to a screen that you will normally never see (the Main Menu shown in Figure 28), which allows you to launch one installation step after another. If you managed to fix the problem through the shell access (congratulations!) then you can retry the step that failed.

![Figure 28: Main Menu of the Installer](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/9da687b65aaeb73101781ff597fbfa0a-05_install-failure-main-menu.png)

Figure 28: Main Menu of the Installer

If you are unable to resolve the problem, you might want to file a bug report. The report must then include the installer logs, which you can retrieve with the main menu's "Save debug logs" function. It offers multiple ways to export the logs, as shown in Figure 29.

![Figure 29: Save Debug Logs (1/2)](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/f0db66ef1d353b245b2b23b621ebdfc5-05_install-failure-save-debug-logs.png)

Figure 29: Save Debug Logs (1/2)

The most convenient method, and the one that we recommend, is to let the installer start a web server hosting the log files Figure 30). You can then launch a browser from another computer on the same network and download all the log files and screenshots that you have taken with the **Screenshot** button available on each screen.

![Figure 30: Save Debug Logs (2/2)](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/b23d930a0de49f5eaa4bd8fe3038fe08-05_install-failure-webserver-running.png)

Figure 30: Save Debug Logs (2/2)

## 5.6. Summary

In this chapter, we focused on the Kali Linux installation process. We discussed Kali Linux's minimum installation requirements, the installation process for standard and fully encrypted file systems, preseeding, which allows unattended installations, how to install Kali Linux on various ARM devices, and what to do in the rare case of an installation failure. Summary Tips:

- The installation requirements for Kali Linux vary from a basic SSH server with no desktop, as little as 128 MB RAM (512 MB recommended) and 2 GB disk space, to the higher-end _kali-linux-default_ metapackage, with at least 2048 MB of RAM and 20 GB of disk space. In addition, your machine must have a CPU supported by at least one of the amd64, i386, or arm64 architectures.
- Kali can easily be installed as the primary operating system, alongside other operating systems through partitioning and boot loader modification, or as a virtual machine.
- To guarantee the confidentiality of your data, you can set up encrypted partitions. This will protect your data if your laptop or hard drive is lost or stolen.
- The installer can also be automated through debconf preseeding, a function that allows you to provide unattended answers to installation questions.
- A preseed file is a plain text file in which each line contains the answer to one Debconf question. A line is split across four fields separated by white space (spaces or tabs). You can preseed answers to the installer with boot parameters, with a preseed file in initrd, with a preseed file on the boot media, or with a preseed file from the network.
- Kali Linux runs on a wide variety of ARM-based devices such as laptops, embedded computers, and developer boards. ARM installation is fairly straightforward. Download the proper image, copy it to an SD card, USB drive, or embedded multi-media controller (eMMC) module, plug it in, boot the ARM device, find your device on the network, log in, and change the SSH password and SSH host keys.
- You can debug failed installations with virtual consoles (accessible with the **CTRL**+**ALT** and function keys), `debconf-get` and `debconf-set` commands, reading the `/var/log/syslog` log file, or by submitting a bug report with log files retrieved with the installer's "Save debug logs" function.

Now that we have discussed Linux fundamentals and Kali Linux installation, let's discuss configuration so you can begin to tailor Kali to suit your needs.

### 5.7.1. Kali Linux full disk Encryption install

#### Exercise:

1. What are the minimum required resources for a VM?
2. Install a standard, default, **full disk encryption** installation of Kali Linux to a new VM. Make sure the final VM is in NAT mode.
3. What technologies are used for encryption?

---

#### Exercise solution:

1. **2GB RAM, 20 GB disk space**
2. Check out [this for installation procedures](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/installing-kali-linux/step-by-step-installation-on-a-hard-drive/step-by-step-installation-on-a-hard-drive) . To be clear, the goal here is that you install Kali with encrypted filesystem to a new VM by booting from the ISO and manually walking through the install. The goal is not to launch the Kali supplied `.vmx`/`.ova` files.
3. LUKS and Logical Volume Management (LVM)

### 5.7.2. Kali Linux unattended install

#### Exercise:

1. Create a new VM, with at least the recommended required hardware requirements.
2. Complete a standard, default, installation, using a preseed file - hosted over HTTP (or HTTPS). Your pressed file is [here](https://offsec-platform-prod.s3-us-east-2.amazonaws.com/offsec-courses/KLR/Binaries/preseed.cfg).

_Note: Make sure the installation is **fully** unattended: you must preseed **locale**, **keymap**, **hostname**, and **domain** as well._

---

#### Exercise solution:

1. Minimum requirements: **2GB RAM, 20 GB disk space**.
2. This is pretty much a standard install with modified boot parameters. Here are suggested boot parameters:

```
preseed/url=https://offsec-platform-prod.s3-us-east-2.amazonaws.com/offsec-courses/KLR/Binaries/preseed.cfg locale=en_US keymap=us hostname=kali domain=local.lan
```

Note that the **locale**, **keymap**, **hostname**, and **domain** parameters are set on the kernel command line!

![Figure 31: Boot options](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/6bd1fbfa4f36a2db96ce59f0340e0ec0-boot_options-1.png)

Figure 31: Boot options

**Question to consider**: "Why can't the preseed file handle the **locale**, **keymap**, **hostname**, and **domain** parameters?"

Good question. Preseeding parameters depends on the preseed method. If you use a preseed file in the initrd, then you can preseed all parameters even those that are very early in the process. If you use a preseed file from the network or from the ISO image itself, then the preseed gets applied a bit later in the installation process and the early parameters need to be preseeded on the kernel command line.

Alternatively, you could also use the **auto=true** and **priority=critical** preseed parameters.

```
preseed/url=https://offsec-platform-prod.s3-us-east-2.amazonaws.com/offsec-courses/KLR/Binaries/preseed.cfg auto=true priority=critical
```

### 5.7.3. Kali Linux standard ARM install

#### Exercise:

1. If you have a Raspberry Pi or similar device, grab a copy of the appropriate ARM image from [here](https://www.kali.org/get-kali/#kali-arm). Burn it to an SD card and try it out.

---

#### Exercise solution:

There's a chicken-and-egg problem here. To keep things standardized, we would rather have you perform all of these steps in Kali. That way, you have all the tools you need, and we can walk you through it without explaining the process on multiple OS's (Windows, macOS/OS X, and Linux). But in order to do this from Kali, we need to get the image over to Kali and the most reliable and straightforward way to do this is with **scp** which relies on the **ssh** service. But we don't touch on SSH until the next chapter.

So although it's not ideal, we'll shoehorn in the SSH procedure here so we can move along and we will discuss the details more in the next chapter. From your Kali installation:

1. Start sshd:

```
kali@kali:~$ sudo systemctl start ssh
kali@kali:~$
```

2. Enable sshd at boot:

```
kali@kali:~$ sudo systemctl enable ssh
kali@kali:~$
```

3. Now, you should be able to ssh into your machine even on reboot:

```
Host Machine:~ j$ ssh kali@192.168.1.12
kali@192.168.1.12's password:

The programs included with the Kali GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Jun  4 17:16:41 2020
kali@kali:~$
```

4. Now we can move the xz file into our Kali VM. Try to avoid VM drag-and-drop, it can be problematic:

```
kali@kali:~$ scp kali-linux-2020.3-rpi3-nexmon.img.xz kali@192.168.60.185:/home/kali
kali@kali:~$
```

5. Next, insert your (minimum 16 GB) SD card and find the proper disk ID:

```
kali@kali:~$ sudo dmesg
[194628.402969] sd 3:0:0:0: Attached scsi generic sg2 type 0
[194628.410035] sd 3:0:0:0: [sdb] 15564800 512-byte logical blocks: (7.97 GB/7.42 GiB)
[194628.410821] sd 3:0:0:0: [sdb] Write Protect is off
[194628.410823] sd 3:0:0:0: [sdb] Mode Sense: 03 00 00 00
[194628.411936] sd 3:0:0:0: [sdb] No Caching mode page found
[194628.411940] sd 3:0:0:0: [sdb] Assuming drive cache: write through
[194628.420751]  sdb: sdb1
kali@kali:~$
```

6. Uncompress the xz file:

```
kali@kali:~$ cd /home/kali/
kali@kali:~$
kali@kali:~$ unxz kali-linux-2020.3-rpi3-nexmon.img.xz
```

(Alternatively, check out `xzcat`).

7. Run the dd with the correct disk identifier (_/dev/sdb_ in our case). Warning! Do not simply copy these values, change them to the correct drive path corresponding to your SD card.

```
kali@kali:~$ sudo dd if=/home/kali/kali-linux-2020.3-rpi3-nexmon.img.xz of=/dev/sdb bs=1M
7000+0 records in
7000+0 records out
7340032000 bytes (7.3 GB, 6.8 GiB) copied, 1356.87 s, 5.4 MB/s
kali@kali:~$
```

8. Plug in your SD and boot up your new Kali Pi. You'll need to hook up HDMI to see what's going on, and a USB keyboard and mouse to type and click. And you'll have to plug in an Ethernet cable to get network (it's DHCP).

### 5.7.4. Custom Kali Linux ARM install

#### Exercise:

In the previous exercise, we performed a standard ARM install. Although we don't cover this in the book, we think it's valuable that you see how to build a custom image. You can walk through this exercise with any supported ARM device, but we will use a Raspberry Pi 3. Check out the list of [supported ARM hardware](https://www.kali.org/get-kali/#kali-arm). We will build a custom Kali ARM image containing:

1. A minimum set of packages.
2. No desktop environment (headless).
    - A static IP address on eth0 so we don't have to hunt for our Pi
    - Tools like `ifconfig` installed.
3. SSH service starts at boot, with your public SSH key pre-installed.

Go ahead, read on. This is a walkthrough, after all.

---

#### Exercise solution:

Download and install the build scripts, build dependencies, and cross compiler.

First, create a directory to store all of our work:

```
kali@kali:~$ mkdir ~/kali/arm-stuff
kali@kali:~$
kali@kali:~$ cd ~/kali/arm-stuff
kali@kali:~$
```

Next, we need a cross-compiler for armhf. This package contains pre-built versions of Linaro GCC and Linaro GDB, a `gdbserver` (a program that allows you to run GDB on a different machine than the one which is running the program being debugged), a system root (with all the headers and libraries to link programs against) and manuals under share/doc:

```
kali@kali:~$ git clone https://gitlab.com/kalilinux/packages/gcc-arm-linux-gnueabihf-4-7
kali@kali:~$
```

Kali will need the files under bin/ for the build:

```
kali@kali:~$ export PATH=${PATH}:~/kali/arm-stuff/gcc-arm-linux-gnueabihf-4.7/bin
kali@kali:~$
```

Next, the real magic. We will grab the Kali Linux ARM build scripts. We use these to build our official Kali Linux ARM images at https://www.kali.org/get-kali/#kali-arm.

```
kali@kali:~$ git clone https://gitlab.com/kalilinux/build-scripts/kali-arm
kali@kali:~$
kali@kali:~$ cd ~/kali/arm-stuff/kali-arm/
kali@kali:~$
```

Next, install the required dependencies. This will take a few minutes:

```
kali@kali:~$ sudo ./build-deps.sh
kali@kali:~$
```

Next, edit the ARM build script, and change your required fields. We are editing the Raspberry Pi 3 Kali ARM script. It's got nexmon built in: a C-based Firmware Patching Framework for Broadcom/Cypress WiFi Chips that enables Monitor Mode, Frame Injection and much more.

In our case we can remove **desktop**, most of **tools**, and **extras**. Additionally, we want to set up the Raspberry Pi IP address to be a static IP so we can SSH to it later on. Of course, SSH should start at boot time, and have our public key.

```
kali@kali:~$ nano rpi3-nexmon.sh
kali@kali:~$
```

First, we will comment out the **desktop** and **extras** sections, and make changes to the **tools** and **services** sections:

```
#desktop="kali-desktop-xfce kali-root-login xserver-xorg-video-fbdev xfonts-terminus xinput"
#tools="kali-linux-default"
tools="aircrack-ng nmap hostapd"
#services="apache2 atftpd"
services="openssh-server gnupg"
#extras="alsa-utils bc bison crda bluez bluez-firmware i2c-tools kali-linux-core libnss-systemd libssl-dev python3-configobj python3-pip python3-requests python3-rpi.gpio python3-smbus triggerhappy"
```

Further down we will pull eth0 off of dhcp and set a static address:

```
auto eth0
        iface eth0 inet static
        address 192.168.1.12
        netmask 255.255.255.0
        gateway 192.168.1.1
EOF
```

The changes we've made can be shown in another way with the diff tool, which compares files. Here we see a before-and-after. White lines show lines that match between the files (but have been moved in this case because we've inserted some lines). Red lines show deletions, and green lines show additions. Note that in this diff, we have deleted configuration lines instead of commenting them:

![Figure 32: rip changes](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/KLR/images/3d560db68173de27c40d054265363d23-rpi_changes-1.png)

Figure 32: rip changes

Once the changes are made, we can run the build script with a nifty identifier (a simple "1.0" in this example). Note that this can take over an hour, based on your CPU, memory and bandwidth:

```
kali@kali:~$ ./rpi3-nexmon.sh 1.0
kali@kali:~$
```

Once this is finished, you should have three files:

```
kali@kali:~/arm-stuff/kali-arm-build-scripts$ ls -l rpi3-nexmon-bh-1.0/
total 553496
-rw-r--r-- 1 kali kali        91 Jun  14 12:14 kali-1.0-rpi3-nexmon.img.sha256sum
-rw-r--r-- 1 kali kali 566765348 Jun  14 12:23 kali-1.0-rpi3-nexmon.img.xz
-rw-r--r-- 1 kali kali        94 Jun  14 12:23 kali-1.0-rpi3-nexmon.img.xz.sha256sum
```

Now, you can burn the ISO to an SD to test the image. As always, be sure to select the correct device ID. In our case, it happens to be /dev/sdb. This can take 20 minutes or more, when run from a properly configured VM:

```
kali@kali:~$ cd ~/kali/arm-stuff/kali-arm/rpi3-nexmon-bh-1.0/
kali@kali:~$
kali@kali:~/kali/arm-stuff/kali-arm/rpi3-nexmon-bh-1.0$ ls
kali-1.0-rpi3-nexmon.img.sha256sum  kali-1.0-rpi3-nexmon.img.xz  kali-1.0-rpi3-nexmon.img.xz.sha256sum
kali@kali:~$
kali@kali:~/kali/arm-stuff/kali-arm/rpi3-nexmon-bh-1.0$ xzcat kali-1.0-rpi3-nexmon.img.xz | dd of=/dev/sdb bs=1M
kali@kali:~$
```

Next, boot up the Kali Pi. You should find it at 192.168.1.12, and ssh should be open.

### 5.7.5. Kali Linux ARM chroot

#### Exercise:

Perhaps the build you made wasn't ideal. Fortunately you can change the build. For this example, let's assume that you forgot to install some packages, such as **net-tools**, **dnsmasq**, and **mlocate**. Rather than reinstalling and re-imaging the device, chroot into the RPi 3 SD card from your Kali machine and make the required changes.

Since this is a walkthrough, and not covered in the book, go ahead and keep reading. This is a walkthrough, after all.

---

#### Exercise solution:

You'll begin with the SD card from a previous exercise. In this example, we are using the image from the previous exercise (Exercise 4) -- our custom build. First, install **qemu** cross compiling tools and related tools into Kali:

```
kali@kali:~$ sudo apt-get install qemu qemu-user qemu-user-static
kali@kali:~$
```

Let's make a /mnt/sd directory to keep our directories we're working on organized:

```
kali@kali:~$ sudo mkdir /mnt/sd
kali@kali:~$
```

Pick up your /dev/sd drive assignment by inserting the Pi's SD card (ours is /dev/sdc). Your USB-SD adapter makes a difference. We are going to pick up all the physical drive mounts in one shot.

```
kali@kali:~$ sudo mount /dev/sdc2 /mnt/sd/
kali@kali:~$
kali@kali:~$ ls -l /mnt/sd
total 76
lrwxrwxrwx  1 root root     7 Oct  5  2020 bin -> usr/bin
drwxr-xr-x  2 root root  4096 Oct  5  2020 boot
drwxr-xr-x  4 root root  4096 Oct  5  2020 dev
drwxr-xr-x 98 root root  4096 Nov  1  2020 etc
drwxr-xr-x  3 root root  4096 Oct  5  2020 home
lrwxrwxrwx  1 root root     7 Oct  5  2020 lib -> usr/lib
drwx------  2 root root 16384 Oct  5  2020 lost+found
drwxr-xr-x  3 root root  4096 Sep 21  2020 media
drwxr-xr-x  2 root root  4096 Oct  5  2020 mnt
drwxr-xr-x  2 root root  4096 Oct  5  2020 opt
drwxr-xr-x  2 root root  4096 Jul  9  2019 proc
drwx------  3 root root  4096 Oct  5  2020 root
drwxr-xr-x  4 root root  4096 Oct  5  2020 run
lrwxrwxrwx  1 root root     8 Oct  5  2020 sbin -> usr/sbin
drwxr-xr-x  2 root root  4096 Oct  5  2020 srv
drwxr-xr-x  2 root root  4096 Jul  9  2019 sys
drwxrwxrwt 10 root root  4096 Nov  1  2020 tmp
drwxr-xr-x 11 root root  4096 Oct  5  2020 usr
drwxr-xr-x 11 root root  4096 Oct  5  2020 var
kali@kali:~$
```

Did you notice how all the Raspberry Pi's SD card directories are now mapped on your system under /mnt/sd?

Mount up all 'special filesystems' under /mnt/sd. Notice that we will be overriding mount options from /etc/fstab on some that are already mapped with the -o option:

```
kali@kali:~$ sudo mount -t proc none /mnt/sd/proc
kali@kali:~$
kali@kali:~$ sudo mount -t sysfs none /mnt/sd/sys
kali@kali:~$
kali@kali:~$ sudo mount -o bind /dev /mnt/sd/dev
kali@kali:~$
kali@kali:~$ sudo mount -o bind /dev/pts /mnt/sd/dev/pts
kali@kali:~$
```

Let's pull the qemu cross-compiling tools over. We need these to compile the ARM stuff since our target is ARM!

```
kali@kali:~$ sudo cp /usr/bin/qemu-arm-static /mnt/sd/usr/bin
kali@kali:~$
```

Time to enter a chroot! Once inside the chroot, all commands we execute will assume that /mnt/sd is our root filesystem. It's a pretty cool trick. Note that we set LAN=C to suppress locale warnings in your chroot:

```
kali@kali:~$ sudo LANG=C chroot /mnt/sd/
kali@kali:~$
```

Let's make some changes to the Pi's filesystem. This is the cool part. All this is happening on your Pi's filesystem!

```
kali@kali:~$ sudo apt-get update
kali@kali:~$
kali@kali:~$ sudo apt-get install mlocate
kali@kali:~$
kali@kali:~$ sudo apt-get install net-tools
kali@kali:~$
kali@kali:~$ sudo apt-get install hostapd dnsmasq
kali@kali:~$
```

Continue configuration as necessary. Once done, exit the chroot and unmount the SDcard.

```
kali@kali:~$ exit
```

We need to unmount all the directories we mounted:

```
kali@kali:~$ sudo umount /mnt/sd/dev/pts
kali@kali:~$
kali@kali:~$ sudo umount /mnt/sd/dev/
kali@kali:~$
kali@kali:~$ sudo umount /mnt/sd/sys
kali@kali:~$
kali@kali:~$ sudo umount /mnt/sd/proc
kali@kali:~$
kali@kali:~$ sudo umount /mnt/sd
kali@kali:~$
```

Lastly, insert the SD card into the Pi, and launch!

- Next Module -> [Helping yourself and getting help 🌀](helping_yourself.md)