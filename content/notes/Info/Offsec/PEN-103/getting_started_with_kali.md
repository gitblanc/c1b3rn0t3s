---
title: Getting started with Kali Linux ⚡
tags:
  - Offsec
  - PEN-103
---
- *All the info was extracted from [Offsec, Pen-103](https://portal.offsec.com/courses/pen-103-16306/)*, under the following [licencese](https://creativecommons.org/licenses/by-sa/3.0/)

# 4. Getting Started with Kali Linux

Unlike some other operating systems, Kali Linux makes getting started easy, thanks to the fact that a _live disk image_ is available, meaning that you can boot the downloaded image without following any prior installation procedure. This means you can use the same image for testing, for use as a bootable USB or DVD-ROM image in a forensics case, or for installing as a permanent operating system on physical or virtual hardware.

Because of this simplicity, it is easy to forget that certain precautions must be taken. Kali users are often the target of those with ill intentions, whether state sponsored groups, elements of organized crime, or individual hackers. The open-source nature of Kali Linux makes it relatively easy to build and distribute fake versions, so it is essential that you get into the habit of downloading from original sources and verifying the integrity and the authenticity of your download. This is especially relevant to security professionals who often have access to sensitive networks and are entrusted with client data.

### 4.1.1. Where to Download

The only official source of Kali Linux ISO images is the Downloads section of the Kali website. Due to its popularity, numerous sites offer Kali images for download, but they should not be considered trustworthy and indeed may be infected with malware or otherwise cause irreparable damage to your system.

> [https://www.kali.org/downloads/](https://www.kali.org/downloads/)

The website is available over _HTTPS_, making it difficult to impersonate. Being able to carry out a man-in-the-middle attack is not sufficient as the attacker would also need a `www.kali.org` certificate signed by a Transport Layer Security (TLS) certificate authority that is trusted by the victim's browser. Because certificate authorities exist precisely to prevent this type of problem, they deliver certificates only to people whose identities have been verified and who have provided evidence that they control the corresponding website.

The links found on the download page point to the `cdimage.kali.org` domain, which redirects to a mirror close to you, improving your transfer speed while reducing the burden on Kali's central servers.

A list of available mirrors can be found here:

> [https://cdimage.kali.org/README?mirrorlist](https://cdimage.kali.org/README?mirrorlist)

### 4.1.2. What to Download

The official download page shows a short list of ISO images, as shown in Figure 1.

![Figure 1: List of Images Offered for Download](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/43f8b5a4799a3ace6606ba999e7a3f43-03_download-iso.png)

Figure 1: List of Images Offered for Download

All disk images labeled 64-bit or 32-bit refer to images suitable for CPUs, found in most modern desktop and laptop computers. If you are downloading for use on a fairly modern machine, it most likely contains a 64-bit processor. If you are unsure, rest assured that all 64-bit processors can run 32-bit instructions. You can always download and run the 32-bit image. The reverse is not true, however. Refer to the sidebar for more detailed information.

If you are planning to install Kali on an ARM-based device, you must refer to [_OffSec's_ download page](https://www.offsec.com/kali-linux-arm-images/) for the list of available devices.

**Is My CPU 32-bit or 64-bit?**

Under Microsoft Windows, you can find this information by running the _System Information_ application (found in the Accessories > System Tools folder). On the System Summary screen, you can inspect the System Type field: it will contain "x64-based PC" for a 64-bit CPU or "x86-based PC" for a 32-bit CPU.

Under OS X/macOS, there is no standard application showing this information but you can still infer it from the output of the `uname -m` command run on the terminal. It will return `x86_64` on a system with a 64-bit kernel (which can only run on a 64-bit CPU), systems with a 32-bit kernel, it will return `i386` or something similar (`i486`, `i586`, or `i686`), and on systems with an arm64 kernel, it will return `arm64`. Any 32-bit kernel can run on a 64-bit CPU, but since Apple controls the hardware and the software, it is unlikely you will find this configuration.

Under Linux, you can inspect the flags field in the `/proc/cpuinfo` virtual file. If it contains the `lm` attribute, then your CPU is a 64-bit; otherwise, it is a 32-bit. The following command line will tell you what kind of CPU you have:

```shell
$ grep -qP '^flags\s*:.*\blm\b' /proc/cpuinfo && echo 64-bit || echo 32-bit
64-bit
```

Now that you know whether you need a 64-bit or 32-bit image, there is only one step left: selecting the kind of image. The available images differ in how they go about installation. The **Installer** and **NetInstaller** images, specialized for a straightforward install featuring selectable installation options, do not come with the ability to run the live system. The **Live** image, however, comes with the ability to run the live system or start the installation process, although it does lack the selectable options featured in the installation images. The selectable options include choices in desktop environments as well as which collection of packages to install. We will be using the live image throughout this course.

Once you have decided on the image you need, you can download the image by clicking on the title in the respective row. Alternatively, you can download the image from the BitTorrent peer-to-peer network by clicking on "Torrent," provided that you have a BitTorrent client associated with the `.torrent` extension.

While your chosen ISO image is downloading, you should take note of the checksum written in the sha256sum column. Once you have downloaded your image, use this checksum to verify that the downloaded image matches the one the Kali development team put online (see [_Verifying Integrity and Authenticity_](https://portal.offsec.com/courses/pen-103-16306/learning/getting-started-with-kali-linux-16826/exercises-16854/editing-boot-parameters-17013#verifying-integrity-authenticity)).

### 4.1.3. Verifying Integrity and Authenticity

Security professionals must verify the integrity of their tools to not only protect their data and networks but also those of their clients. While the Kali download page and links are TLS-protected, Kali relies on a network of external mirrors to distribute the image means that you should not blindly trust what you download. The mirror you were directed to may have been compromised, or you might be the victim of an attack yourself.

To alleviate this, the Kali project always provides checksums of the images it distributes. But to make such a check effective, you must be sure that the checksum you grabbed is effectively the checksum published by the Kali Linux developers. You have different ways to ascertain this.

#### Relying on the TLS-Protected Website

When you retrieve the checksum from the TLS-protected download webpage, its origin is indirectly guaranteed by the X.509 certificate security model: the content you see comes from a web site that is effectively under the control of the person who requested the TLS certificate.

Now you should generate the checksum of your downloaded image and ensure that it matches what you recorded from the Kali website:

```
$ sha256sum kali-linux-2020.3-live-amd64.iso
1a0b2ea83f48861dd3f3babd5a2892a14b30a7234c8c9b5013a6507d1401874f  kali-linux-2020.3-live-amd64.iso
```

If your generated checksum matches the one on the Kali Linux download page, you have the correct file. If the checksums differ, there is a problem, although this does not always indicate a compromise or an attack; downloads occasionally get corrupted as they traverse the Internet. Try your download again, from another official Kali mirror, if possible (see [_cdimage.kali.org_](https://portal.offsec.com/courses/pen-103-16306/learning/getting-started-with-kali-linux-16826/exercises-16854/editing-boot-parameters-17013#cdimage.kali.org) for more information about available mirrors).

#### Relying on PGP's Web of Trust

If you don't trust HTTPS for authentication, you are a bit paranoid but rightfully so. There are many examples of badly managed certificate authorities that issued rogue certificates, which ended up being misused. You may also be the victim of a "friendly" man-in-the-middle attack implemented on many corporate networks, using a custom, browser-implanted trust store that presents fake certificates to encrypted websites, allowing corporate auditors to monitor encrypted traffic.

For cases like this, we also provide a GnuPG key that we use to sign the checksums of the images we provide. The key's identifiers and its fingerprints are shown here:

```
pub   rsa4096 2012-03-05 [SC] [expires: 2023-01-16]
      44C6 513A 8E4F B3D3 0875  F758 ED44 4FF0 7D8D 0BF6
uid                      Kali Linux Repository <devel@kali.org>
sub   rsa4096 2012-03-05 [E] [expires: 2023-01-16]
```

This key is part of a global _web of trust_ because it has been signed at least by me (Raphaël Hertzog) and I am part of the web of trust due to my heavy GnuPG usage as a Debian developer.

The PGP/GPG security model is very unique. Anyone can generate any key with any identity, but you would only trust that key if it has been signed by another key that you already trust. When you sign a key, you certify that you met the holder of the key and that you know that the associated identity is correct. And you define the initial set of keys that you trust, which obviously includes your own key.

This model has its own limitations so you can opt to download Kali's public key over HTTPS (or from a keyserver) and just decide that you trust it because its fingerprint matches what we announced in multiple places, including just above in this course:

```
$ wget -q -O - https://archive.kali.org/archive-key.asc | gpg --import
[ or ]
$ gpg --keyserver hkps://keys.openpgp.org --recv-key 44C6513A8E4FB3D30875F758ED444FF07D8D0BF6
gpg: key ED444FF07D8D0BF6: public key "Kali Linux Repository <devel@kali.org>" imported
gpg: Total number processed: 1
gpg:               imported: 1
[...]
$ gpg --fingerprint 44C6513A8E4FB3D30875F758ED444FF07D8D0BF6
[...]
      44C6 513A 8E4F B3D3 0875  F758 ED44 4FF0 7D8D 0BF6
[...]
```

After you have retrieved the key, you can use it to verify the checksums of the distributed images. Let's download the file with the checksums (`SHA256SUMS`) and the associated signature file (`SHA256SUMS.gpg`) and verify the signature:

```
$ wget https://cdimage.kali.org/current/SHA256SUMS
[...]
$ wget https://cdimage.kali.org/current/SHA256SUMS.gpg
[...]
$ gpg --verify SHA256SUMS.gpg SHA256SUMS
gpg: Signature made Tue 18 Aug 2020 10:31:15 AM EDT
gpg:                using RSA key 44C6513A8E4FB3D30875F758ED444FF07D8D0BF6
gpg: Good signature from "Kali Linux Repository <devel@kali.org>"
```

If you get that "Good signature" message, you can trust the content of the `SHA256SUMS` file and use it to verify the files you downloaded. Otherwise, there is a problem. You should review whether you downloaded the files from a legitimate Kali Linux mirror.

Note that you can use the following command line to verify that the downloaded file has the same checksum that is listed in `SHA256SUMS`, provided that the downloaded ISO file is in the same directory:

```
$ grep kali-linux-2020.3-live-amd64.iso SHA256SUMS | sha256sum -c
kali-linux-2020.3-live-amd64.iso: OK
```

If you don't get `OK` in response, then the file you have downloaded is different from the one released by the Kali team. It cannot be trusted and should not be used.

### 4.1.4. Copying the Image on a DVD-ROM or USB Key

Unless you want to run Kali Linux in a virtual machine, the ISO image is of limited use in and of itself. You must burn it on a DVD-ROM or copy it onto a USB key to be able to boot your machine into Kali Linux. We have chosen the Kali live image as we wish to boot from a USB allowing us to either use a live environment or install Kali Linux's default configuration.

We won't cover how to burn the ISO image onto a DVD-ROM, as the process varies widely by platform and environment, but in most cases, right clicking on the `.iso` file will present a contextual menu item that executes a DVD-ROM burning application. Try it out!

**Warning**

In this section, you will learn how to overwrite an arbitrary disk with a Kali Linux ISO image. Always double-check the target disk before launching the operation as a single mistake would likely cause complete data loss and possibly damage your setup beyond repair.

#### Creating a Bootable Kali USB Drive on Windows

As a prerequisite, you should download and install _Win32 Disk Imager_: [https://sourceforge.net/projects/win32diskimager/](https://sourceforge.net/projects/win32diskimager/)

Plug your USB key into your Microsoft Windows PC and note the drive designator associated to it (for example, "E:\").

Launch _Win32 Disk Imager_ and choose the Kali Linux ISO file that you want to copy on the USB key. Verify that the letter of the device selected corresponds with that assigned to the USB key. Once you are certain that you have selected the correct drive, click the Write button and confirm that you want to overwrite the contents of the USB key as shown in Figure 4.

![Figure 2: Win32 disk imager](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/dfb3bc701d0045afe0d879aa9623ade2-03_win32-disk-imager.png)

Figure 2: Win32 disk imager

![Figure 3: Win32 disk imager double checking](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/005afea4a6ead08ee78203e66bd86173-03_win32-disk-imager-confirm.png)

Figure 3: Win32 disk imager double checking

![Figure 4: Win32 disk imager in action](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/940b18a4ce09ff5ee287ddb98e2145b4-03_win32-disk-imager-progress.png)

Figure 4: Win32 disk imager in action

Once the copy is completed, safely eject the USB drive from your Microsoft Windows system. You can now use the USB device to boot Kali Linux.

#### Creating a Bootable Kali USB Drive on Linux

Creating a bootable Kali Linux USB key in a Linux environment is easy. The GNOME desktop environment, which is installed by default in many Linux distributions, comes with a _Disks_ utility (in the _gnome-disk-utility_ package). That program shows a list of disks, which refreshes dynamically when you plug or unplug a disk. When you select your USB key in the list of disks, detailed information will appear and will help you confirm that you selected the correct disk. Note that you can find its device name in the title bar as shown in Figure 5.

![Figure 5: GNOME Disks utility](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/183f62da307709e4f34b7e8bee0aa6d5-03_gnome-disks.png)

Figure 5: GNOME Disks utility

Click on the menu button and select **Restore Disk Image...** in the displayed pop-up menu. Select the ISO image that you formerly downloaded and click on **Start Restoring...** as shown in Figure 6.

![Figure 6: Restoring a image](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/f8d44de213947592af7a550652fdb2b9-03_gnome-disks-restore-image.png)

Figure 6: Restoring a image

Enjoy a cup of coffee while it finishes copying the image on the USB key Figure 7).

![Figure 7: GNOME Disks in action](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/0221810e3f25e3735bda18705e5f8a06-03_gnome-disks-progressbar.png)

Figure 7: GNOME Disks in action

**Create the Bootable USB Drive from the Command Line**

Even though the graphical process is fairly straightforward, the operation is just as easy for command line users.

When you insert your USB key, the Linux kernel will detect it and assign it a name, which is printed in the kernel logs. You can find its name by inspecting the logs returned by `dmesg`.

```
$ sudo su
[...]
# dmesg
[...]
[ 2596.727036] usb 1-2.1: new high-speed USB device number 7 using uhci_hcd
[ 2597.023023] usb 1-2.1: New USB device found, idVendor=0781, idProduct=5575, bcdDevice= 1.26
[ 2597.023025] usb 1-2.1: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[ 2597.023026] usb 1-2.1: Product: Cruzer Glide
[ 2597.023026] usb 1-2.1: Manufacturer: SanDisk
[ 2597.023026] usb 1-2.1: SerialNumber: 200533495211C0824E58
[ 2597.025989] usb-storage 1-2.1:1.0: USB Mass Storage device detected
[ 2597.026064] scsi host3: usb-storage 1-2.1:1.0
[ 2598.055632] scsi 3:0:0:0: Direct-Access     SanDisk  Cruzer Glide     1.26 PQ: 0 ANSI: 5
[ 2598.058596] sd 3:0:0:0: Attached scsi generic sg2 type 0
[ 2598.063036] sd 3:0:0:0: [sdb] 31266816 512-byte logical blocks: (16.0 GB/14.9 GiB)
[ 2598.067356] sd 3:0:0:0: [sdb] Write Protect is off
[ 2598.067361] sd 3:0:0:0: [sdb] Mode Sense: 43 00 00 00
[ 2598.074276] sd 3:0:0:0: [sdb] Write cache: disabled, read cache: enabled, doesn't support DPO or FUA
[ 2598.095976]  sdb: sdb1
[ 2598.108225] sd 3:0:0:0: [sdb] Attached SCSI removable disk
```

Now that you know that the USB key is available as `/dev/sdb`, you can proceed to copy the image with the `dd` command:

```
# dd if=kali-linux-2020.3-live-amd64.iso of=/dev/sdb
6129688+0 records in
6129688+0 records out
3138400256 bytes (3.1 GB, 2.9 GiB) copied, 678.758 s, 4.6 MB/s
```

Note that you need root permissions for this operation to succeed and you should also ensure that the USB key is unused. That is, you should make sure that none of its partitions are mounted. The command also assumes that it is run while in the directory hosting the ISO image, otherwise the full path will need to be provided.

For reference, `if` stands for "input file" and `of` for "output file." The `dd` command reads data from the input file and writes it back to the output file. It does not show any progress information so you must be patient while it is doing its work (It is not unusual for the command to take more than half an hour!). Look at the write activity LED on the USB key if you want to double check that the command is working. The statistics shown above are displayed only when the command has completed. On OS X/macOS, you can also press **CTRL+T** during the operation to get statistical information about the copy including how much data has been copied.

#### Creating a Bootable Kali USB Drive on OS X/macOS

OS X/macOS is based on UNIX, so the process of creating a bootable Kali Linux USB drive is similar to the Linux procedure. Once you have downloaded and verified your chosen Kali ISO file, use `dd` to copy it over to your USB stick.

To identify the device name of the USB key, run `diskutil list` to list the disks available on your system. Next, insert your USB key and run the `diskutil list` command again. The second output should list an additional disk. You can determine the device name of the USB key by comparing the output from both commands. Look for a new line identifying your USB disk and note the `/dev/diskX` where X represents the disk ID.

You should make sure that the USB key is not mounted, which can be accomplished with an explicit unmount command (assuming `/dev/disk6` is the device name of the USB key):

```
$ diskutil unmountDisk /dev/disk6
```

Now proceed to execute the `dd` command. This time, add a supplementary parameter, `bs` for block size. It defines the size of the block that is read from the input file and then written to the output file. We will also utilize the raw disk path (signified by the _r_ before _disk_) which will allow faster write speeds.

```
# dd if=kali-linux-2020.3-live-amd64.iso of=/dev/rdisk2 bs=4m
748+1 records in
748+1 records out
3138400256 bytes transferred in 713.156461 secs (4400718 bytes/sec)
```

That's it. Your USB key is now ready and you can boot from it or use it to install Kali Linux.

**Booting an Alternate Disk on OS X/macOS**

To boot from an alternate drive on an OS X/macOS system, bring up the boot menu by pressing and holding the **Option** key immediately after powering on the device and selecting the drive you want to use.

For more information, see [Apple's knowledge base](https://support.apple.com/en-gb/guide/mac-help/mchlp1034/mac).

### 4.2.1. On a Real Computer

As a prerequisite, you need either a USB key prepared (as detailed in the previous section) or a DVD-ROM burned with a Kali Linux ISO image.

The BIOS/UEFI is responsible for the early boot process and can be configured through a piece of software called Setup. In particular, it allows users to choose which boot device is preferred. In this case, you want to select either the DVD-ROM drive or USB drive, depending on which device you have created. Depending on your BIOS/UEFI, you may have a one time boot menu option, allowing to temporarily change the boot order.

Starting Setup usually involves pressing a particular key very soon after the computer is powered on. This key is often **Delete** or **Escape**, and sometimes **F2, F8, F10 or F12**. Most of the time, the choice is briefly flashed on-screen when the computer powers on, before the operating system loads.

Once the BIOS/UEFI has been properly configured to boot from your device, booting Kali Linux is simply a matter of inserting the DVD-ROM or plugging in the USB drive and powering on the computer.

**Disable Secure Boot**

While the Kali Linux images can be booted in UEFI mode, they do not support _secure boot_. You should disable that feature in your machine's Setup.

### 4.2.2. In a Virtual Machine

Virtual machines have multiple benefits for Kali Linux users. They are especially useful if you want to try out Kali Linux but aren't ready to commit to installing it permanently on your machine or if you have a powerful system and want to run multiple operating systems simultaneously. This is a popular choice for many penetration testers and security professionals who need to use the wide range of tools available in Kali Linux but still want to have full access to their primary operating system. This also provides them with the ability to archive or securely delete the virtual machine and any client data it may contain rather than reinstalling their entire operating system.

The snapshot features of virtualization software also make it easy to experiment with potentially dangerous operations, such as malware analysis, while allowing for an easy way out by restoring a previous snapshot.

There are many virtualization tools available for all major operating systems, including _VirtualBox®_, _VMware Workstation®_, _Xen_, _KVM_, and _Hyper-V_ to name a few. Ultimately, you will use the one that best suits you but we will cover the two most frequently-used in a desktop context: _VirtualBox®_ and _VMware Workstation®_, both running on Microsoft Windows 10. If you don't have corporate policy constraints or personal preference, our recommendation is that you try out VirtualBox first, as it is free, works well, is (mostly) open-source, and is available for most operating systems.

For the next sections, we will assume that you have already installed the appropriate virtualization tool and are familiar with its operation.

#### Preliminary Remarks

To fully benefit from virtualization, you should have a CPU with the appropriate virtualization features and they should not be disabled by the BIOS/UEFI. Double check for any "Intel® Virtualization Technology" and/or "Intel® VT-d Feature" options in the machine's Setup screens.

You should also have a 64-bit host operating system, such as `amd64` architecture for Debian-based Linux distributions, `x86_64` architecture for RedHat-based Linux distributions, and `64-bit` for Microsoft Windows.

If you lack any of the prerequisites, either the virtualization tool will not work properly or it will be restricted to running only 32-bit guest operating systems.

Since virtualization tools hook into the host operating system and hardware at a low level, there are often incompatibilities between them. Do not expect these tools to run well at the same time. Also, Microsoft Windows users beware that professional editions or higher come with _Hyper-V_ installed and enabled, which might interfere with your virtualization tool of choice. To turn it off, execute "Turn Windows features on or off" from Windows Settings.

#### VirtualBox

After the initial installation, VirtualBox's main screen looks something like Figure 8.

![Figure 8: VirtualBox's Start Screen](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/85237052b78add010149ee00db426d80-03_vbox-start-screen.png)

Figure 8: VirtualBox's Start Screen

Click on **New** Figure 9) to start a wizard that will guide you through the multiple steps required to input all the parameters of the new virtual machine.

![Figure 9: Name and Operating System](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/6637d77f389e7dae0ddc97b5fe1073a1-03_vbox-new-vm-01.png)

Figure 9: Name and Operating System

In the first step, shown in Figure 10, you must assign a name to your new virtual machine. We will use "Kali Linux." You must also indicate what kind of operating system will be used. Since Kali Linux is based on Debian GNU/Linux, select "Linux" for the type and "Debian (32-bit)" or "Debian (64-bit)" for the version. Although any other Linux version will most likely work, this will help distinguish between the various virtual machines that you might have installed.

![Figure 10: Memory Size](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/dd05c7d16f6adb93231e551e359370e0-03_vbox-new-vm-02-ram.png)

Figure 10: Memory Size

In the second step, you must decide how much memory to allocate to the virtual machine. While the recommended size of 1024 MB is acceptable for a Debian virtual machine acting as a server, it is definitely not enough to run a Kali desktop system, especially not for a Kali Linux live system, as the live system uses memory to store changes made to the file system. We recommend increasing the value to 1500 MB Figure 11 and highly recommend that you allocate no less than 2048 MB of RAM. For more information, see [_Minimal Installation Requirements_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/installing-kali-linux).

![Figure 11: Hard Disk](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/9de02963db8a153ac36ffde8fbd820af-03_vbox-new-vm-03-disk.png)

Figure 11: Hard Disk

In the third step (shown in Figure 12, you are prompted to choose a physical or virtual hard disk for your new virtual machine. Although a hard disk is not required to run Kali Linux as a live system, add one for when we demonstrate the installation procedure later, in [Module 4, Installing Kali Linux](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/installing-kali-linux).

![Figure 12: Hard Disk File Type](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/4a2d20a55cf91f4e2bd309ee7e1d2d6d-03_vbox-new-vm-04-disk-type.png)

Figure 12: Hard Disk File Type

The content of the hard disk of the virtual machine is stored on the host machine as a file. VirtualBox is able to store the contents of the hard disk using multiple formats (shown in Figure 13 : the default (`VDI`) corresponds to VirtualBox's native format; `VMDK` is the format used by VMware. Keep the default value, because you don't have any reason to change it. The ability to use multiple formats is interesting mainly when you want to move a virtual machine from one virtualization tool to another.

![Figure 13: Storage on Physical Hard Disk](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/7a0bc07a0cd653d6e5a191d638ece62f-03_vbox-new-vm-05-disk-dynamic.png)

Figure 13: Storage on Physical Hard Disk

The explanation text in Figure 14 clearly describes the advantages and drawbacks of dynamic and fixed disk allocation. In this example, we accept the default selection (Dynamically allocated), since we are using a laptop with SSD disks. We don't want to waste space and won't need the extra bit of performance as the machine is already quite fast to begin with.

![Figure 14: File Location and Size](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/353fcb811074bfe02f2d5ca1118e2ef1-03_vbox-new-vm-06-disk-size.png)

Figure 14: File Location and Size

The default hard disk size of 20 GB shown in Figure 15 is enough for a standard installation of Kali Linux, so we will not change it. For more information about Kali's requirements see [_Minimal Installation Requirements_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/installing-kali-linux/minimal-installation-requirements/minimal-installation-requirements). You can also tweak the name and the location of the disk image. This can be handy when you don't have enough space on your hard disk, allowing you to store the disk image on an external drive.

![Figure 15: The New Virtual Machine Appears in the List](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/f717d603d4a1587e00ca2baee1ce1076-03_vbox-vm-list.png)

Figure 15: The New Virtual Machine Appears in the List

The virtual machine has been created but you can't really run it yet, because there is no operating system installed. You also have some settings to tweak. Click on **Settings** on the VM Manager screen and let's review some of the most useful settings.

![Figure 16: Storage Settings](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/3f7f699eb1ad7be68ba8803f2d0d7b2f-03_vbox-settings-storage.png)

Figure 16: Storage Settings

In the Storage screen Figure 17, you should associate the Kali Linux ISO image with the virtual CD/DVD-ROM reader. First, select the CD-ROM drive in the Storage Tree list and then click on the small CD-ROM icon on the right to display a contextual menu where you can **Choose Virtual Optical Disk File...**.

![Figure 17: System Settings: Motherboard](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/c1e3b29233d8fa43bf4c3ba8355b0439-03_vbox-settings-system-motherboard.png)

Figure 17: System Settings: Motherboard

In the System screen Figure 18, you will find a Motherboard tab. Make sure that the boot order indicates that the system will first try to boot from any optical device before trying a hard disk. This is also the tab where you can alter the amount of memory allocated to the virtual machine, should the need arise.

![Figure 18: System Settings: Processor](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/a99bc32c3a3150527fded7d6c573b936-03_vbox-settings-system-processor.png)

Figure 18: System Settings: Processor

In the same screen but on the "Processor" tab Figure 18, you can adjust the number of processors assigned to the virtual machine. Most importantly, if you use a 32-bit image, enable PAE/NX or the Kali image will not boot since the default kernel variant used by Kali for i386 (aptly named "686-pae") is compiled in a way that requires Physical Address Extension (PAE) support in the CPU.

There are many other parameters that can be configured, like the network setup (defining how the traffic on the network card is handled), but the above changes are sufficient to be able to boot a working Kali Linux live system. Finally, click Boot and the virtual machine should boot properly, as shown in Figure 19. If not, carefully review all settings and try again.

![Figure 19: Kali Linux Boot Screen in VirtualBox](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/a60d7601c005ac216ccfd4da3fd0a4a1-03_vbox-run-vm.png)

Figure 19: Kali Linux Boot Screen in VirtualBox

#### VMware Workstation

_VMware Workstation_ is very similar to _VirtualBox_ in terms of features and user interface, because they are both designed primarily for desktop usage, but the setup process for a new virtual machine is a bit different. We will be using _VMware Workstation Pro_ edition.

![Figure 20: VMware Start Screen](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/d26626ed67a23675ad0afa5c042d0e14-03_vmware-start-screen.png)

Figure 20: VMware Start Screen

The initial screen, shown in Figure 21, displays a big **Create a New Virtual Machine** button that starts a wizard to guide you through the creation of your virtual machine.

![Figure 21: New virtual Machine Wizard](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/8f9c93e876addbf7a4e00b6639b58b21-03_vmware-new-vm-01.png)

Figure 21: New virtual Machine Wizard

In the first step, you must decide whether you want to be presented with advanced settings during the setup process. In this example, there are no special requirements so choose the typical installation, as shown in Figure 21.

![Figure 22: Guest Operating System Installation](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/88130ce69b1b762bb04660cfa989675d-03_vmware-new-vm-02-install-iso.png)

Figure 22: Guest Operating System Installation

The wizard assumes that you want to install the operating system immediately and asks you to select the ISO image containing the installation program Figure 21. Select "Installer disc image file (iso)" and click on Browse to select the image file.

![Figure 23: Select a Guest Operating System](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/2a354bb81b389ceeed9ebd2743c4ed00-03_vmware-new-vm-03-os-selection.png)

Figure 23: Select a Guest Operating System

When the operating system cannot be detected from the selected ISO image, the wizard asks you which guest OS type you intend to run. You should select "Linux" for the OS and "Debian 10.x 64-bit" for the version, as shown in Figure 24. We select "Debian 10.x" due to Kali Linux being constantly updated to the _newest_ version of Debian.

![Figure 24: Name the Virtual Machine](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/29a67ca75c58b5245421f100b22e3bc0-03_vmware-new-vm-04-name.png)

Figure 24: Name the Virtual Machine

We have chosen Kali Linux as the name of the new virtual machine Figure 24. As with VirtualBox, you also have the option to store the virtual machine files in an alternate location.

![Figure 25: Specify Disk Capacity](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/044a7181c13435b492fc43bea435c067-03_vmware-new-vm-05-disk-size.png)

Figure 25: Specify Disk Capacity

The default hard disk size of 20 GB Figure 25 is usually sufficient but you can adjust it here depending on your expected needs. As opposed to VirtualBox, which can use a single file of varying size, VMware has the ability to store the disk's content over multiple files. In both cases, the goal is to conserve the host's disk space.

![Figure 26: Ready to Create Virtual Machine](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/fb5650996810d3144d4a46c72fa3ffa8-03_vmware-new-vm-06-summary.png)

Figure 26: Ready to Create Virtual Machine

VMware Workstation is now configured to create the new virtual machine. It displays a summary of the choices made so that you can double-check everything before creating the machine. Notice that the wizard opted to allocate 2048 MB of RAM to the virtual machine, which is sufficient for our needs. If the allocated value is lower, that is not enough so click on **Customize Hardware...** Figure 26 and tweak the Memory setting, as shown in Figure 27.

![Figure 27: Configure Hardware Window](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/61ba95ba9544f01eb3ef44976dbb0c27-03_vmware-new-vm-07-configure-hardware.png)

Figure 27: Configure Hardware Window

After a last click on Finish Figure 26, the virtual machine is now configured and can be started by clicking "Power on this virtual machine" as shown in Figure 28.

![Figure 28: Kali Linux Virtual Machine Ready](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/593e932f6016fedb5296d63c53df3f71-03_vmware-kali-vm-ready.png)

Figure 28: Kali Linux Virtual Machine Ready

## 4.3. Summary

In this chapter, you learned about the various Kali Linux ISO images, learned how to verify and download them, and learned how to create bootable USB disks from them on various operating systems. We also discussed how to boot the USB disks and reviewed how to configure the BIOS/UEFI and startup settings on various hardware platforms so that the USB disks will boot.

Summary Tips:

- `www.kali.org` is the only official download site for Kali ISOs. Do not download them from any other site, because those downloads could contain malware.
- Always validate the sha256sum of your downloads with the `sha256sum` command to ensure the integrity of your ISO download. If it doesn't match, try the download again or use a different source.
- You must write the Kali Linux ISO image to a bootable media if you want to boot it on a physical machine. Use _Win32 Disk Imager_ on Microsoft Windows, the _Disks utility_ on Linux using GNOME, or the `dd` command on Mac OS X/macOS/Linux. Be _very careful_ when writing the image. Selecting the wrong disk could permanently damage data on your machine.
- Configure the BIOS/UEFI Setup screens on a PC or hold the Option key on OS X/macOS to allow the machine to boot from the USB drive.
- Virtual machine programs like _VirtualBox_ and _VMware Workstation Pro_ are especially useful if you want to try out Kali Linux but aren't ready to commit to installing it permanently on your machine or if you have a powerful system and want to run multiple operating systems simultaneously.

Now that you have a working installation of Kali Linux, it is time to delve into some Linux fundamentals that are required for basic and advanced operation of Kali. If you are a moderate to advanced Linux user, consider skimming the next chapter ([_Linux Fundamentals_](https://portal.offsec.com/courses/pen-103/books-and-videos/modal/modules/linux-fundamentals)).

### 4.4.1. Getting set up, downloading and verifying, and burning Kali

#### Exercise:

0. Re-use the ["Kali Live 64-bit ISO"](https://www.kali.org/get-kali/#kali-live) from the previous chapter.
1. Download a pre-made [Kali Linux VM release](https://www.kali.org/get-kali/#kali-virtual-machines) _(we suggest 64-bit version)_.
2. Launch the Kali VM.
3. **From this point forward, you should be in the VM**. [Log into the VM](https://www.kali.org/docs/introduction/default-credentials/) (**kali**/**kali**) and copy over the live image into the Kali VM.
4. Download and import Kali's public GPG key.
5. Extract the fingerprint and get the SHA256SUMS and the associated signature file for the Kali ISOs.
6. Verify that the SHA256 checksum for your downloaded ISO matches the one in the SHA256SUMS file
7. Create a bootable USB device with the image.

---

#### Exercise solution:

1. You shouldn't need help installing a VM program (VMware or VirtualBox).
2. You shouldn't need help downloading Kali VM. _If you do, this course is not for you._
3. Extract the Kali VM `.7z` file, launch the `.VMX` file (if VMware) or `.OVA` (if VirtualVBox) in the extracted directory to run the VM.
4. Copy/download the Kali live ISO.

_Note: that through this exercise your version numbers may differ._

```
kali@kali:~$ wget https://archive.kali.org/kali-images/kali-2020.3/kali-linux-2020.3-live-amd64.iso
kali@kali:~$
```

5. Download and import Kali's public GPG key:

```
kali@kali:~$ wget -q -O - https://archive.kali.org/archive-key.asc | gpg --import
kali@kali:~$
#or
kali@kali:~$ gpg --keyserver hkps://keys.openpgp.org --recv-key
44C6513A8E4FB3D30875F758ED444FF07D8D0BF6
kali@kali:~$
```

6. Extract the fingerprint and get the ISO SHASUMS:

```
kali@kali:~$ gpg --fingerprint 44C6513A8E4FB3D30875F758ED444FF07D8D0BF6
kali@kali:~$
kali@kali:~$ wget https://archive.kali.org/kali-images/kali-2020.3/SHA256SUMS
kali@kali:~$
kali@kali:~$ wget https://archive.kali.org/kali-images/kali-2020.3/SHA256SUMS.gpg
kali@kali:~$
```

7. Now, we will verify the signature, to see if the SHA256SUMS file is authentic:

```
kali@kali:~$ gpg --verify SHA256SUMS.gpg SHA256SUMS
kali@kali:~$
```

You should see a confirmation: "Good signature from "Kali Linux Repository (devel@kali.org)"

You may see the following warning:

```
gpg: WARNING: This key is not certified with a trusted signature!
```

This warning is normal. You can avoid it by using the "`--trust-model` always" option. The warning just says that there's no path between your set of trusted keys and the Kali key in the web of trust. If you don't have a key and/or if you never signed anyone else's key, you will never have a trust path to any other key.

Now that you know the SHA256SUMS file is authentic, you can trust the hashes that are in that file. Now, get the SHA sum of the ISO you downloaded:

```
kali@kali:~$ shasum -a 256 ./kali-linux-2020.3-live-amd64.iso
1a0b2ea83f48861dd3f3babd5a2892a14b30a7234c8c9b5013a6507d1401874f  ./kali-linux-2020.3-live-amd64.iso
kali@kali:~$
```

Compare your hash with the hash listed in the (now-trusted) SHA256SUMS file:

```
kali@kali:~$ grep kali-linux-2020.3-live-amd64 SHA256SUMS
1a0b2ea83f48861dd3f3babd5a2892a14b30a7234c8c9b5013a6507d1401874f  kali-linux-2020.3-live-amd64.iso
kali@kali:~$
```

If the hashes don't match, you've done something wrong (or had something wrong happen to you!).

8. Put in your USB drive, attach it to the VM, find it with `dmesg` and burn the bootable image with something like this. Beware! This is destructive! Use the right disk identifier (`/dev/sdb` in this case)!

_Note: We first use `sudo su` to elevate our privileges to prevent typing `sudo` with every command. Many commands in these exercises require elevated permissions, so being root may be easier however it will be less secure. Use `sudo` before your command if you are unsure._

```
kali@kali:~$ sudo su
root@kali:~#
root@kali:~# dmesg
[...]
[ 2596.727036] usb 1-2.1: new high-speed USB device number 7 using uhci_hcd
[ 2597.023023] usb 1-2.1: New USB device found, idVendor=0781, idProduct=5575, bcdDevice= 1.26
[ 2597.023025] usb 1-2.1: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[ 2597.023026] usb 1-2.1: Product: Cruzer Glide
[ 2597.023026] usb 1-2.1: Manufacturer: SanDisk
[ 2597.023026] usb 1-2.1: SerialNumber: 200533495211C0824E58
[ 2597.025989] usb-storage 1-2.1:1.0: USB Mass Storage device detected
[ 2597.026064] scsi host3: usb-storage 1-2.1:1.0
[ 2598.055632] scsi 3:0:0:0: Direct-Access     SanDisk  Cruzer Glide     1.26 PQ: 0 ANSI: 5
[ 2598.058596] sd 3:0:0:0: Attached scsi generic sg2 type 0
[ 2598.063036] sd 3:0:0:0: [sdb] 31266816 512-byte logical blocks: (16.0 GB/14.9 GiB)
[ 2598.067356] sd 3:0:0:0: [sdb] Write Protect is off
[ 2598.067361] sd 3:0:0:0: [sdb] Mode Sense: 43 00 00 00
[ 2598.074276] sd 3:0:0:0: [sdb] Write cache: disabled, read cache: enabled, doesn't support DPO or FUA
[ 2598.095976]  sdb: sdb1
[ 2598.108225] sd 3:0:0:0: [sdb] Attached SCSI removable disk
root@kali:~#
root@kali:~# dd if=kali-linux-2020.3-live-amd64.iso of=/dev/sdb bs=1M
6129688+0 records in
6129688+0 records out
3138400256 bytes (3.1 GB, 2.9 GiB) copied, 678.758 s, 4.6 MB/s
root@kali:~#
```

---

#### Questions

1. What good examples can you think of for booting Kali live? What about bad examples?
2. Does it strike you weird that you can simply `dd` an ISO to a USB key, and have it boot?

---

#### Answers:

1. Kali Live is great when you want to: keep a portable copy of Kali in your pocket; test out Kali Linux without making any changes on your computer; need to engage forensics mode. It's a bad idea to use Kali live as any kind of permanent installation, especially if you're hoping to save changes (no persistence!) or if you have limited memory on the boot machine.
2. The Kali (and Debian) ISO is an **isohybrid**. When the ISO is built, a **syslinux** utility runs the `isohybrid` command on the ISO, which adds a partition table to the ISO, while still keeping it a valid ISO file.

### 4.4.2. Booting Kali

#### Exercise:

1. Boot the Kali USB drive you created in the previous exercise, and select Live mode
2. Create a 6 GB test image in `/home/kali`.
3. What happened and why?
4. Verify that changes do not persist in live mode by rebooting.

---

#### Exercise solution:

1. There a couple ways you can do this. You can reboot your host machine, and boot from the USB. You can also boot VirtualBox with USB (Google "boot USB VirtualBox") or you can boot the USB from VMmare. See the [Kali Docs page](https://www.kali.org/docs/usb/boot-usb-in-a-vm/) for more info on booting USB from VMmare.
2. To create the 6 GB file:

```
kali@kali:~$ sudo dd if=/dev/zero of=test.img bs=4M count=6144
kali@kali:~$
```

3. Eventually you'll get a message that there's "no space on the device", even with a 20GB hard drive... what's happening? Well, since you're in live mode, you're working in RAM. Therefore all your "filesystem" writes end up in volatile memory. Once you run out of RAM... you run out of disk space.
    
4. Reboot, and verify your changes.
    

### 4.4.3. Editing boot parameters

#### Exercise:

1. We've booted from a pre-made Kali VM and a Kali USB drive. Now, we'll boot another way. Boot a VM from the Kali ISO. Make sure the network is in NAT mode.
2. Edit the live boot option and remove the "`quiet`" option on the kernel line for a more-verbose boot up.
3. Confirm this makes a difference in the boot verbosity.
4. Check out the boot parameters for **live** and **forensics** mode. What are the differences?

---

#### Exercise solution:

1. In order to boot from an ISO, connect the Kali ISO to a virtual CD drive before booting.

- In VMmare, this is in Virtual Machine > Settings > CD/DVD (IDE). Check the box to enable CD, and select the disk image.
- In VMmare, to enable NAT mode: Virtual Machine > Network Adapter

2. At the boot menu, choose live boot, press **tab** and remove **quiet** from **boot** parameters:

![Figure 29: Live boot kernel quiet options](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-103/images/e3a19959d9012f3a895e65fc019ac955-Live-Boot-Kernel-Quiet-option-1.png)

Figure 29: Live boot kernel quiet options

Boot with **enter**.

3. Did it?
4. The differences are in the **noswap** and **noautomount** boot parameters which exist in the forensics mode option. While **noswap** is a standard Debian boot parameter, the **noautomount** is a Kali specific feature, implemented by the `/etc/X11/Xsession.d/52kali_noautomount` file, shipped in the **kali-defaults** package.