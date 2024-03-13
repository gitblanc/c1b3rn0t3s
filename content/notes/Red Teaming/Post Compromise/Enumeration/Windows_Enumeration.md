---
title: Windows Enumeration 🧊
---
![](Pasted%20image%2020240131214129.png)

In this task, we assume you have access to `cmd` on a Microsoft Windows host. You might have gained this access by exploiting a vulnerability and getting a shell or a reverse shell. You may also have installed a backdoor or set up an SSH server on a system you exploited. In all cases, the commands below require `cmd` to run.

In this task, we focus on enumerating an MS Windows host. For enumerating MS Active directory, you are encouraged to check the [Enumerating Active Directory](https://tryhackme.com/room/adenumeration) room. If you are interested in a privilege escalation on an MS Windows host, we recommend the [Windows Privesc 2.0](https://tryhackme.com/room/windowsprivesc20) room.

We recommend that you click "**Start AttackBox**" and "**Start Machine**" so that you can experiment and answer the questions at the end of this task.

## System

One command that can give us detailed information about the system, such as its build number and installed patches, would be `systeminfo`. In the example below, we can see which hotfixes have been installed.

```shell
C:\>systeminfo

Host Name:                 WIN-SERVER-CLI
OS Name:                   Microsoft Windows Server 2022 Standard
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
[...]
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: KB5013630
                           [02]: KB5013944
                           [03]: KB5012673
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
[...]
```

You can check installed updates using `wmic qfe get Caption,Description`. This information will give you an idea of how quickly systems are being patched and updated.

```shell
C:\>wmic qfe get Caption,Description
Caption                                     Description      
http://support.microsoft.com/?kbid=5013630  Update
https://support.microsoft.com/help/5013944  Security Update
                                            Update
```

You can check the installed and started Windows services using `net start`. Expect to get a long list; the output below has been snipped.

```shell
C:\>net start
These Windows services are started:

   Base Filtering Engine
   Certificate Propagation
   Client License Service (ClipSVC)
   COM+ Event System
   Connected User Experiences and Telemetry
   CoreMessaging
   Cryptographic Services
   DCOM Server Process Launcher
   DHCP Client
   DNS Client
[...]
   Windows Time
   Windows Update
   WinHTTP Web Proxy Auto-Discovery Service
   Workstation

The command completed successfully.
```

If you are only interested in installed apps, you can issue `wmic product get name,version,vendor`. If you run this command on the attached virtual machine, you will get something similar to the following output.

```shell
C:\>wmic product get name,version,vendor
Name                                                            Vendor                                   Version
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.28.29910     Microsoft Corporation                    14.28.29910
[...]
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29910  Microsoft Corporation                    14.28.29910
```

## Users

To know who you are, you can run `whoami`; moreover, to know what you are capable of, i.e., your privileges, you can use `whoami /priv`. An example is shown in the terminal output below.

```shell
C:\>whoami
win-server-cli\strategos

> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
[...]
```

Moreover, you can use `whoami /groups` to know which groups you belong to. The terminal output below shows that this user belongs to the `NT AUTHORITY\Local account and member of Administrators group` among other groups.

```shell
C:\>whoami /groups

GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ===============================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
[...]
```

You can view users by running `net user`.

```shell
C:\>net user

User accounts for \\WIN-SERVER-CLI

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
michael                  peter                    strategos
WDAGUtilityAccount
The command completed successfully.
```

You can discover the available groups using `net group` if the system is a Windows Domain Controller or `net localgroup` otherwise, as shown in the terminal below.

```shell
C:\>net localgroup

Aliases for \\WIN-SERVER-CLI

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Certificate Service DCOM Access
*Cryptographic Operators
*Device Owners
[...]
```

You can list the users that belong to the local administrators’ group using the command `net localgroup administrators`.

```shell
C:\>net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
michael
peter
strategos
The command completed successfully.
```

Use `net accounts` to see the local settings on a machine; moreover, you can use `net accounts /domain` if the machine belongs to a domain. This command helps learn about password policy, such as minimum password length, maximum password age, and lockout duration.

## Networking

You can use the `ipconfig` command to learn about your system network configuration. If you want to know all network-related settings, you can use `ipconfig /all`. The terminal output below shows the output when using `ipconfig`. For instance, we could have used `ipconfig /all` if we wanted to learn the DNS servers.

```shell
C:\>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : localdomain
   Link-local IPv6 Address . . . . . : fe80::3dc5:78ef:1274:a740%5
   IPv4 Address. . . . . . . . . . . : 10.20.30.130
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.20.30.2
```

On MS Windows, we can use `netstat` to get various information, such as which ports the system is listening on, which connections are active, and who is using them. In this example, we use the options `-a` to display all listening ports and active connections. The `-b` lets us find the binary involved in the connection, while `-n` is used to avoid resolving IP addresses and port numbers. Finally, `-o` display the process ID (PID).

In the partial output shown below, we can see that `netstat -abno` showed that the server is listening on TCP ports 22, 135, 445 and 3389. The processes`sshd.exe`, `RpcSs`, and `TermService` are on ports `22`, `135`, and `3389`, respectively. Moreover, we can see two established connections to the SSH server as indicated by the state `ESTABLISHED`.

```shell
C:\>netstat -abno

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       2016
 [sshd.exe]
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       924
  RpcSs
 [svchost.exe]
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
 Can not obtain ownership information
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       416
  TermService
 [svchost.exe]
[...]
  TCP    10.20.30.130:22        10.20.30.1:39956       ESTABLISHED     2016
 [sshd.exe]
  TCP    10.20.30.130:22        10.20.30.1:39964       ESTABLISHED     2016
 [sshd.exe]
[...]
```

You might think that you can get an identical result by port scanning the target system; however, this is inaccurate for two reasons. A firewall might be blocking the scanning host from reaching specific network ports. Moreover, port scanning a system generates a considerable amount of traffic, unlike `netstat`, which makes zero noise.

Finally, it is worth mentioning that using `arp -a` helps you discover other systems on the same LAN that recently communicated with your system. ARP stands for Address Resolution Protocol; `arp -a` shows the current ARP entries, i.e., the physical addresses of the systems on the same LAN that communicated with your system. An example output is shown below. This indicates that these IP addresses have communicated somehow with our system; the communication can be an attempt to connect or even a simple ping. Note that `10.10.255.255` does not represent a system as it is the subnet broadcast address.

```shell
C:\>arp -a

Interface: 10.10.204.175 --- 0x4 
  Internet Address      Physical Address      Type
  10.10.0.1             02-c8-85-b5-5a-aa     dynamic
  10.10.16.117          02-f2-42-76-fc-ef     dynamic
  10.10.122.196         02-48-58-7b-92-e5     dynamic
  10.10.146.13          02-36-c1-4d-05-f9     dynamic
  10.10.161.4           02-a8-58-98-1a-d3     dynamic
  10.10.217.222         02-68-10-dd-be-8d     dynamic
  10.10.255.255         ff-ff-ff-ff-ff-ff     static
```

Start the attached MS Windows Server if you have not done so already, as you need it to answer the questions below. You can connect to the MS Windows VM via SSH from the AttackBox, for example, using `ssh user@10.10.222.213` where the login credentials are:

- Username: `user`
- Password: `THM33$$88`

