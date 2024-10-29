---
title: Graverobber
tags:
  - CTF
  - HackTheBox
  - Reversing
---
Once downloaded the files I executed the binary:

![](Pasted%20image%2020241025154915.png)

We can use `strace` to know what the binary is doing:

```shell
strace ./robber

[redacted]
newfstatat(AT_FDCWD, "H/", 0x7ffc7b2fde60, 0) = -1 ENOENT (No such file or directory)
fstat(1, {st_mode=S_IFCHR|0600, st_rdev=makedev(0x88, 0), ...}) = 0
getrandom("\x0e\x4d\xea\x32\xc1\x03\x80\x7f", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x561180faa000
brk(0x561180fcb000)                     = 0x561180fcb000
write(1, "We took a wrong turning!\n", 25We took a wrong turning!
) = 25
exit_group(1)                           = ?
+++ exited with 1 +++
```

We're trying to use `newfstatat` (a specialized version of the `stat` syscall used for file metadata) on some directory `H`. So I created it and executed the binary again:

```shell
mkdir H
strace ./robber

[redacted]
newfstatat(AT_FDCWD, "H/", {st_mode=S_IFDIR|0775, st_size=4096, ...}, 0) = 0
newfstatat(AT_FDCWD, "H/T/", 0x7ffdd223ad50, 0) = -1 ENOENT (No such file or directory)
fstat(1, {st_mode=S_IFCHR|0600, st_rdev=makedev(0x88, 0), ...}) = 0
getrandom("\xc0\xa6\x66\x70\x74\xb1\x38\x02", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x55832041b000
brk(0x55832043c000)                     = 0x55832043c000
write(1, "We took a wrong turning!\n", 25We took a wrong turning!
) = 25
exit_group(1)                           = ?
+++ exited with 1 +++
```

Looks like it will open several directories in sequence. We'll write a script to automate creating them.

```python
import os
import shutil
from pwn import *

# First, detect and create the directory to work in

try:
    shutil.rmtree("directories")
    os.mkdir("directories")
except Exception:
    pass
os.chdir("directories")

# Then, we will loop running the binary under strace (using -e to filter only the newfstatat calls):

while True:
    with context.local(log_level='ERROR'):
        p = process(["strace", "-e", "newfstatat", "../robber"])
        out = p.recvall().decode()
        p.close()

		# We'll then look at the last call to see the last path expected, and use that to create a directory. We'll also break if the error message isn't printed as we've likely found the whole path

        if 'wrong turning' not in out: break
        stats = [line for line in out.split("\n") if "newfstatat" in line]
        # Get last line, and get the content of the string
        path = stats[-1].split('"')[1]
        # Remove separators and print path
        print(path.replace("/", ""))
        # Recursively make the directory
        os.makedirs(path)
```

![](Pasted%20image%2020241025155730.png)