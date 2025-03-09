---
title: Accenture CTF
tags:
  - RootedCON
  - CTF
  - Web
  - Crypto
  - Forensics
date: 2025-03-06T00:00:00Z
---
![](Pasted%20image%2020250306213500.png)

# Warm Up

## Baby 1

- Decode from base64:

```shell
ZmxhZ3tCaWVudmVuaWRAX2FsX0NURn0=
flag{Bienvenid@_al_CTF}
```

## Baby 2

- Decode from base92:

```txt
F#S<YR\J*0f)Y@1;D:GyRBd=@^zv
flag{Las_buenas_bases}
```

## Baby 3

- Decode from ROT13:

```txt
synt{ry_prfne_ebznab}
flag{el_cesar_romano}
```

## Baby 4

- Brute Force XOR:

```txt
ndiosp8zWp8zWp8zW{gzzqu
flag{x0r_x0r_x0r_sorry}
```

# Web

## Login

- [http://51.15.202.137:7777/](http://51.15.202.137:7777/)

![](Pasted%20image%2020250306220134.png)

Adding `'` to the `password` parameter with Burp deals into an error, so SQLi is confirmed:

![](Pasted%20image%2020250306220231.png)

I can read the flag with basic SQLi:

![](Pasted%20image%2020250306220356.png)

## Secure Bank

- [[http://51.15.202.137/](http://51.15.202.137/)]([http://51.15.202.137/](http://51.15.202.137/))

![](Pasted%20image%2020250306220457.png)

The unique user-data entry point is the `/transfer.php` endpoint:

![](Pasted%20image%2020250306220737.png)

Performing a [dirsearch](/notes/tools/dirsearch.md) scan I found an `/administrator` endpoint:

```shell
dirsearch -u http://51.15.202.137/

[redacted]
[22:06:07] 301 -  322B  - /administrator  ->  http://51.15.202.137/administrator/
[22:06:07] 200 -  515B  - /administrator/                                   
[22:06:07] 200 -  515B  - /administrator/index.php                          
[22:06:21] 200 -  543B  - /login.php                                        
[22:06:24] 200 -  607B  - /news.php
```

![](Pasted%20image%2020250306220724.png)

==FALTA==

## Catalogo

- [http://51.15.202.137:8888/](http://51.15.202.137:8888/)

![](Pasted%20image%2020250306222249.png)

# Forensics

## Rooted logo

- We download the image and check it with `exiftool`:

```shell
exiftool rooted_logo.jpeg 
ExifTool Version Number         : 13.10
File Name                       : rooted_logo.jpeg
Directory                       : .
File Size                       : 7.2 kB
File Modification Date/Time     : 2025:03:06 22:53:07+01:00
File Access Date/Time           : 2025:03:06 22:53:34+01:00
File Inode Change Date/Time     : 2025:03:06 22:53:27+01:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 96
Y Resolution                    : 96
Exif Byte Order                 : Big-endian (Motorola, MM)
Artist                          : ZmxhZ3ttM3Q0ZDR0MHNfM243M3NjMG5kMWQ0c30=
XP Author                       : ZmxhZ3ttM3Q0ZDR0MHNfM243M3NjMG5kMWQ0c30=
Padding                         : (Binary data 268 bytes, use -b option to extract)
About                           : uuid:faf5bdd5-ba3d-11da-ad31-d33d75182f1b
Creator                         : ZmxhZ3ttM3Q0ZDR0MHNfM243M3NjMG5kMWQ0c30=
Image Width                     : 200
Image Height                    : 200
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 200x200
Megapixels                      : 0.040
```

- Then decode it from base64:

```txt
ZmxhZ3ttM3Q0ZDR0MHNfM243M3NjMG5kMWQ0c30=
flag{m3t4d4t0s_3n73sc0nd1d4s}
```

## log hunter

- If we inspect deeper the file downloaded, we can find a different hex:

![](Pasted%20image%2020250306232200.png)

- Decode it from hex:

```txt
666c61677b4c6f675f736561726368217d
flag{Log_search!}
```

## Memdump

![](Pasted%20image%2020250306234516.png)

- Decode from Hex and then XOR Brute Force:

```txt
0x0010: 4f 70 65 6e 53 6f 75 72 63 65 0x0020: 12 34 56 78 9a bc de f0 0x0030: 33 39 34 32 2e 38 30 38 31 20 38 25 0a 2d 65 27 28
flag{memdump_x0r}
```

# Crypto

## Ah!

- Apply ROT13 Brute Force:

![](Pasted%20image%2020250307001840.png)

```txt
djye{Sgcknpc_Ssqrgrsagml}
flag{Siempre_Sustitucion}
```

