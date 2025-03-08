---
title: VarGroup CTF
tags:
  - RootedCON
  - CTF
date: 2025-03-08T00:00:00Z
---
# Easy

## Network Nostalgia

#### **Description:**

A retired network administrator, stuck in the past, refuses to abandon his old ways. He still configures and manages the network using deprecated and insecure protocols.

✨ **Category:** Networking  
📌 **File Provided:** `Capture.pcapng`  
🔎 **Objective:** Extract sensitive information and decrypt what’s hidden.

I did a quick search in Wireshark:

```shell
frame contains "flag"
```

![](Pasted%20image%2020250307165114.png)

So I got the flag encrypted in Cisco Type 7:
- I used to crack this [ifm.net](https://www.ifm.net.nz/cookbooks/passwordcracker.html)

```txt
0220287A2C1D2C705F4D5926310E020E335315190D182E
FLAG{C1sc0_Type_7_RIP}
```

## Warm Up

#### **Description:**

One of our colleagues sent us this message. He mentioned that he hit his head while visiting a temple during one of his trips.

✨ **Category:** Crypto  
📌 **File Provided:** `WarmUp.png`  
🔎 **Objective:** Decode the message and obtain the flag.

![](Pasted%20image%2020250307165713.png)

Searching around the internet I discovered this is Templars Cipher. I decoded it from [dcode](https://www.dcode.fr/templars-cipher)

```shell
FLAG{EASYP EASY CRYPT}
```

## I'm a Stegosaurus

#### **Description:**

A default Windows wallpaper—nothing unusual, right?

✨ **Category:** Steganography  
📌 **File Provided:** `Windows.jpg`  
🔎 **Objective:** Extract sensitive information.

I get an image:

![](Pasted%20image%2020250307170524.png)

So I performed some steganography to it and noticed that there was a flag.txt (I performed a `strings` before):

```shell
unzip Windows.jpg
[27CCE.zip] flag.txt password: 
```

As i didn't know the password I tried to Brute Force it with [John The Ripper 🐈‍⬛](/notes/tools/John_The_Ripper.md):

```shell
zip2john 27CCE.zip > hash.txt
john hash.txt

[redacted]
12345678         (27CCE.zip/flag.txt)
```

Got the flag:

```shell
FLAG{LINUX_IS_BETTER_}
```

## Message from Grandma

#### **Description:**

Gandma has forwarded me an email that she got from a special friend, but I don't understand whats going on.

✨ **Category:** Steganography  
📌 **File Provided:** `email_from_grandma.html`  
🔎 **Objective:** Find what he sent her.

We get an html. if we inspect it:

![](Pasted%20image%2020250307180304.png)

Inspecting the source code I noticed the following:

```js
function cRes() {
            const width = window.innerWidth;
            const height = window.innerHeight;
            document.getElementById('resolution').textContent = `${width}x${height}`;
            
            if (width === 240 && height === 320) {
                rQC(cQD);
            } else {
                rQC(cRP(23));
            }
        }
```

Basically, if the resolution of the browser is 240x320 we will get the correct QR. If not, we'll get a random one. So we use the mobile view of devtools and set the screen size to 240x320:

![](Pasted%20image%2020250307180453.png)

Then we can inspect it in google and get the flag:

![](Pasted%20image%2020250307180517.png)

```txt
FLAG{U_QR4zy_Gr4ndm4?}
```

## Hash roulette

#### **Description:**

32 different hashes, some more famous than others. Can you crack them all? But wait, 32? The flag was supposed to have a length of 16...

✨ **Category:** Crypto  
📌 **File Provided:** `hashes.txt`  
🔎 **Objective:** Crack the hashes and find the secret message.

![](Pasted%20image%2020250307181307.png)

![](Pasted%20image%2020250307181321.png)

![](Pasted%20image%2020250307181342.png)

| #   | Hash                                                                                                                             | crackstation | hashes.com | script | si/no/puede |
| --- | -------------------------------------------------------------------------------------------------------------------------------- | ------------ | ---------- | ------ | ----------- |
| 1   | 51b834b7c1ef0b59ea50888fcb39ace2                                                                                                 | x            | x          |        | si          |
| 2   | c4ca4238a0b923820dcc509a6f75849b                                                                                                 | 1            | 1          | 1      | si          |
| 3   | c2c53d66948214258a26ca9ca845d7ac0c17f8e7                                                                                         | T            | T          | T      | si          |
| 4   | 525ab75c928c6fac98a0f62e4da5316b7247ccd704c967ef9142925c                                                                         | 8            | 8          |        | puede       |
| 5   | 4c94485e0c21ae6c41ce1dfe7b6bfaceea5ab68e40a2476f50208e526f506080                                                                 | v            | v          | v      | si          |
| 6   | af55baaeaa31edca8eca315482bedfc9c8298ab6947826053bbd5a62c704bd75cedcea5d957fc840e590a29288f44be7                                 | F            | F          | F      | si          |
| 7   | 31bca02094eb78126a517b206a88c73cfa9ec6f704c7030d18212cace820f025f00bf0ea68dbf3f3a5436ca63b53bf7bf80ad8d5de7d8359d0b7fed9dbc3ab99 | 0            | 0          | 0      | si          |
| 8   | 37c5bddc9433ff59c69181cbab858a2ecc04c6a2                                                                                         | F            | F          |        | puede       |
| 9   | 3acb384b67995724469edc254c71f4ffcb699424606bf018254fad2e42ed613bd4a350453498a354a60dd8bd7c2ad141fb4611a7460a8f50841e569749dc32ca | A            | A          |        | puede       |
| 10  | fafa573a4caaa6d0367f122a3f40d74a61513cfa7bad05259ffe674eb7c10ae38b5e4271287c74b72d88f79019004acf95316d4142294db0b32cb69d1139f376 |              |            |        |             |
| 11  | 652e530edee5893b576f72b875ea1c918e85e29d859e7e3fa78b623d8abca3de                                                                 |              |            |        |             |
| 12  | 18ec3b715647a14c4b5d7fe870f6ac237c61bbcf8d56062a74f0824b5218a042                                                                 |              |            |        |             |
| 13  | 61886c21370ba76d87ef2ef10ee1f508dbb1f7eeb239786568ac8aa9                                                                         |              | E          |        |             |
| 14  | d7e9468290673221249673d2b82c3cb316819a8496c2f2dba3eaebd9477af44c                                                                 |              |            | u      | puede       |
| 15  | d17e08f9fd1ec955b2384bba9312e525edad397e244071a0dd499c3403719434c5c21d833e7ecd46ed47f14d2bdbcfa3                                 |              |            |        |             |
| 16  | fda430c40ee744a4f06e6a750564e16e80451b1943dbd11f8f8f399b1101a06d723c1f730cc8d996f7b5ba5656c6b963dab711dbaf0eb493978db715ee4ac986 |              |            | Z      | puede       |
| 17  | b969a39b683ce8f8e80ac2c08ce116c4c6539100b715c2e01a1dc18bcee9e6cdf1536ec4260b06646a115516a0b8c1f1b6be90f8d32e3cfc4822346581b1ccda |              |            |        |             |
| 18  | 0d869764040d76f626be277bc31072f1e85d9376223b23584817a2ba9834304f9969b024e9fe9555b750763ab4cb920c74363182e53b2e602f78099068ae4e3b |              |            |        |             |
| 19  | 800618943025315f869e4e1f09471012e69f20e9f683920d3fb4329abd951e878b1f9372                                                         | F (raro)     |            |        |             |
| 20  | aa026d33bfedc422b2e5f3876a721801241d89d70ea893bd9cbea1ca                                                                         |              |            |        |             |
| 21  | 321f9d47bb0e429b204aad72bdb5733b6e3649aa742d3106b940a68f8338aec9                                                                 | 3            |            |        |             |
| 22  | 1705466cd026f37e34007db6750bf1fe04867f81a9a6aebe60ebec7a8539b6699d1504adc104ef3d0195ee9a3f012b901ad51cfd56fc28fc64c9d393aed76290 |              | 3          |        |             |
| 23  | 818af2ae014b14c85a35639901ac6bfc47908bcbd94a7f5211627b1f52f316a994e1296503701dd6827a8e5969d33d1d0b68c452eb95e481035b168a6c0f09c4 |              |            |        |             |
| 24  | fff402b21443323c53059421cae583868121effeed539f804df382b09313285f                                                                 | X            |            |        |             |
| 25  | 754fe9beaa91bb7ae98bee55168e16c7b1f3c5aa54ccf83c28db3384633cace48639beee8cd005e3ebb6b95dd43c95b7                                 | 9            |            | X      |             |
| 26  | 19581e27de7ced00ff1ce50b2047e7a567c76b1cbaebabe5ef03f7c3017bb5b7                                                                 | K            | 9          | 9      | puede       |
| 27  | feedad52d2337e75b588db5208cc13ed335c2d0b                                                                                         | 8            | K          |        |             |
| 28  | c9f0f895fb98ab9159f51fd0297e236d                                                                                                 | y            | 8          | 8      | puede       |
| 29  | 95cb0bfd2977c761298d9624e4b4d4c72a39974a                                                                                         | 1            | y          | y      | puede       |
| 30  | 4dff4ea340f0a823f15d3f4f01ab62eae0e5da579ccb851f8db9dfe84c58b2b37b89903a740e1ee172da793a6e79d560e5f7f9bd058a12a280433ed6fa46510a | 8            | 1          | 1      | puede       |
| 31  | 525ab75c928c6fac98a0f62e4da5316b7247ccd704c967ef9142925c                                                                         |              | 8          | 8      | puede       |
| 32  | 01d241c14b95d9e7494ebc8d1c0b0b1fa050ecc8c39f77db803e1f5e8f7dcda4                                                                 |              |            |        |             |


## You know nothing, but you can know everything

#### **Description:**

You start with nothing—just an image, a face and a vague hint. But with the right techniques, the internet holds all the answers.

✨ **Category:** OSINT  
📌 **File Provided:** `TuNoSabesNada_PeroPuedesSaberloTodo.pdf`  
🔎 **Objective:** Use OSINT to find the secret code.

![](Pasted%20image%2020250307182616.png)

First we need to do a reverse image search to find the city from this image:

![](Pasted%20image%2020250307182733.png)

I got the location at google maps by searching Vargroup:

```
https://www.google.es/maps/place/Var+Group+Espa%C3%B1a/@41.6479513,-0.8829407,3a,75y,153.25h,100.22t/data=!3m7!1e1!3m5!1szecw_0_nopapoXrELMvEww!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com%2Fv1%2Fthumbnail%3Fcb_client%3Dmaps_sv.tactile%26w%3D900%26h%3D600%26pitch%3D-10.21940346445507%26panoid%3Dzecw_0_nopapoXrELMvEww%26yaw%3D153.2507201384061!7i16384!8i8192!4m10!1m2!2m1!1sVargroup!3m6!1s0xd5915561f40cf69:0xdff4f946809ee215!8m2!3d41.6478622!4d-0.8831508!15sCghWYXJncm91cJIBHmJ1c2luZXNzX21hbmFnZW1lbnRfY29uc3VsdGFudOABAA!16s%2Fg%2F11y8m68t4v?hl=es&entry=ttu&g_ep=EgoyMDI1MDMwNC4wIKXMDSoJLDEwMjExNDUzSAFQAw%3D%3D
```

For the second part I did the same but with a person:

![](Pasted%20image%2020250307184026.png)

```
Gorka Jiménez, CEO de Var Group
```

For the last one I need to find a weird message in their social networks. So I visited their website:

![](Pasted%20image%2020250307184259.png)

==FALTA==

```txt
FLAG{zaragozagorkajimenez005b8}
FLAG{zaragozagorka632}
```

# Medium

## The Uncensoring

#### **Description:**

The new junior pentester did a great job on his first audit. However, he was too confident and ended up making the same mistake he reported...

✨ **Category:** Steganography  
📌 **File Provided:** `Penetration_Test_Report_VC.pdf`  
🔎 **Objective:** Extract sensitive information.

I downloaded the pdf and found the flag inside of it but it is obfuscated:

![](Pasted%20image%2020250307230343.png)

![](flag_pixelada.png)

So I found this [Depixelation PoC](https://github.com/spipm/Depixelization_poc):

```shell
python3 depix.py \
    -p /home/gitblanc/CTFS/RootedCON2025/vargroup/medium/flag_pixelada.png \
    -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png \
    -o /home/gitblanc/CTFS/RootedCON2025/vargroup/medium/flag_despixelada.png
```

![](flag_despixelada.png)

```txt
FLAG{I was blurry wth}
```

## True or False?

#### **Description:**

Although its simple interface seems pretty straightforward, something is off in this web application. Carefully observe its responses to figure out what’s really going on beneath the surface.

✨ **Category:** Web  
🔎 **Objective:** Exploit a vulnerability to read sensitive information.

![](Pasted%20image%2020250308001123.png)

# Hard

## The Var Store

#### **Description:**

They say they are so generous that it is possible to buy flags without paying in Var Group stores. Can you check it out?

- **You must not fuzz the server**

✨ **Category:** Web  
🔎 **Objective:** Complete the purchase process and get the flag.

![](Pasted%20image%2020250308003124.png)

I capture the request with Burpsuite:

![](Pasted%20image%2020250308003149.png)

I'll modify the `Content-Type` to `json` and the body:

![](Pasted%20image%2020250308003227.png)

It worked!

![](Pasted%20image%2020250308003302.png)