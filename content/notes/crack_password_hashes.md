---
title: Crack Password Hashes (Sites) 🤡
---

- Sites:

  - [crackstation](https://crackstation.net/)
  - [hashes.com](https://hashes.com/en/decrypt/hash)

- Using Hashcat:

```shell
hashcat -m 160 'e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme' /usr/share/wordlists/rockyou.txt
```

- `-m` option is the kind of hash you are trying to break

  - Identify the kind of hash with [hash identifier](https://www.kali.org/tools/hash-identifier/)
  - Also identify the kind of hash with: [haiti](https://github.com/noraj/haiti) or run:

  ```shell
  git clone https://github.com/noraj/haiti.git
  sudo gem install fpm
  cd haiti/packages/debian/ruby-docopt
  fpm -s gem docopt
  cd ../haiti
  fpm -s gem haiti-hash
  cd ..
  sudo dpkg -i ruby-docopt/ruby-docopt_0.6.1_all_debian11.deb
  sudo dpkg -i haiti/haiti_2.1.0_all_debian11.deb
  cd ../../
  rm -rf haiti
  ```

  - [haiti usage](https://noraj.github.io/haiti/#/pages/usage)
  - Basic command: `haiti b16f211a8ad7f97778e5006c7cecdf31`

  - [Check more hash formats on Hashcat official web](https://hashcat.net/wiki/doku.php?id=example_hashes)

- Wordlists of hashes:

  - [SecLists](https://github.com/danielmiessler/SecLists)
  - tool: [wordlistctl](https://github.com/BlackArch/wordlistctl), for searching all leaked or composed wordlists (around 6300)
    - Example usage: `wordlistctl search rockyou`
    - Download one you find: `sudo python3 wordlistctl.py fetch malenames-usa-top1000`

- Tools:
  - [Inventory raw/cracking](https://inventory.raw.pm/tools.html#title-tools-cracking)

---

- **Rule mode**: consists on using a wordlist by adding it some pattern or mangle the string. For example, adding the current year or appending a common special character
- Creating a **custom rule** for john:

```shell
# This rule appends at the end, beginning and both up to 5 digits and symbols
[List.Rules:CRACK1]
cAz"[0-9~!@#$%^&*()_+]"
cAz"[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]"
cAz"[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]"
cAz"[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]"
cAz"[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]"
cA0"[0-9~!@#$%^&*()_+]"
cA0"[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]"
cA0"[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]"
cA0"[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]"
cA0"[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]""[0-9~!@#$%^&*()_+]"

# This rule reverses all word on a wordlist
[List.Rules:CRACK5]
r

# This rule appends numbers to a string
[List.Rules:CRACK6]
Az"[0-9][0-9][0-9][0-9][0-9][0-9][0-9]"
```

- Command to extract necessary data of a wordlist and piping it to what we need:

```shell
sudo cat /usr/share/wordlists/misc/city-state-country.txt | dos2unix | grep 'Mexico*' | cut -f 1 -d ',' | uniq > mexico.txt
```

- Examples with **john**

```shell
john hash.txt --wordlist=/usr/share/wordlists/passwords/rockyou.txt rules=norajCommon02

john /home/gitblanc/TryHackMe/crackthehashlevel2/hash1.txt --format=Raw-Md5 --wordlist=/usr/share/wordlists/usernames/malenames-usa-top1000.txt --rules=CRACK1
```

- [Consult John The Ripper Wordlist rules syntax](https://www.openwall.com/john/doc/RULES.shtml)
- Ideas of mutation rules, of course several can be combined together.

- **Border mutation** - commonly used combinations of digits and special symbols can be added at the end or at the beginning, or both
- **Freak mutation** - letters are replaced with similarly looking special symbols
- **Case mutation** - the program checks all variations of uppercase/lowercase letters for any character
- **Order mutation** - character order is reversed
- **Repetition mutation** - the same group of characters are repeated several times
- **Vowels mutation** - vowels are omitted or capitalized
- **Strip mutation** - one or several characters are removed
- **Swap mutation** - some characters are swapped and change places
- **Duplicate mutation** - some characters are duplicated
- **Delimiter mutation** - delimiters are added between characters

- Depending of your distribution, the John configuration may be located at `/etc/john/john.conf` and/or `/usr/share/john/john.conf`. To locate the JtR install directory run `locate john.conf`, then create `john-local.conf` in the same directory (in my case `/usr/share/john/john-local.conf`) and create our rules in here.
- Add a new rule on the new john file:

```shell
[List.Rules:THM01]
$[0-9]$[0-9]
```

- Generate mutations on wordlists with [Mentalist](https://github.com/sc0tfree/mentalist)
- Generate specific wordlists with [Cewl](https://github.com/digininja/CeWL)
  - Example **cewl** command: `cewl -d 2 -w $(pwd)/example.txt https://example.org`
  - The `-d` option is the depth (number of link level the spider will follow)
- Craft wordlists from scratch with [TTPassGen](https://github.com/tp7309/TTPassGen)

  - Example command to create a wordlist containing all 4 digits PIN code value: `ttpassgen --rule '[?d]{4:4:*}' pin.txt`
  - Example command to generate a list of all lowercase chars combinations of length 1 to 3: `ttpassgen --rule '[?l]{1:3:*}' abc.txt`
  - Example to create a wordlist that is a combination of several wordlists (PIN + `-` + letter): `ttpassgen --dictlist 'pin.txt,abc.txt' --rule '$0[-]{1}$1' combination.txt`
  - ==Be warned combining wordlists quickly generated huge files, here combination.txt is 1.64 GB.==

- Use the tool [lyricpass](https://github.com/initstring/lyricpass) to download the lyrics of all the songs made by a group or musician.

  - Example: `lyricpass.py -a "Adele"`

- For stego challenges, if you do not find anything with common methods (like cracking with john or hashcat) try this web: [md5hashing.net](https://md5hashing.net/hash)

## Rooms

- Check the Thm [Crack the Hash Level 2](https://tryhackme.com/room/crackthehashlevel2)
