---
title: Password Profiling 🚔
---
Having a good wordlist is critical to carrying out a successful password attack. It is important to know how you can generate username lists and password lists. In this section, we will discuss creating targeted username and password lists. We will also cover various topics, including default, weak, leaked passwords, and creating targeted wordlists.  

## Default Passwords  

Before performing password attacks, it is worth trying a couple of default passwords against the targeted service. Manufacturers set default passwords with products and equipment such as switches, firewalls, routers. There are scenarios where customers don't change the default password, which makes the system vulnerable. Thus, it is a good practice to try out admin:admin, admin:123456, etc. If we know the target device, we can look up the default passwords and try them out. For example, suppose the target server is a Tomcat, a lightweight, open-source Java application server. In that case, there are a couple of possible default passwords we can try: admin:admin or tomcat:admin.

Here are some website lists that provide default passwords for various products.

- [](https://cirt.net/passwords)[https://cirt.net/passwords](https://cirt.net/passwords)
- [](https://default-password.info/)[https://default-password.info/](https://default-password.info/)
- [](https://datarecovery.com/rd/default-passwords/)[https://datarecovery.com/rd/default-passwords/](https://datarecovery.com/rd/default-passwords/)

## Weak Passwords  

Professionals collect and generate weak password lists over time and often combine them into one large wordlist. Lists are generated based on their experience and what they see in pentesting engagements. These lists may also contain leaked passwords that have been published publically. Here are some of the common weak passwords lists :

- [https://wiki.skullsecurity.org/index.php?title=Passwords](https://wiki.skullsecurity.org/index.php?title=Passwords)[](https://wiki.skullsecurity.org/index.php?title=Passwords) - This includes the most well-known collections of passwords.
- [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords) - A huge collection of all kinds of lists, not only for password cracking.

## Leaked Passwords

Sensitive data such as passwords or hashes may be publicly disclosed or sold as a result of a breach. These public or privately available leaks are often referred to as 'dumps'. Depending on the contents of the dump, an attacker may need to extract the passwords out of the data. In some cases, the dump may only contain hashes of the passwords and require cracking in order to gain the plain-text passwords. The following are some of the common password lists that have weak and leaked passwords, including webhost, elitehacker,hak5, Hotmail, PhpBB companies' leaks:  

- [SecLists/Passwords/Leaked-Databases](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases)

## Combined wordlists  

Let's say that we have more than one wordlist. Then, we can combine these wordlists into one large file. This can be done as follows using cat:

```shell
cat file1.txt file2.txt file3.txt > combined_list.txt
```

To clean up the generated combined list to remove duplicated words, we can use sort and uniq as follows:

```shell
sort combined_list.txt | uniq -u > cleaned_combined_list.txt
```

## Customized Wordlists  

Customizing password lists is one of the best ways to increase the chances of finding valid credentials. We can create custom password lists from the target website. Often, a company's website contains valuable information about the company and its employees, including emails and employee names. In addition, the website may contain keywords specific to what the company offers, including product and service names, which may be used in an employee's password!   

Tools such as Cewl can be used to effectively crawl a website and extract strings or keywords. Cewl is a powerful tool to generate a wordlist specific to a given company or target. Consider the following example below:

````shell
user@thm$ cewl -w list.txt -d 5 -m 5 http://thm.labs
````

`-w` will write the contents to a file. In this case, list.txt.

`-m` 5 gathers strings (words) that are 5 characters or more

`-d` 5 is the depth level of web crawling/spidering (default 2)

http://thm.labs is the URL that will be used

As a result, we should now have a decently sized wordlist based on relevant words for the specific enterprise, like names, locations, and a lot of their business lingo. Similarly, the wordlist that was created could be used to fuzz for usernames. 

Apply what we discuss using cewl against https://clinic.thmredteam.com/ to parse all words and generate a wordlist with a minimum length of 8. Note that we will be using this wordlist later on with another task!

## Username Wordlists

Gathering employees' names in the enumeration stage is essential. We can generate username lists from the target's website. For the following example, we'll assume we have a {first name} {last name} (ex: John Smith) and a method of generating usernames.

- **{first name}:** john
- **{last name}:** smith
- **{first name}{last name}:  johnsmith** 
- **{last name}{first name}:  smithjohn**  
- first letter of the **{first name}{last name}: jsmith** 
- first letter of the **{last name}{first name}: sjohn**  
- first letter of the **{first name}.{last name}: j.smith** 
- first letter of the **{first name}-{last name}: j-smith** 
- and so on

Thankfully, there is a tool username_generator that could help create a list with most of the possible combinations if we have a first name and last name.

```shell
user@thm$ git clone https://github.com/therodri2/username_generator.git
Cloning into 'username_generator'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (7/7), done.
remote: Total 9 (delta 0), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (9/9), done.

user@thm$ cd username_generator
```

Using python3 username_generator.py -h shows the tool's help message and optional arguments.

````shell
user@thm$ python3 username_generator.py -h
usage: username_generator.py [-h] -w wordlist [-u]

Python script to generate user lists for bruteforcing!

optional arguments:
  -h, --help            show this help message and exit
  -w wordlist, --wordlist wordlist
                        Specify path to the wordlist
  -u, --uppercase       Also produce uppercase permutations. Disabled by default
````

Now let's create a wordlist that contains the full name John Smith to a text file. Then, we'll run the tool to generate the possible combinations of the given full name.

````shell
user@thm$ echo "John Smith" > users.lst
user@thm$ python3 username_generator.py -w users.lst
usage: username_generator.py [-h] -w wordlist [-u]
john
smith
j.smith
j-smith
j_smith
j+smith
jsmith
smithjohn
````

This is just one example of a custom username generator. Please feel free to explore more options or even create your own in the programming language of your choice!

## Keyspace Technique

Another way of preparing a wordlist is by using the key-space technique. In this technique, we specify a range of characters, numbers, and symbols in our wordlist. crunch is one of many powerful tools for creating an offline wordlist. With crunch, we can specify numerous options, including min, max, and options as follows:

````shell
user@thm$ crunch -h
crunch version 3.6

Crunch can create a wordlist based on the criteria you specify.  
The output from crunch can be sent to the screen, file, or to another program.

Usage: crunch   [options]
where min and max are numbers

Please refer to the man page for instructions and examples on how to use crunch.
````

The following example creates a wordlist containing all possible combinations of 2 characters, including 0-4 and a-d. We can use the -o argument and specify a file to save the output to.

````shell
user@thm$ crunch 2 2 01234abcd -o crunch.txt
Crunch will now generate the following amount of data: 243 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: xx
crunch: 100% completed generating output
````

Here is a snippet of the output:

````shell
user@thm$ cat crunch.txt
00
01
02
03
04
0a
0b
0c
0d
10
.
.
.
cb
cc
cd
d0
d1
d2
d3
d4
da
db
dc
dd
````

It's worth noting that crunch can generate a very large text file depending on the word length and combination options you specify. The following command creates a list with an 8 character minimum and maximum length containing numbers 0-9, a-f lowercase letters, and A-F uppercase letters:

crunch 8 8 0123456789abcdefABCDEF -o crunch.txt the file generated is 459 GB and contains 54875873536 words.

crunch also lets us specify a character set using the -t option to combine words of our choice. Here are some of the other options that could be used to help create different combinations of your choice:  

`@` - lower case alpha characters

`,` - upper case alpha characters

`%` - numeric characters

`^` - special characters including space

For example, if part of the password is known to us, and we know it starts with pass and follows two numbers, we can use the % symbol from above to match the numbers. Here we generate a wordlist that contains pass followed by 2 numbers:

````shell
user@thm$  crunch 6 6 -t pass%%
Crunch will now generate the following amount of data: 700 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 100
pass00
pass01
pass02
pass03
````

## CUPP - Common User Passwords Profiler

CUPP is an automatic and interactive tool written in Python for creating custom wordlists. For instance, if you know some details about a specific target, such as their birthdate, pet name, company name, etc., this could be a helpful tool to generate passwords based on this known information. CUPP will take the information supplied and generate a custom wordlist based on what's provided. There's also support for a 1337/leet mode, which substitutes the letters a, i,e, t, o, s, g, z  with numbers. For example, replace a  with 4  or i with 1. For more information about the tool, please visit the GitHub repo [here](https://github.com/Mebus/cupp).

To run CUPP, we need python 3 installed. Then clone the GitHub repo to your local machine using git as follows:

```shell
user@thm$  git clone https://github.com/Mebus/cupp.git
Cloning into 'cupp'...
remote: Enumerating objects: 237, done.
remote: Total 237 (delta 0), reused 0 (delta 0), pack-reused 237
Receiving objects: 100% (237/237), 2.14 MiB | 1.32 MiB/s, done.
Resolving deltas: 100% (125/125), done.
```

Now change the current directory to CUPP and run python3 cupp.py or with -h to see the available options.

````shell
user@thm$  python3 cupp.py
 ___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]

usage: cupp.py [-h] [-i | -w FILENAME | -l | -a | -v] [-q]

Common User Passwords Profiler

optional arguments:
  -h, --help         show this help message and exit
  -i, --interactive  Interactive questions for user password profiling
  -w FILENAME        Use this option to improve existing dictionary, or WyD.pl output to make some pwnsauce
  -l                 Download huge wordlists from repository
  -a                 Parse default usernames and passwords directly from Alecto DB. Project Alecto uses purified
                     databases of Phenoelit and CIRT which were merged and enhanced
  -v, --version      Show the version of this program.
  -q, --quiet        Quiet mode (don't print banner)
````

CUPP supports an interactive mode where it asks questions about the target and based on the provided answers, it creates a custom wordlist. If you don't have an answer for the given field, then skip it by pressing the Enter key.

```shell
user@thm$  python3 cupp.py -i
 ___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: 
> Surname: 
> Nickname: 
> Birthdate (DDMMYYYY): 


> Partners) name:
> Partners) nickname:
> Partners) birthdate (DDMMYYYY):


> Child's name:
> Child's nickname:
> Child's birthdate (DDMMYYYY):


> Pet's name:
> Company name:


> Do you want to add some key words about the victim? Y/[N]:
> Do you want to add special chars at the end of words? Y/[N]:
> Do you want to add some random numbers at the end of words? Y/[N]:
> Leet mode? (i.e. leet = 1337) Y/[N]:

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to .....txt, counting ..... words.
> Hyperspeed Print? (Y/n)
```

As a result, a custom wordlist that contains various numbers of words based on your entries is generated. Pre-created wordlists can be downloaded to your machine as follows:

````shell
user@thm$  python3 cupp.py -l
 ___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


        Choose the section you want to download:

     1   Moby            14      french          27      places
     2   afrikaans       15      german          28      polish
     3   american        16      hindi           29      random
     4   aussie          17      hungarian       30      religion
     5   chinese         18      italian         31      russian
     6   computer        19      japanese        32      science
     7   croatian        20      latin           33      spanish
     8   czech           21      literature      34      swahili
     9   danish          22      movieTV         35      swedish
    10   databases       23      music           36      turkish
    11   dictionaries    24      names           37      yiddish
    12   dutch           25      net             38      exit program
    13   finnish         26      norwegian


        Files will be downloaded from http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/ repository

        Tip: After downloading wordlist, you can improve it with -w option

> Enter number:
````

Based on your interest, you can choose the wordlist from the list above to aid in generating wordlists for brute-forcing!

Finally, CUPP could also provide default usernames and passwords from the Alecto database by using the `-a` option.

````shell
user@thm$  python3 cupp.py -a
 ___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Checking if alectodb is not present...
[+] Downloading alectodb.csv.gz from https://github.com/yangbh/Hammer/raw/b0446396e8d67a7d4e53d6666026e078262e5bab/lib/cupp/alectodb.csv.gz ...

[+] Exporting to alectodb-usernames.txt and alectodb-passwords.txt
[+] Done.
````

