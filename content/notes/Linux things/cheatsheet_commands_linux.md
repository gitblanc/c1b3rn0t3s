---
title: Some Linux cheatsheet  commands 👾
---

- Get all the info of your operating system

```
hostnamectl
```

- Get the content of a .sh:

```
file file.sh
```

- Get the PATH:

```
echo $PATH
```

- Get the bash functions available:

```
declare -F
```

- To count the results:

```
declare -f | wc -l
```

- List a function definition:

```
type quote
```

- Use a funtion:

```
quote bob
```

- If you don't have Internet, try this:

```
sudo ifconfig eth0 up
sudo dhclient eth0
```

- SUID:

  - Files with the SUID bit set when executed are run with the permissions of the owner of the file. So if there is an binary that is owned by root and it has the SUID bit set we could theoretically use this binary to elevate our permissions.

    To find SUID binaries, we can run the following command:

```
find / -user root -perm /4000 2>/dev/null
```

- How to find any file:

```
find / type f -iname filename.txt 2> /dev/null
```

- Get the size of a file:

```
du -sh file.txt
```

- BASH math -> https://phoenixnap.com/kb/bash-math
- `ERROR: Unable to negotiate with X.X.X.X port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss`

```
ssh -oHostKeyAlgorithms=+ssh-dss username@x.x.x.x
```

- To encrypt an external or internal hard drive or USB:

```
sudo apt-get install cryptsetup
sudo apt-get install gnome-disk-utility
```

- Compare the size of two remote files using ssh:

```
ls -l file.txt | awk '{ print $x }' #x is the option you want
```

- How to remove a package on linux:

```
sudo apt-get remove package
```

- How to upload files remotely via sftp:

```
sshpass -p passwd sftp -oHostKeyAlgorithms=+ssh-dss  username@host
put -r directory_from directory_to
```

- Check your open ports:

```
netstat -putona
netstat -nlptn
```

- Use the tool tac for printing files when cat, vi, vim... are blocked or not permitted:

```shell
tac /home/file.txt
```

- Get everything of a website to obtain flags:

```shell
wget -r -np -k http://IP_HOST
cd IP_HOST
grep -nri "THM"
```

- Locate any file with `find`:

```shell
sudo find / -type f -name root.txt 2>/dev/null
# or
sudo find / -type f -name root.txt 2>/dev/null
#or
sudo find /home -type f -name root.txt 2>/dev/null
```

- Unzip a file on Linux using Python:

```shell
python3 -m zipfile -e CVE-2021-3156-main.zip .
```

- Transfer a file from remote host to yours using **scp**:

```shell
scp -i id_rsa USER@IP_HOST:/PATH/TO/THE/FILE /DESTINATION/PATH
```

- If the linux machine doesn't have `wget`, we can try:

```shell
curl "url_to_the_file" -o output.file
```
