---
title: Some Linux cheatsheet  commands 👾
---
- Find all the files sizes in Gb, Mb... ordered by descending:

```shell
du -sh *
```

- Get all the info of your operating system

```shell
hostnamectl
```

- Get the content of a .sh:

```shell
file file.sh
```

- Get the PATH:

```shell
echo $PATH
```

- Get the bash functions available:

```shell
declare -F
```

- To count the results:

```shell
declare -f | wc -l
```

- List a function definition:

```shell
type quote
```

- Use a funtion:

```shell
quote bob
```

- If you don't have Internet, try this:

```shell
sudo ifconfig eth0 up
sudo dhclient eth0
```

- SUID:

  - Files with the SUID bit set when executed are run with the permissions of the owner of the file. So if there is an binary that is owned by root and it has the SUID bit set we could theoretically use this binary to elevate our permissions.

    To find SUID binaries, we can run the following command:

```shell
find / -user root -perm /4000 2>/dev/null
#or
find / -type f -user root -perm -u=s 2>/dev/null
```

- How to find any file:

```shell
find / type f -iname filename.txt 2> /dev/null
```

- Get the size of a file:

```shell
du -sh file.txt
```

- BASH math -> https://phoenixnap.com/kb/bash-math
- `ERROR: Unable to negotiate with X.X.X.X port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss`

```shell
ssh -oHostKeyAlgorithms=+ssh-dss username@x.x.x.x
```

- To encrypt an external or internal hard drive or USB:

```shell
sudo apt-get install cryptsetup
sudo apt-get install gnome-disk-utility
```

- Compare the size of two remote files using ssh:

```shell
ls -l file.txt | awk '{ print $x }' #x is the option you want
```

- How to remove a package on linux:

```shell
sudo apt-get remove package
```

- How to upload files remotely via sftp:

```shell
sshpass -p passwd sftp -oHostKeyAlgorithms=+ssh-dss  username@host
put -r directory_from directory_to
```

- Check your open ports:

```shell
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
#by private key
scp -i id_rsa USER@IP_HOST:/PATH/TO/THE/FILE /DESTINATION/PATH
#by port
scp -P PORT USER@IP_HOST:/PATH/TO/THE/FILE /DESTINATION/PATH
```

- If the linux machine doesn't have `wget`, we can try:
	- Using  [Netcat 😼](Netcat.md)
	- Or the following:

```shell
curl "url_to_the_file" -o output.file
```


- Add a host to the known hosts:

```shell
sudo echo "10.10.59.31 subdomain.adana.thm" | sudo tee -a /etc/hosts
```

- Find open ports internally:

```shell
ss -tulwn
```

- Download a file from attacker's machine using `scp`:

```shell
scp USER@MACHINE-IP:/gitea/gitea/gitea.db /tmp/gitea.db
```

- If you find a `.db` try to enter to it by:

```shell
sqlite3 file.db
# The you can do
select * from user;
select lower_name, is_admin from user;
# Update the admin of a new user
UPDATE user SET is_admin=1 WHERE lower_name="<username>";
.quit #exit the database
```

- Upload the modified database:

```shell
scp /tmp/gitea.db USER@MACHINE-IP:/gitea/gitea/gitea.db
```

- Analyze services and running processes:

```shell
systemctl list-units --type=service --state=running
```

- Get to know which kind of file it is:

```shell
file /path/to/file
```

- Find `user.txt` flag:

```shell
find / -type f -name user.txt 2>/dev/null
```

- Mount a remote directory to our machine:

```shell
mkdir /mnt/NAME
mount HOST:/DIR /mnt/NAME
ls -la /mnt/NAME # to check
```

![](Pasted%20image%2020240512165418.png)

- Check if your cpu is 32 or 64 bits:

```shell
$ grep -qP '^flags\s*:.*\blm\b' /proc/cpuinfo && echo 64-bit || echo 32-bit
64-bit
```

