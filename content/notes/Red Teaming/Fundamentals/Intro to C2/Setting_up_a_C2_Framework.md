---
title: Setting up a C2 Framework 🕌
---
### Let's Setup a C2 Server

In order to gain a better understanding of what is required to set up and administer a C2 server, we will be using Armitage. As a reminder, Armitage is a GUI for the Metasploit Framework, and because of this, it has almost all aspects of a standard C2 framework.

_Note: In case you're using the AttackBox, you may skip to the Preparing our Environment section._

### Setting Up Armitage

**Downloading, Building, and Installing Armitage**

First, we must clone the repository from Gitlab:

````shell
git clone https://gitlab.com/kalilinux/packages/armitage.git && cd armitage
bash package.sh

#For me worked: $ sudo apt install armitage
````

After the building process finishes, the release build will be in the `./releases/unix/` folder.  You should check and verify that Armitage was able to be built successfully.

````shell
cd ./release/unix/ && ls -la
````

In this folder, there are two key files that we will be using:

**Teamserver -**

This is the file that will start the Armitage server that multiple users will be able to connect to. This file takes two arguments:

- IP Address

Your fellow Red Team Operators will use the IP Address to connect to your Armitage server.  

-  Shared Password

Your fellow Red Team Operators will use the Shared Password to access your Armitage server.  

**Armitage -**  
This is the file you will be using to connect to the Armitage Teamserver. Upon executing the binary, a new prompt will open up, displaying connection information and your username (this should be treated as a nickname, not a username for authentication) and password.

![](Pasted%20image%2020240125180412.png)

### Preparing our Environment

Before we can launch Armitage, we must do a few pre-flight checks to ensure Metasploit is configured properly. Armitage relies heavily on Metasploit's Database functionality, so we must start and initialize the database before launching Armitage. In order to do so, we must execute the following commands:

````shell
systemctl start postgresql && systemctl status postgresql
````

Lastly, we must initialize the Database so that Metasploit can use it. It's important to note that you **cannot** be the root user when attempting to initialize the Metasploit Database. On the **AttackBox,** you must use the **Ubuntu** user.

````shell
msfdb --use-defaults delete
msfdb --use-defaults init
````

After initialization is completed, we can finally start the Armitage Team Server. 

### Starting and Connecting to Armitage

````shell
# First in kali locate where armitage is with: $ dpkg -L armitage
cd /opt/armitage/release/unix && ./teamserver YourIP P@ssw0rd123
# In my case worke: $ cd /usr/bin/ && sudo ./teamserver 10.14.69.1 P@ssw0rd123

````

Once your Teamserver is up and running, we can now start the Armitage client. This is used to connect to the Teamserver and displays the GUI to the user.

````shell
cd /opt/armitage/release/unix && ./armitage
````

When operating a C2 Framework, you never want to expose the management interface publicly; You should always listen on a local interface, never a public-facing one. This complicates access for fellow operators. Fortunately, there is an easy solution for this. For operators to gain access to the server, you should create a new user account for them and enable SSH access on the server, and they will be able to SSH port forward TCP/55553.  Armitage **explicitly denies** users listening on 127.0.0.1; this is because it is essentially a shared Metasploit server with a "Deconfliction Server" that when multiple users are connecting to the server, you're not seeing everything that your other users are seeing. With Armitage, you must listen on your tun0/eth0 IP Address.

![](Pasted%20image%2020240125180610.png)

After clicking "Connect", you will be prompted to enter a nickname. You can set this to whatever you like; only your fellow Red Team Operators will see it.

![](Pasted%20image%2020240125180626.png)

After a moment or two, the Armitage UI should open up, until we start interacting with remote systems; it will look bare. In the next upcoming task, we will be exploiting a vulnerable virtual machine to get you more accustomed to the Armitage UI and how it can be used.

![](Pasted%20image%2020240125180642.png)

Now that Armitage is set up and working correctly, in the next task, we will learn more about securely accessing Armitage (as described above), creating listeners, various listener types, generating payloads, and much more!
