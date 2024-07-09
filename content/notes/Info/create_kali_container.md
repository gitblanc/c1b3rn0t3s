---
title: Create a Kali docker container for Pentesting 🐉
---
Once you've got docker installed, do the following:

```shell
# Pull the Kali Linux Image
apt install kali-linux-headless -y

# Deploy the Kali Linux Container
docker run -ti kalilinux/kali-rolling /bin/bash

# Install the tools (by default there are no tools installed)
apt update
apt install kali-linux-headless -y # or apt -y install kali-linux-large
```

Now, connect via ssh to the machine and locate the ID for the running Kali Linux container (do not close it or exit it):

```shell
# On your hosting machine from another terminal...
docker ps
# take note of the ID
docker commit ID NAME_OF_CONTAINER
```

Then you can just run your new fresh container using:

```shell
docker run -it NAME_OF_CONTAINER /bin/bash
```