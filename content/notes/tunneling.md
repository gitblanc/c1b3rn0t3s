---
title: Tunneling 🚡
---
## Finding out what is doing a port

Quickly run:

```shell
curl localhost:9001
```

## Performing a reverse tunneling

When you find a port that is only opened in localhost like:

![](Pasted%20image%2020240417214309.png)

you can drop a SSH key on the server and use SSH to do a reverse tunneling of the port you want to access back on our machine:

```shell
# Generate the ssh key
ssh-keygen -f USERNAME
```

![](Pasted%20image%2020240417214633.png)

Now copy the `USERNAME.pub` key into the USERNAME `.ssh` folder:

![](Pasted%20image%2020240417214904.png)

```shell
cp USERNAME.pub /home/USERNAME/.ssh/authored_keys
```

Give to the SSH private key the necessary permissions and use the argument `-L` to perform a reverse port forwarding of the local port to your local box port:

```shell
chmod 400 USERNAME
ssh -L PORT:127.0.0.1:PORT -i USERNAME USERNAME@IP_ATTACK
```

