---
title: Tunneling 🚡
---
## Finding out what is doing a port

Quickly run:

```shell
curl localhost:9001
```

## Reverse SSH tunnelling theory

![](Pasted%20image%2020240530150957.png)

>[!Info]
>Reverse SSH port forwarding specifies that the given port on the remote server host is to be forwarded to the given host and port on the local side.

>[!Note]
>`-L` is a local tunnel (YOU <-- CLIENT). If a site was blocked, you can forward the traffic to a server you own and view it. For example, if `imgur` was blocked at work, you can do `ssh -L 9000:imgur.com:80 user@example.com` Going to `localhost:9000` on your machine, will load `imgur` traffic using your other server.
>
`-R` is a remote tunnel (YOU --> CLIENT). You forward your traffic to the other server for others to view. Similar to the example above, but in reverse.

> We will use a tool called **ss** to investigate sockets running on a host.

If we run `ss -tulpn` it will tell us what socket connections are running

| **Argument** | **Description**                    |
| ------------ | ---------------------------------- |
| `-t`         | Display TCP sockets                |
| `-u`         | Display UDP sockets                |
| `-l`         | Displays only listening sockets    |
| `-p`         | Shows the process using the socket |
| `-n`         | Doesn't resolve service names      |

To expose a service running on a blocked port by a firewall rule to the outside, we can expose the port to us (locally). Run the following on your machine:

```shell
ssh -L YOUR_MACHINE_PORT:localhost:VICTIMS_MACHINE_PORT USERNAME@IP_ATTACK
```

## Performing a reverse SSH tunneling

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
ssh -L YOUR_MACHINE_PORT:localhost:VICTIMS_MACHINE_PORT -i USERNAME USERNAME@IP_ATTACK
```

## Using Chisel

- Check the note [Chisel 🦦](/notes/tools/Chisel.md)

