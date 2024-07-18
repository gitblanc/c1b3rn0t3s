---
title: IDA 👠
tags:
  - Tool
---
## Installation

- Go to the [official webpage](https://hex-rays.com/ida-free/#download) and download the free version.
- Once downloaded: 
	- `chmod +x idafreeXX_linux.run`
	- `idafreeXX_linux.run`
	- Choose the desired destination to install (default `/home/USER`)
- Start it by: `/LOCATION/idafree-X.X/ida64`

### Create a permanent alias  for IDA

```shell
vim ~/.bashrc
## Add thew following at the end:

# custom aliases
alias ida="/LOCATION/idafree-X.X/ida64"

## Then do the following:
source ~/.bashrc
```

> Remember to change the version and location :D

## Opening strings

- Go to `View >> Open subviews >> Strings` or press `Shift + F12`

![](Pasted%20image%2020240419143532.png)

![](Pasted%20image%2020240419143634.png)

## Using the breakpoint

- Click on `Right click >> Add a breakpoint` or press `F2`
- In this case, we are going to analyze the previous operation of an `elf` binary which uses the `strcmp()` function:

![](Pasted%20image%2020240419144159.png)

- For text view -> `Right click >> Text View`

![](Pasted%20image%2020240419144220.png)

- Now we want to execute the binary by adding some parameters. For this we are going to do: `Debugger >> Process options` and add the argument:

![](Pasted%20image%2020240419144426.png)

- Now we can run the program by clicking the green button


