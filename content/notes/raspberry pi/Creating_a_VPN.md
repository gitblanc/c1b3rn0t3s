---
title: Creating a VPN ✳️
---
## Raspbery Pi Zero 2w

This vpn is going to be setup with a Zero 2w model without using a monitor and with OpenVPN configuration. [PiVpn software](https://www.pivpn.io/) will be used

- Open the [raspberry pi imager](https://www.raspberrypi.com/software/)
- Select the latest OS and configure all parameters
	- hostname
	- username & password
	- wireless LAN
	- locale settings
	- enable ssh config by authentication with username and password
- Flash the SD card
- Plug the card in the raspberry
- Let it like 5 mins to fully boot
- Connect to the raspberry by ssh: `ssh USERNAME@IP_ADDR`
	- To check the ip of the raspberry go to `http://192.168.1.1` and enter your router configuration
	- Search for network map and look for the hostname you previously assigned to the raspberry
- Run the following commands:
	- `sudo apt update`
	- `curl -L https://install.pivpn.io | bash`
	- Select UDP
	- Select static IP address
	- Configure it for OpenVPN
	- Configure Google DNS Servers

*You've finished.*

### Add vpn clients

- Run `pivpn add`
	- Introduce then the name of the client (e.g. `john_iphone`)
	- Select an expiration date for the certificate
	- Select a password

*You've finished*

### Configure the vpn on your phone

- Install OpenVpn from the App Store or Play Store
- Import the `CLIENT.ovpn` file you previously generated
- Connect to it with the password you assigned

*You've finished*

![[Pasted image 20240313234209.png]]