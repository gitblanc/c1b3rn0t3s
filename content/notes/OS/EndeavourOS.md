---
title: EndeavourOS
---
![](Pasted%20image%2020240826212716.png)

## Downloads

- [https://endeavouros.com/](https://endeavouros.com/)

## Forum

- [https://forum.endeavouros.com/](https://forum.endeavouros.com/)

## Cheatsheet

- Update system: `yay -Syu`
- Install a package: `yay -S PACKAGE` or + `sudo pacman -S PACKAGE`

## Install an .appimage and configure KDE Plasma shortcut

1. Download your `.appimage`
2. Create a `.desktop` like: `sudo vim /usr/share/applications/PACKAGE.desktop`
3. Inside of it put something like:

```.desktop
[Desktop Entry] 
Name=PACKAGE 
Comment=whatever
Exec=/path/to/PACKAGE.appimage 
Icon=/path/to/PACKAGE-ICON.png
Terminal=false 
Type=Application Categories=Development;whatever;
```

4. Download a proper icon and save it in the same path declared before: `/path/to/PACKAGE-ICON.png`

## ERRORS
### External monitors not working

1. Check if they are even detected: `xrandr --listmonitors`
	1. If they are just go to: [wiki.archlinux.org](https://wiki.archlinux.org/title/Multihead) and follow the steps
2. Otherwise:
	1. Identify your GPU: `lspci | grep -E "VGA|3D"`
		- **NVIDIA**: `sudo pacman -Syu nvidia nvidia-utils nvidia-settings`
		- **AMD**: `sudo pacman -Syu`
		- **Intel**: `sudo pacman -Syu`
	2. Reboot: `sudo reboot now`