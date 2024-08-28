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

> *Credits to [https://discovery.endeavouros.com](https://discovery.endeavouros.com/hardware/optimus-manager-for-nvidia/2021/03/)*

>[!Important]
>*Nvidia drivers are not compatible with Wayland, you must use Xorg or similar*

- Check the graphics car you are using: `glxinfo | grep "OpenGL renderer"`

1. Check if they are even detected: `xrandr --listmonitors`
	1. If they are just go to: [wiki.archlinux.org](https://wiki.archlinux.org/title/Multihead) and follow the steps
2. Otherwise:
	1. Identify your GPU: `lspci | grep -E "VGA|3D"`
		- **NVIDIA**: `sudo pacman -Syu nvidia nvidia-utils nvidia-settings`
		- **AMD**: `sudo pacman -Syu`
		- **Intel**: `sudo pacman -Syu`
	2. Reboot: `sudo reboot now`

>[!Tip]
>*Try to plug the external monitors via Thunderbolt instead of HDMI*

### Enabling Nvidia GPU

> *I created the following Topic at the official forum, which dealed to the solution: [https://forum.endeavouros.com/t/nvidia-geforce-3060-rtx-mobile-not-working/59686/6](https://forum.endeavouros.com/t/nvidia-geforce-3060-rtx-mobile-not-working/59686/6)*

BTW, just do the following:

- First I removed `optimus-manager-qt-git` and `optimus-manager-git`

```shell
sudo pacman -Rs optimus-manager-git optimus-manager-qt-git
```

- Then I installed `envy-control`:

```shell
cd /your/path 
git clone https://github.com/bayasdev/envycontrol.git 
cd envycontrol 
sudo pacman -S python-pipx # this is to create an isolated environment 
pipx install .
```

- Now get the path to execute the script:

```shell
pipx list # search for the envycontrol # in my case it was: sudo /home/gitblanc/.local/bin/envycontrol --switch nvidia 
sudo /path/to/envycontrol --switch nvidia
```

- It is imperative to reboot for the changes to take effect: `sudo reboot now`

### Icon Task manager bug (disappearing icons)

> *Credits to [https://forum.endeavouros.com/t/bug-on-my-icon-only-task-manager/58990/6](https://forum.endeavouros.com/t/bug-on-my-icon-only-task-manager/58990/6)*

```shell
rm -rf ~/.config/plasma-org.kde.plasma.desktop-appletsrc
rm -rf ~/.config/plasmashellrc
rm -rf ~/.config/kdeglobals
rm -rf ~/.config/kded*
rm -rf ~/.config/kactivitymanagerd
rm -rf ~/.config/kcm_* 
rm -rf ~/.config/kglobalaccel*
rm -rf ~/.config/kirigami*
rm -rf ~/.config/kwinrc
rm -rf ~/.config/kscreenlockerrc
rm -rf ~/.config/kwin*
rm -rf ~/.config/kio_uiserver
rm -rf ~/.config/ksmserverrc
rm -rf ~/.config/kded*
rm -rf ~/.local/share/plasma*
rm -rf ~/.kde4
rm -rf ~/.cache/* 
rm -rf ~/.local/share/kscreen* 
rm -rf ~/.local/share/konsole*
sudo reboot now
```


## Install nvidia drivers

- Run: `nvidia-inst`

