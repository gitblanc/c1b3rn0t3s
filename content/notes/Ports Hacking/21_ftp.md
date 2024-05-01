---
title: 21 FTP 🐐
---
## Anonymous login

- Login without password:
	- User: `anonymous`

## Uploading content
### Watching it on the browser

- If you got an access to ftp, try to upload content and watching it on the brower
	- The directory might be like: `/home/ftpuser/ftp/shell.php`, if you come from making a lfi
	- If you can't access it in your browner, get the `wp-config.php` and try to find some credentials

![](Pasted%20image%2020240320112905.png)

- If you get a Forbidden error when trying to see a file that you uploaded, try to modify its permissions with `chmod 777 file.txt`
	- Now you can upload a **web shell** -> [Reverse shells 👾](reverse_shells.md)


