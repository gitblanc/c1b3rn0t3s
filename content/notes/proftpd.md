---
title: ProFtpd ⚕️
---
![](Pasted%20image%2020240512163901.png)

ProFtpd is a free and open-source FTP server, compatible with Unix and Windows systems. Its also been vulnerable in the past software versions.

## Connect to ftp using netcat

```shell
nc HOST PORT
```

## Copy module

```shell
# Select the file to copy
SITE CPFR /path/to/file
# Select where to copy it
SITE CPTO /new/path/to/file
```

