---
title: Windows Scripting Host (WSH) 🪤
tags:
  - TryHackMe
  - Theory
---
Windows Scripting Host (WSH)

Windows scripting host is a built-in Windows administration tool that runs batch files to automate and manage tasks within the operating system.

It is a Windows native engine, cscript.exe (for command-line scripts) and wscript.exe (for UI scripts), which are responsible for executing various Microsoft Visual Basic Scripts (VBScript), including vbs and vbe. For more information about VBScript, please visit [here](https://en.wikipedia.org/wiki/VBScript). It is important to note that the VBScript engine on a Windows operating system runs and executes applications with the same level of access and permission as a regular user; therefore, it is useful for the red teamers.

Now let's write a simple VBScript code to create a windows message box that shows the Welcome to THM message. Make sure to save the following code into a file, for example, hello.vbs.

```javascript
Dim message 
message = "Welcome to THM"
MsgBox message
```

In the first line, we declared the message variable using Dim. Then we store a string value of Welcome to THM in the message variable. In the next line, we use the MsgBox function to show the content of the variable. For more information about the MsgBox function, please visit [here](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/scripting-articles/sfw6660x(v=vs.84)?redirectedfrom=MSDN). Then, we use wscript to run and execute the content of hello.vbs. As a result, A Windows message will pop up with the Welcome to THM message.

![](Pasted%20image%2020240127113836.png)

Now let's use the VBScript to run executable files. The following vbs code is to invoke the Windows calculator, proof that we can execute .exe files using the Windows native engine (WSH).

```javascript
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True
```

We create an object of the WScript library using CreateObject to call the execution payload. Then, we utilize the Run method to execute the payload. For this task, we will run the Windows calculator calc.exe. 

To execute the vbs file, we can run it using the wscript as follows,

```shell
c:\Windows\System32>wscript c:\Users\thm\Desktop\payload.vbs
```

We can also run it via cscript as follows,

```shell
c:\Windows\System32>cscript.exe c:\Users\thm\Desktop\payload.vbs
```

As a result, the Windows calculator will appear on the Desktop.

![](Pasted%20image%2020240127113924.png)

Another trick. If the VBS files are blacklisted, then we can rename the file to .txt file and run it using wscript as follows,

```shell
c:\Windows\System32>wscript /e:VBScript c:\Users\thm\Desktop\payload.txt
```

The result will be as exact as executing the vbs files, which run the calc.exe binary.

![](Pasted%20image%2020240127114002.png)