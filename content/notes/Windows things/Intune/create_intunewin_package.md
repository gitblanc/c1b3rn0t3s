---
title: Create .intunewin packages 📦
tags:
  - Intune
---
# Convert .exe to .intunewin

*This content was extracted from [whackasstech.com](https://whackasstech.com/microsoft/msintune/how-to-deploy-notepad-with-microsoft-intune/) and I'll be performing the download of Notepad++*

### Step 1: Download XXXXX application

First you need to download the app you want.

### Step 2: Create Intune Win32 application

After you have downloaded the XXXXX application the next step is to create an Intune Win App. Just follow the steps below:

- Create a new folder **DeployXXXXX** on **C:.** Copy the downloaded executable into this folder. Note that the executable can have a different name.
- Create a new folder **Output** on **C:**

![](Pasted%20image%2020250402113110.png)

Now we are going to create an Intune Win file with the official application. First of all download the official Microsoft Intune Win App Tool.

- Download the official Microsoft [**Intune Win App Tool**](https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe)
- After installation **open** the Intune Win App Tool.

In the application specify the following things:

- Please specify the source folder: **C:\DeployXXXXX**
- Please specify the setup file: **XXXXX.exe**
- Please specify the output folder: **C:\Output**
- Do you want to specify catalog folder: **N**

![](Pasted%20image%2020250402113203.png)

In your Output Folder, there should be a new intunewin file. We will need this in the next step.

![](Pasted%20image%2020250402113213.png)

### Step 3: Import and deploy with Microsoft Intune

After we have created the intunewin file of the executable, we can now upload the application to Microsoft Intune and deploy it to our environment. Just follow these steps.

- Go to [**intune.microsoft.com**](https://intune.microsoft.com/)
- Click on **Apps**
- Click on **Windows**
- Click on **Add**
- Chose App type **Windows app (win32)**
- Click on **Select**

![](Pasted%20image%2020250402113251.png)

- Click on **Select app package file**
- **Upload** your IntuneWin file which is located in **C:\Output**
- Click on **OK**
- Click on **Next**

![](Pasted%20image%2020250402113304.png)

- Here you can change the Settings. I leave it as it is. Don't forget to **enter a Publisher**
- Click on **Next**

![](Pasted%20image%2020250402113325.png)

On the Program tab enter the following Commands:

- Install Command: **XXXXX.exe /S** (***NOTE: change it to your program install command***)
- Uninstall command: **C:\Program Files\XXXXX\uninstall.exe /S** (***NOTE: change it to your program uninstall command***)
- Allow available uninstall: **Yes**
- Install behavior: **System**
- Click on **Next**

![](Pasted%20image%2020250402113448.png)

On the Requirements tab enter:

- Operating system architecture: **64-bit**
- Minimum operating system: **Windows 10 YYYY** (apply to your minimum required version)
- Click on **Next**

On the Detection rules tab enter the following:

- Rules format: **Manually configure detection rules**
- Click on **Add**
- Rule type: **File**
- Path: **C:\Program Files\XXXXX
- File or Folder: XXXXX.exe**
- Detection method: **File or folder exists**
- Associated with a 32-bit app on 64-bit clients: **No**
- Click on **Ok** and on **Next**

![](Pasted%20image%2020250402113529.png)

- Define your Dependencies if applicable and click on **Next**
- Define your Supersedence if applicable and click on **Next**
- On the Assignments tab assign the Policy to a Group or to **All User**
- Click on **Next**
- And **Review + Create the Policy**