---
title: Insomnia
tags:
  - HackTheBox
  - Challenge
  - Easy
  - Web
  - Code_Review
date: 2025-02-17T00:00:00Z
---
![](Pasted%20image%2020250217132018.png)

I created a user and login with it:

![](Pasted%20image%2020250217132958.png)

Inspecting the source code I noticed that there is a user `administrator` with a random password of 16 chars and a JWT secret:

![](Pasted%20image%2020250217133200.png)

So I checked my JWT token:

![](Pasted%20image%2020250217133225.png)

Token: `gitblanc:12345678:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE3Mzk3OTUzNjYsImV4cCI6MTczOTgzMTM2NiwidXNlcm5hbWUiOiJnaXRibGFuYyJ9.l49QTujcoO13_b4sL2v8gJo2VyH19tHir8XCfCv1hFQ`

Inside the `ProfileController.php` we can notice the following code:

![](Pasted%20image%2020250217140349.png)

So basically if we login as admin, the flag will be displayed. Inspecting further I discovered a flaw inside `UserController.php`:

![](Pasted%20image%2020250217140839.png)

![](Pasted%20image%2020250217140848.png)

So if we capture the request and modify the response, we can bypass the login, because the `!count($json_data) == 2` checks if the number of params is not equals to 2:

![](Pasted%20image%2020250217141338.png)

![](Pasted%20image%2020250217141402.png)

![](Pasted%20image%2020250217141430.png)

==Challenge completed!==



