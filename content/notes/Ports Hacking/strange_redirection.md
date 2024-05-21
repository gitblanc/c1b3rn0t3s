---
title: Strange port redirects 😒
---
## Port 22 running Apache

Something like this can be a case to study:

![](Pasted%20image%2020240521161748.png)

It's strange to see port 22 having an Apache, and you will get this error if you try to open it in the browser:

![](Pasted%20image%2020240521161857.png)

To bypass this, you must do (in Firefox):

In Firefox, navigate to `about:config`. You’ll get a message telling you that you’re voiding your warranty (for free software). Agree, and you’ll be shown a list of configurations:

![](Pasted%20image%2020240521163305.png)

From here, search for `network.security.ports.banned.override`. In some versions of Firefox this might show nothing (in which case right-click anywhere on the page, choose `new -> String` and use the search query as the preference name) — in others it will show the same as for me:

![](Pasted%20image%2020240521163317.png)

Whether you’ve had to create a new entry or not, add or change the "Value" field to be `22`:

![](Pasted%20image%2020240521163330.png)

You can now go back to the webpage and click reload. It should now load properly:

![](Pasted%20image%2020240521163340.png)