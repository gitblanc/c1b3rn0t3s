---
title: High DPI Screen Configurations (2k or more)
---
## Config Kali to autoscale

![](Pasted%20image%2020241022094034.png)

## Config Ghidra to autoscale

Go to `/usr/share/ghidra/support/launch.properties` and change this:

```shell
# High DPI Screen
VMARGS_LINUX=-Dsun.java2d.uiScale=2
#VMARGS_LINUX=-Dsun.java2d.uiScale=1
```

