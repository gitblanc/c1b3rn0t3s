---
title: RDP 🖥️
---
## xfreerdp

```shell
xfreerdp /u:USER /p:PASSWD /cert:WHATEVER /v:IP_ATTACK /DIR
# example
xfreerdp /u:admin /p:password /cert:ignore /v:10.10.206.165 /workarea
```

>[!Note]
>If you get this error: `[ERROR][com.freerdp.core] - transport_connect_tls:freerdp_set_last_error_ex ERRCONNECT_TLS_CONNECT_FAILED [0x00020008]`, try to use **Remmina** instead

## Remmina

Run it with `remmina`

![](Pasted%20image%2020240531183019.png)

Click on `+` at top left

![](Pasted%20image%2020240531183206.png)

If you want to make it Windows 7 compatible, click on `Advanced` and set `TLS Security Level` to 0:

![](Pasted%20image%2020240531183305.png)

Also select `Use client resolution` to see at full window (like Vbox Guests):

![](Pasted%20image%2020240531183559.png)

## rdesktop

```shell
rdesktop IP_ATTACK
```

