---
title: BurpSuite 📙
---
## Configuring BurpSuite

*I will do it in Brave*

1. In your browser, search for [FoxyProxy](https://chromewebstore.google.com/detail/foxyproxy/gcknhkkoolaabfmlnjonogaaifnjlfnp?hl=en-US). Download it
2. Add a new Proxy with:
	- Hostname: `127.0.0.1`
	- Port: `8080`
3. Enable the proxy
4. Go to `http://burpsuite`
5. Download the CA Certificate
6. On the browser go to `Certificates >> Authorities` and enable the 3 boxes

## Analyzing just the webs you want

1. Add to the scope with: `Target >> Scope >> Add`
2. Now enable the proxy intercept and the foxyproxy on Burp

![](Pasted%20image%2020240512150638.png)

You will now only catch the traffic you have on your scope :D

## PortSwigger web labs

==MUST DO==: Pretty nice and accurate labs in [PortSwigger](https://portswigger.net/web-security/all-labs)

