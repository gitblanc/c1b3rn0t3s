---
title: Leaked credentials 🔐
tags:
  - Bug-Bounty
---
# Manual searches on the web (hacking forums)

- [Breachforums](https://breachforums.st)
- [Exploit.in](https://exploit.in/)
- [Xss.is](https://xss.is/)
- [https://www.nodo313.net/](https://www.nodo313.net/)
- [https://onniforums.com/](https://onniforums.com/) 
- [https://cyberarsenal.org/](https://cyberarsenal.org/)
- [https://leakzone.net/](https://leakzone.net/)
- [https://in4.bz/](https://in4.bz/)

>[!Note]
>*Once obtained the leak, you'll need to do some OSINT to gather the username/mail/whatever to search, and then you may want to use my tool for searching massive wordlists [Keyhunter](https://github.com/gitblanc/KeyHunter)*
>- ***Aprox. 0.05secs/100Mb***
# Regex patterns on websites

> *Credits to [h4x0r-dz](https://github.com/h4x0r-dz/Leaked-Credentials)*

## Manual (devtools)

To search for leaked credentials using Google Chrome's Developer Tools and regex, follow these short steps:

1. **Open DevTools:** In Chrome, navigate to the site you're inspecting, then open Developer Tools with `Ctrl+Shift+I` (Windows/Linux) or `Cmd+Option+I` (macOS).
2. **Go to Network Tab:** Click on the "Network" tab.
3. **Enable Regex Search:** Click the regex icon in the filter bar to enable regex mode.
4. **Refresh Page:** Refresh the page to load all network requests.
5. **Apply Regex:** Paste the given regex into the filter bar to search for patterns indicating leaked credentials.

```regexp
(access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|apikey|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|heroku_api_key|sonatype_password|awssecretkey)
```

6. **Review Matches:** Manually inspect the filtered requests to identify potential leaks.

![](Pasted%20image%2020250305095401.png)

## Using burp suite

To search for leaked credentials in your target's scope using Burp Suite:

1. **Launch Burp Suite:** Start Burp Suite and configure your browser to route traffic through it.
2. **Browse Your Target:** Navigate through your target site and its subdomains to capture traffic in Burp Suite.
3. **Use the Regex in Search:**
    - Go to the "Burp" > "Search" tab.
    - In the search type, choose "Regular expression".
    - Paste the following regex:

```regexp
(?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\-,]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\-_=]{8,64})['\"]
```

4. **Inspect Results:** Review the search results for potential leaks.

![](Pasted%20image%2020250305095444.png)

