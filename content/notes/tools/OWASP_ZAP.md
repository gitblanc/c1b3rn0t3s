---
title: OWASP ZAP 🦈
---
## Configuration guide

1. Go to `Tools/Options/Local Servers/Proxies` and set port to 8081
2. Then go to `Tools/Options/Server Certificates` and click on save
3. Import it in your browser (in brave/chrome search for certificates and add it on authorities)

## Brute force login forms (FUZZ)

- Once you captured the form, send it to request and then click on the parameters you want to FUZZ