---
title: Find piHoles
tags:
  - Script
---
- More info here [bee-san](https://github.com/bee-san/How-I-Hacked-Your-Pi-Hole/blob/master/README.md)

```python
from shodan import Shodan
import requests
api = Shodan('API_KEY')

def url_ok(url):
    r = requests.head("http://" + url)
    return r.status_code == 200

def check_page(url):
    r = requests.get("http://" + url + "/admin/")
    return "Pi-hole" in r.text

def pruneIPS(vulnerableIPs):
    for i in vulnerableIPs:
        if not url_ok(i):
            if not check_page(i):
                vulnerableIPs.remove(i)
    return vulnerableIPs

result = api.search("pi-hole")

VulnerableIP = []
for service in result['matches']:
    VulnerableIP.append(service['ip_str'])
```