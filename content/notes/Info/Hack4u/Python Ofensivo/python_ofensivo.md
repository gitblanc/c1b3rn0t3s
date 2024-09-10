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

