---
title: List all content recursively (tree alternative)
tags:
  - Script
---
> This script is an alternative to popular package **tree**
## Python2.7

```python
# -*- coding: utf-8 -*-

import os

# Secuencia de escape ANSI para el color azul
BLUE = '\033[94m'
RESET = '\033[0m'

def list_directory(path, indent='', output_file=None):
    try:
        items = os.listdir(path)
    except OSError as e:
        print(e)
        return

    files = []
    directories = []

    # Separar archivos y directorios
    for item in items:
        full_path = os.path.join(path, item)
        if os.path.isdir(full_path):
            directories.append(item)
        else:
            files.append(item)

    # Mostrar directorios primero
    for directory in sorted(directories):
        line = indent + '|-- ' + BLUE + directory + RESET
        print(line)
        if output_file:
            # Guardar en el archivo sin color
            output_file.write(indent + '|-- ' + directory + '\n')
        list_directory(os.path.join(path, directory), indent + '|   ', output_file)

    # Mostrar archivos
    for file in sorted(files):
        line = indent + '|-- ' + file
        print(line)
        if output_file:
            output_file.write(line + '\n')

if __name__ == '__main__':
    path = raw_input("Ingrese el path del directorio: ")
    output_path = raw_input("Ingrese el path donde desea guardar el resultado (incluya el nombre del archivo): ")

    if os.path.isdir(path):
        print(path)
        with open(output_path, 'w') as f:
            f.write(path + '\n')
            list_directory(path, output_file=f)
        print("Resultado guardado en:", output_path)
    else:
        print("El path especificado no es un directorio válido.")
```

## Python3

```python
# -*- coding: utf-8 -*-

import os

# Secuencia de escape ANSI para el color azul
BLUE = '\033[94m'
RESET = '\033[0m'

def list_directory(path, indent='', output_file=None):
    try:
        items = os.listdir(path)
    except OSError as e:
        print(e)
        return

    files = []
    directories = []

    # Separar archivos y directorios
    for item in items:
        full_path = os.path.join(path, item)
        if os.path.isdir(full_path):
            directories.append(item)
        else:
            files.append(item)

    # Mostrar directorios primero
    for directory in sorted(directories):
        line = indent + '|-- ' + BLUE + directory + RESET
        print(line)
        if output_file:
            # Guardar en el archivo sin color
            output_file.write(indent + '|-- ' + directory + '\n')
        list_directory(os.path.join(path, directory), indent + '|   ', output_file)

    # Mostrar archivos
    for file in sorted(files):
        line = indent + '|-- ' + file
        print(line)
        if output_file:
            output_file.write(line + '\n')

if __name__ == '__main__':
    path = input("Ingrese el path del directorio: ")
    output_path = input("Ingrese el path donde desea guardar el resultado (incluya el nombre del archivo): ")

    if os.path.isdir(path):
        print(path)
        with open(output_path, 'w') as f:
            f.write(path + '\n')
            list_directory(path, output_file=f)
        print("Resultado guardado en:", output_path)
    else:
        print("El path especificado no es un directorio válido.")
```

## Output example

![](Pasted%20image%2020240904110340.png)