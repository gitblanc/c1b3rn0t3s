---
title: Entrada y salida de datos 🥝
tags:
  - Theory
  - Hack4u
---
>[!Warning]
>*This course is fully in spanish :d*

![](Pasted%20image%2020240826120138.png)

## Entrada por teclado y salida por pantalla

La interacción del usuario a través de la consola es una habilidad esencial en Python, y en esta clase, exploraremos las funciones que permiten la entrada y salida de datos. Utilizaremos ‘**input()**‘ para recoger la entrada del teclado y ‘**print()**‘ para mostrar mensajes en la pantalla.

En cuanto al formato de texto, veremos cómo manejar y presentar la información de manera amigable. Esto incluye desde la manipulación básica de cadenas hasta técnicas más avanzadas de formateo de cadenas que permiten la inserción de variables y la alineación del texto.

La codificación de caracteres es un aspecto clave para garantizar que la entrada y salida manejen adecuadamente diferentes idiomas y conjuntos de caracteres, preservando la integridad de los datos y la claridad de la comunicación en la consola.

Dominar estas funciones es crucial para crear programas que requieran interacción con el usuario, y te brindarán las herramientas necesarias para construir aplicaciones interactivas robustas y fáciles de usar.

```python
nombre = input("\n[+] Dime tu nombre") # Lo que se recibe es un str
print(f"Tu nombre es: {nombre}")
```

```python
from getpass import getpass
passwd = getpass("\n[+] Dime tu contraseña:") # Lo que se recibe no se ve mientras se introduce
print(f"Tu contraseña es: {passwd}")
```

## Lectura y escritura de archivos

La lectura y escritura de archivos son operaciones fundamentales en la mayoría de los programas, y Python proporciona herramientas sencillas y poderosas para manejar archivos. En esta clase, aprenderemos cómo abrir, leer, escribir y cerrar archivos de manera eficiente y segura.

**Manejo Básico de Archivos**

Explicaremos cómo utilizar la función ‘**open()**‘ para crear un objeto archivo y cómo los modos de apertura (‘**r**‘ para lectura, ‘**w**‘ para escritura, ‘**a**‘ para añadir y ‘**b**‘ para modo binario) afectan la manera en que trabajamos con esos archivos.

**Lectura de Archivos**

Detallaremos cómo leer el contenido de un archivo en memoria, ya sea de una sola vez con el método ‘**read()**‘ o línea por línea con ‘**readline()**‘ o iterando sobre el objeto archivo.

```python
# se carga todo de golpe
with open("example.txt", "rb") as f: # r -> lectura normal, rb -> lectura para caracteres especiales
	file_content = f.read()
```

- ==Más óptimo==

```python
# leyendo línea por línea
with open("example.txt", "rb") as f:
	for line in f:
		print(line) # añadir un .strip() para quitar el salto de línea final
					# añadir un .decode() si se usa rb
```

**Escritura en Archivos**

Examinaremos cómo escribir en un archivo usando métodos como ‘**write()**‘ o ‘**writelines()**‘, y cómo estos métodos difieren en cuanto a su manejo de strings y secuencias de strings.

```python
f = open("example.txt", "w") # w borra todo el contenido previo del archivo
f.write("¡Hola mundo!")
f.close()
```

```python
f = open("example.txt", "a") # conserva el contenido previo del archivo y lo añade justo después
f.write(" ¡Hola mundo de nuevo!")
f.close()
```

- ==Más óptimo==

```python
with open("example.txt", "w") as f:
	f.write("¡Hola mundo!")
```

**Manejadores de Contexto**

Uno de los aspectos más importantes de la lectura y escritura de archivos en Python es el uso de manejadores de contexto, proporcionados por la declaración ‘**with**‘. Los manejadores de contexto garantizan que los recursos se manejen correctamente, abriendo el archivo y asegurándose de que, sin importar cómo o dónde termine el bloque de código, el archivo siempre se cierre adecuadamente. Esto ayuda a prevenir errores comunes como fugas de recursos o archivos que no se cierran si ocurre una excepción.

El uso de ‘**with open()**‘ no solo mejora la legibilidad del código, sino que también simplifica el manejo de excepciones al trabajar con archivos, haciendo el código más seguro y robusto.

Al concluir esta clase, tendrás una comprensión profunda de cómo interactuar con el sistema de archivos en Python, cómo procesar datos de archivos de texto y binarios, y las mejores prácticas para asegurar que los archivos se lean y escriban de manera efectiva. Estos conocimientos son vitales para una amplia gama de aplicaciones, desde el análisis de datos hasta la automatización de tareas y el desarrollo de aplicaciones web.

```python
try:
	with open("example.txt", "rb") as f_in, open("image.png", "wb") as f_out:
		file_content = f_in.read() # para leer todo el contenido de golpe
		f_out.write(file_content)
except FileNotFoundError:
	print("\n[!] No ha sido posible encontrar este archivo :(")
```

## Formateo de cadenas y manipulación de texto

El formateo de cadenas y la manipulación de texto son habilidades esenciales en Python, especialmente en aplicaciones que involucran la presentación de datos al usuario o el procesamiento de información textual. En esta clase, nos centraremos en las técnicas y herramientas que Python ofrece para trabajar con cadenas de texto.

**Formateo de Cadenas**

Aprenderemos los distintos métodos de formateo de cadenas que Python proporciona, incluyendo:

- **Formateo Clásico**: A través del operador %, similar al ‘**printf**‘ en C.
- **Método format()**: Un enfoque versátil que ofrece numerosas posibilidades para formatear y alinear texto, rellenar caracteres, trabajar con números y más.
- **F-strings (Literal String Interpolation)**: Introducido en Python 3.6, este método permite incrustar expresiones dentro de cadenas de texto de una manera concisa y legible.

**Manipulación de Texto**

Exploraremos las funciones y métodos incorporados para la manipulación de cadenas, que incluyen:

- **Métodos de Búsqueda y Reemplazo**: Como ‘**find()**‘, ‘**index()**‘, ‘**replace()**‘ y métodos de expresiones regulares.
- **Métodos de Prueba**: Para verificar el contenido de la cadena, como ‘**isdigit()**‘, ‘**isalpha()**‘, ‘**startswith()**‘, y ‘**endswith()**‘.
- **Métodos de Transformación**: Que permiten cambiar el caso de una cadena, dividirla en una lista de subcadenas o unirlas, como ‘**upper()**‘, ‘**lower()**‘, ‘**split()**‘, y ‘**join()**‘.

También veremos cómo trabajar con cadenas Unicode en Python, lo que es esencial para aplicaciones modernas que necesitan soportar múltiples idiomas y caracteres especiales.

Al final de esta clase, tendrás una comprensión completa de cómo dar formato a las cadenas para la salida de datos y cómo realizar operaciones comunes de manipulación de texto. Estas habilidades son fundamentales para la creación de aplicaciones que necesitan una interfaz de usuario sofisticada y para el procesamiento de datos en aplicaciones de backend.