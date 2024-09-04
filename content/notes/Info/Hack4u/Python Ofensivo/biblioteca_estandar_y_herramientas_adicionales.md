---
title: Biblioteca estándar y herramientas adicionales 🐝
tags:
  - Theory
  - Hack4u
---
>[!Warning]
>*This course is fully in spanish :d*

![](Pasted%20image%2020240826120138.png)

## Manejo de fechas y horas

La biblioteca ‘**datetime**‘ en Python es una de las principales herramientas para trabajar con fechas y horas. Aquí hay algunos aspectos clave sobre esta biblioteca:

- **Tipos de Datos Principales**: ‘**datetime**‘ incluye varios tipos de datos, como ‘**date**‘ (para fechas), ‘**time**‘ (para horas), ‘**datetime**‘ (para fechas y horas combinadas), y ‘**timedelta**‘ (para representar diferencias de tiempo).
- **Manipulación de Fechas y Horas**: Permite realizar operaciones como sumar o restar días, semanas, o meses a una fecha, comparar fechas, o extraer componentes como el día, mes, o año de una fecha específica.
- **Zonas Horarias**: A través del módulo ‘**pytz**‘ que se integra con ‘**datetime**‘, se pueden manejar fechas y horas en diferentes zonas horarias, lo que es crucial para aplicaciones que requieren precisión a nivel global.
- **Formateo y Análisis**: ‘**datetime**‘ permite convertir fechas y horas a strings y viceversa, utilizando códigos de formato específicos. Esto es útil para mostrar fechas y horas en formatos legibles o para parsear strings que representan fechas/horas.
- **Facilidad de Uso**: A pesar de su potencia y flexibilidad, datetime es relativamente fácil de usar, lo que la hace accesible incluso para programadores principiantes.
- **Amplia Aplicación**: Desde registros de eventos hasta cálculos de períodos de tiempo, datetime es indispensable en una variedad de aplicaciones, como sistemas de reservas, análisis de datos temporales, y más.

En resumen, datetime es una biblioteca integral y robusta para el manejo de fechas y horas en Python, ofreciendo una amplia gama de funcionalidades esenciales para el manejo de datos temporales en la programación.

```python
import datetime

ahora = datetime.datetime.now()
fecha = datetime.date(2023, 6, 14)
fecha = datetime.time(14, 6, 23)

print(ahora.year)
print(ahora.month)
print(ahora.day)
print(ahora.hour)
print(ahora.minute)
print(ahora.second)
```

## Expresiones regulares (regex)

La librería ‘**re**‘ en Python proporciona un conjunto completo de herramientas para trabajar con expresiones regulares, que son patrones de cadenas diseñados para la búsqueda y manipulación de texto.

Aquí hay varios aspectos importantes de esta librería:

- **Funciones Básicas**: ‘**re**‘ incluye funciones como ‘**search**‘ (para buscar un patrón dentro de una cadena), ‘**match**‘ (para verificar si una cadena comienza con un patrón específico), ‘**findall**‘ (para encontrar todas las ocurrencias de un patrón), y ‘**sub**‘ (para reemplazar partes de una cadena que coinciden con un patrón).
- **Compilación de Patrones**: Permite compilar expresiones regulares en objetos de patrón, lo que puede mejorar el rendimiento cuando se usan repetidamente.
- **Grupos y Captura**: Ofrece la capacidad de definir grupos dentro de patrones de expresiones regulares, lo que facilita extraer partes específicas de una cadena que coinciden con subpatrones.
- **Flags**: Soporta modificadores que alteran la forma en que las expresiones regulares son interpretadas y coincididas, como ignorar mayúsculas y minúsculas o permitir el modo multilínea.
- **Patrones Complejos**: Permite la creación de patrones complejos utilizando una variedad de símbolos y secuencias especiales, como cuantificadores, aserciones y clases de caracteres.
- **Aplicaciones Prácticas**: Las expresiones regulares son extremadamente útiles en tareas como la validación de formatos (por ejemplo, direcciones de correo electrónico), el análisis de registros (logs), el procesamiento de lenguaje natural, y la limpieza y preparación de datos.
- **Curva de Aprendizaje**: Aunque potentes, las expresiones regulares pueden ser complejas y requieren una curva de aprendizaje. Sin embargo, una vez dominadas, se convierten en una herramienta invaluable en el arsenal de cualquier programador.

En resumen, la librería ‘**re**‘ en Python es una herramienta esencial para cualquier tarea que implique procesamiento complejo de cadenas de texto, proporcionando una forma poderosa y flexible de buscar, analizar, y manipular datos basados en texto.

```python
import re

text = "mi gato está en el tejado y mi otro gato está en el jardín"

matches = re.findall("gato", text) # se almacenan todas las coincidencias
print(matches)
```

```python
import re

text = "Hoy estamos a 10/10/2023, mañana estaremos a 11/10/2023"

matches = re.findall("\d{2}/\\d{2}/\d{4}", text) # empieza por 2 dígitos, las \ hay que escaparlas
print(matches)
```

```python
import re

text = "Los usuarios pueden contactarnos a soporte@hack4u.io o a info@hack4u.io"

matches = re.findall("(\w+)@(\w+\.\w{2,})", text) # con \w contempla caracteres alfanuméricos (el + es para indicar 1 o más), la segunda cadena tiene 2 de longitud como mínimo
print(matches)
```

```python
import re

text = "mi gato está en el tejado y mi otro gato está en el jardín"
nuevo_texto = re.sub("gato", "perro", text)

print(nuevo_texto)
```

```python
import re

def validar_correo(correo):
	patron = "[A-Za-z0-9._+-]+@[A-Za-z0-9]+\.[A-Za-z]{2,}"
	if re.findall(patron, correo):
		return True
	else:
		return False

print(validar_correo("soporte@.io"))
```

```python
import re

text = "car, cart, masticar y magicarp"
re.findall(r"\bcar", texto) # con \b indicas que a la izquierda no puede haber nada más -> car, cart
re.findall(r"car\b", texto) # -> masticar, magicarp

print(nuevo_texto)
```

```python
import re

text = "Hoy estamos a 10/10/2023, mañana estaremos a 11/10/2023"
patron = r"\b(\d{2}\/\d{2}\/\d{4})\b"

for match in re.finditr(patron, texto):
	print(match)
	print(match.group(0))
```

## Manejo de archivos y directorios

La librería ‘**os**‘ y el módulo ‘**shutil**‘ en Python son herramientas fundamentales para interactuar con el sistema de archivos, especialmente en lo que respecta a la creación y eliminación de archivos y directorios.

Aquí tienes una descripción detallada de ambas:

**Librería os**

- **Funcionalidades Básicas**: ‘os’ proporciona una interfaz rica y variada para interactuar con el sistema operativo subyacente. Permite realizar operaciones como la creación y eliminación de archivos y directorios, así como la manipulación de rutas y el manejo de la información del sistema de archivos.

**Creación y Eliminación de Archivos y Directorios**

- **Creación de Directorios**: Utilizando ‘**os.mkdir()**‘ u ‘**os.makedirs()**‘, se pueden crear directorios individuales o múltiples directorios (y subdirectorios) respectivamente.
- **Eliminación**: ‘**os.remove()**‘ se usa para eliminar archivos, mientras que ‘**os.rmdir()**‘ y ‘**os.removedirs()**‘ permiten eliminar directorios y directorios con subdirectorios, respectivamente.
- **Gestión de Rutas**: La sublibrería ‘**os.path**‘ es crucial para manipular rutas de archivos y directorios, como unir rutas, obtener nombres de archivos, verificar si un archivo o directorio existe, etc.

**Módulo shutil**

- **Operaciones de Alto Nivel**: Mientras que os se enfoca en operaciones básicas, ‘**shutil**‘ proporciona funciones de nivel superior, más orientadas a tareas complejas y operaciones en lotes.
- **Copiar y Mover Archivos y Directorios**: ‘**shutil**‘ es especialmente útil para copiar y mover archivos y directorios. Funciones como ‘**shutil.copy()**‘, ‘**shutil.copytree()**‘, y ‘**shutil.move()**‘ facilitan estas tareas.
- **Eliminación de Directorios**: Aunque ‘**os**‘ puede eliminar directorios, ‘**shutil.rmtree()**‘ es una herramienta más poderosa para eliminar un directorio completo y todo su contenido.
- **Manejo de Archivos Temporales**: ‘**shutil**‘ también ofrece funcionalidades para trabajar con archivos temporales, lo que es útil para operaciones que requieren almacenamiento temporal de datos.

En resumen, ‘**os**‘ y ‘**shutil**‘ en Python son bibliotecas complementarias para la gestión de archivos y directorios. Mientras ‘**os**‘ ofrece una gran flexibilidad para operaciones básicas y de bajo nivel, ‘**shutil**‘ brinda herramientas más potentes y de alto nivel, adecuadas para tareas complejas y operaciones en lotes. Juntas, forman un conjunto integral de herramientas para la manipulación eficaz del sistema de archivos en Python.

```python
import os

if os.path.exists("mi_archivo.txt"):
	print(f"[+] El archivo existe\n")
else
	print(f"[!] El archivo no existe\n")
```

```python
import os

if not os.path.exists("mi_directorio"):
	os.mkdir("mi_directorio")
```

```python
import os

if not os.path.exists("mi_directorio/mi_subdirectorio"):
	os.mkdirs("mi_directorio/mi_subdirectorio") # crear varios directorios de golpe
```

```python
import os

print(f"\n[+] Listando todos los recursos del directorio actual de trabajo:\n")
recursos = os.listdir()
for recurso in recursos:
	print(recurso)
```

```python
import os

if os.path.exists("file1.txt"):
	os.remove("file1.txt")
if os.path.exists("mi_directorio"): 
	#os.rmdir("mi_directorio")# no deja borrar si el directorio contiene cosas
	shutil.rmtree("mi_directorio")#se puede borrar de forma recursiva
```

```python
import os

if os.path.exists("file2.txt"):
	os.rename("file2.txt", "cambiado.txt")
if os.path.exists("/etc/passwd"):
	tam = os.path.getsize("/etc/passwd")
print(tam)
```

```python
import os

ruta = os.path.join("mi_directorio", "mi_archivo.txt")

print(f"\n[+] Ruta: {ruta}")
archivo = os.path.basename(ruta)
print(f"\n[+] Nombre del archivo: {archivo}")
directorio = os.path.dirname(ruta)
print(f"\n[+] Nombre del directorio: {directorio}")

archivo, directorio = os.path.split(ruta)
```

## Conexiones de red y protocolos

Los protocolos **TCP** (Transmission Control Protocol) y **UDP** (User Datagram Protocol) son fundamentales en la comunicación de red, y la librería ‘**socket**‘ en Python proporciona las herramientas necesarias para interactuar con ellos. Aquí tienes una descripción detallada de ambos protocolos y el uso de ‘**socket**‘:

**Protocolo TCP**

- **Orientado a la Conexión**: TCP es un protocolo orientado a la conexión, lo que significa que establece una conexión segura y confiable entre el emisor y el receptor antes de la transmisión de datos.
- **Fiabilidad y Control de Flujo**: Garantiza la entrega de datos sin errores y en el mismo orden en que se enviaron. También gestiona el control de flujo y la corrección de errores.
- **Uso en Aplicaciones**: Es ampliamente utilizado en aplicaciones que requieren una entrega fiable de datos, como navegadores web, correo electrónico, y transferencia de archivos.

**Protocolo UDP**

- **No Orientado a la Conexión**: A diferencia de TCP, UDP es un protocolo no orientado a la conexión. Envía datagramas (paquetes de datos) sin establecer una conexión previa.
- **Rápido y Ligero**: UDP es más rápido y tiene menos sobrecarga que TCP, ya que no verifica la llegada de paquetes ni mantiene el orden de los mismos.
- **Uso en Aplicaciones**: Ideal para aplicaciones donde la velocidad es crucial y se pueden tolerar algunas pérdidas de datos, como juegos en línea, streaming de video y voz sobre IP (VoIP).

**Librería ‘socket’ en Python**

La librería ‘**socket**‘ en Python es una herramienta esencial para la programación de comunicaciones en red. Permite a los desarrolladores crear aplicaciones que pueden enviar y recibir datos a través de la red, ya sea en una red local o a través de Internet. Aquí tienes una visión general de la librería ‘**socket**‘:

- **Creación de sockets**: La librería ‘**socket**‘ proporciona clases y funciones para crear sockets, que son puntos finales de comunicación. Puedes crear sockets tanto para el protocolo TCP (Transmission Control Protocol) como para UDP (User Datagram Protocol).
- **Conexiones TCP**: Puedes utilizar ‘**socket**‘ para establecer conexiones TCP, que son conexiones confiables y orientadas a la conexión. Esto es útil para aplicaciones que requieren transferencia de datos confiable, como la transmisión de archivos o la comunicación cliente-servidor.
- **Comunicación UDP**: La librería ‘**socket**‘ también admite la comunicación mediante UDP, que es un protocolo de envío de mensajes sin conexión. Es adecuado para aplicaciones que necesitan una comunicación rápida y eficiente, como juegos en línea o aplicaciones de transmisión de video en tiempo real.
- **Funciones de envío y recepción**: Puedes utilizar métodos como ‘**send()**‘ y ‘**recv()**‘ para enviar y recibir datos a través de sockets. Esto te permite transferir información entre dispositivos de manera eficiente.
- **Gestión de conexiones**: La librería ‘**socket**‘ incluye métodos como ‘**bind()**‘ para asociar un socket a una dirección y puerto específicos, y ‘**listen()**‘ para poner un socket en modo de escucha, lo que le permite aceptar conexiones entrantes.
- **Conexiones cliente-servidor**: Con ‘**socket**‘, puedes crear aplicaciones cliente-servidor, donde un programa actúa como servidor esperando conexiones entrantes y otro actúa como cliente para conectarse al servidor.

En resumen, la librería ‘**socket**‘ en Python proporciona las herramientas necesarias para desarrollar aplicaciones de red, permitiendo la comunicación entre dispositivos a través de diferentes protocolos y ofreciendo control sobre la transferencia de datos. Es una parte fundamental de la programación de redes en Python y se utiliza en una amplia variedad de aplicaciones, desde servidores web hasta aplicaciones de chat y juegos en línea.

```python
#server.py
import socket

# Crear el socket del servidor
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 1234)
server_socket.bind(server_address) # ponerse en escucha en localhost en el puerto 1234

server_socket.listen(1) # límite de conexiones 1

while True:
	client_socket, client,address = server_socket.accept()
	data = client_socket.recv(1024) # tamaño del mensaje
	print(f"\n[+] Mensaje recibido del cliente: {data.decode()}")
	print(f"\n[+] Información del cliente que se ha omunicado con nosotros: {client_address}")

	client_socket.sendall(f"Un saludo crack!\n".encode()) # no se puede hacer bf, por eso el encode()

	client_socket.close()
```

![](Pasted%20image%2020240904091431.png)

```python
# client.py
import socket

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_address = ('localhost', 1234)
client_socket.connect(server_address)

try:
	message = b"Este es un mensaje de prueba que estoy enviando al servidor"
	client_socket.sendall(message)
	data = client_socket.recv(1024)
	
	print(f"\n[+] El servidor nos ha respondido con este mensaje: {data.decode()}")
finally:
	client_socket.close()
```

![](Pasted%20image%2020240904092023.png)

**Manejadores de contexto con conexiones**

Los manejadores de contexto (‘**with**‘ en Python) se utilizan para garantizar que los recursos se gestionen de manera adecuada. En el contexto de las conexiones de socket, un manejador de contexto se encarga de abrir y cerrar el socket de manera segura. Esto evita que los recursos del sistema se queden en uso indefinidamente y asegura una gestión adecuada de las conexiones.

**Diferencias entre send y sendall**

- **send(data)**: El método ‘**send()**‘ se utiliza para enviar una cantidad específica de datos a través del socket. Puede no enviar todos los datos en una sola llamada y puede ser necesario llamarlo múltiples veces para enviar todos los datos.
- **sendall(data)**: El método ‘**sendall()**‘ se utiliza para enviar todos los datos especificados a través del socket. Realiza llamadas repetidas a ‘**send()**‘ internamente para garantizar que todos los datos se envíen por completo sin pérdidas.

La elección entre ‘**send**‘ y ‘**sendall**‘ depende de si se necesita garantizar la entrega completa de los datos o si se permite que los datos se envíen en fragmentos. send puede enviar datos en fragmentos, mientras que sendall garantiza que todos los datos se envíen sin pérdida.

```python
# server.py
import socket

def start_server():
	host = 'localhost'
	port = 1234

	# Para asegurar que el descriptor se cierra correctamente
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.bind((host, port))
		print(f"\n[+] Servidor en escucha en {host}:{port}")
		s.listen(1)
		conn, addr = s.accept()

		with conn:
			print(f"\n[+] Se ha conectado un nuevo cliente: {addr}")
			while True:
				# cualquier cosa que me escriba yo se lo devuelvo
				data = conn.recv(1024)
				
				if not data:
					break
				
				conn.sendall(data) # se envía de vuelta

start_server()
```

![](Pasted%20image%2020240904093044.png)

```python
# client.py
import socket

def start_client():
	host = 'localhost'
	port = 1234

	# AF_INET: operar con IPv4, SOCK_STREAM: operar con TCP
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.connect(host, port)
		s.sendall(b"Hola, servidor!")
		data = s.recv(1024)

	print(f"\n[+] Mensaje recibido del servidor: {data.decode()}")

start_client()
```

![](Pasted%20image%2020240904093443.png)

- Ahora con UDP:

```python
# udp_server.py
import socket

def start_udp_server():
	host = 'localhost'
	port = 1234

	# SOCK_DGRAM: UDP
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
		s.bind((host, port))
		print(f"\n[+] Servidor UDP en escucha en {host}:{port}")
		
		print(f"\n[+] Se ha conectado un nuevo cliente: {addr}")
		while True:
			data, addr = s.recvfrom(1024)

			print(f"\n[+] Mensaje enviado por el cliente: {data.decode()}")
			print(f"\n[+] Información del cliente que nos ha enviado el mensaje: {addr}")

start_udp_server()
```

Ahora si nos conectamos con Netcat por TCP, nos da un connection refuse:

![](Pasted%20image%2020240904094227.png)

- Hay que usar la opción `-u`

![](Pasted%20image%2020240904094417.png)

```python
# udp_client.py
import socket

def start_udp_client():
	host = 'localhost'
	port = 1234

	# AF_INET: operar con IPv4, SOCK_STREAM: operar con TCP
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
		message = "Hola, se está tensando muchísimo".encode("utf-8")
		s.sendto(message, (host, port)) # no puedes poner acentos 

start_udp_client()
```

![](Pasted%20image%2020240904094927.png)

La función ‘**setsockopt**‘ en la programación de redes juega un papel crucial al permitir a los desarrolladores ajustar y controlar varios aspectos de los sockets. Los sockets son fundamentales en la comunicación de red, proporcionando un punto final para el envío y recepción de datos en una red.

**Niveles en setsockopt**

Cuando utilizas ‘setsockopt’, puedes especificar diferentes niveles de configuración, que determinan el ámbito y la aplicación de las opciones que estableces:

- **Nivel de Socket (SOL_SOCKET)**: Este nivel afecta a las opciones aplicables a todos los tipos de sockets, independientemente del protocolo que estén utilizando. Las opciones en este nivel controlan aspectos generales del comportamiento del socket, como el tiempo de espera, el tamaño del buffer, y el reuso de direcciones y puertos.
- **Nivel de Protocolo**: Este nivel permite configurar opciones específicas para un protocolo de red en particular, como TCP o UDP. Por ejemplo, puedes ajustar opciones relacionadas con la calidad del servicio, la forma en que se manejan los paquetes de datos, o características específicas de un protocolo.

**socket.SOL_SOCKET**

‘**socket.SOL_SOCKET**‘ es una constante en muchos lenguajes de programación que se usa con ‘setsockopt’ para indicar que las opciones que se van a ajustar son a nivel de socket. Esto significa que las opciones aplicadas en este nivel afectarán a todas las operaciones de red realizadas a través del socket, sin importar el protocolo de transporte específico (como TCP o UDP) que esté utilizando.

**socket.SO_REUSEADDR**

‘**socket.SO_REUSEADDR**‘ es otra opción comúnmente utilizada en setsockopt. Esta opción es muy útil en el desarrollo de aplicaciones de red. Lo que hace es permitir que un socket se enlace a un puerto que todavía está siendo utilizado por un socket que ya no está activo. Esto es particularmente útil en situaciones donde un servidor se reinicia y sus sockets aún están en un estado de “espera de cierre” (**TIME_WAIT**), lo que podría impedir que el servidor se vuelva a enlazar al mismo puerto.

Al establecer ‘**SO_REUSEADDR**‘, el sistema operativo permite reutilizar el puerto inmediatamente, lo que facilita la reanudación rápida de los servicios del servidor.

En resumen, ‘**setsockopt**‘ con diferentes niveles y opciones, como ‘**SOL_SOCKET**‘ y ‘**SO_REUSEADDR**‘, proporciona una flexibilidad significativa en la configuración de sockets para una comunicación de red eficiente y efectiva.

