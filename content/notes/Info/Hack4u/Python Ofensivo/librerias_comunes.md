---
title: Manejo de librerías comunes 🦤
tags:
  - Theory
  - Hack4u
---
>[!Warning]
>*This course is fully in spanish :d*

![](Pasted%20image%2020240826120138.png)

## Librería os y sys

Las bibliotecas ‘**os**‘ y ‘**sys**‘ de Python son herramientas esenciales para cualquier desarrollador que busque interactuar eficazmente con el sistema operativo y gestionar el entorno de ejecución de sus programas. Estas bibliotecas proporcionan una amplia gama de funcionalidades que permiten una mayor flexibilidad y control en el desarrollo de software.

**  
Biblioteca os**

La biblioteca ‘**os**‘ en Python es una herramienta poderosa para interactuar con el sistema operativo. Proporciona una interfaz portátil para usar funcionalidades dependientes del sistema operativo, lo que significa que los programas pueden funcionar en diferentes sistemas operativos sin cambios significativos en el código. Algunas de sus capacidades incluyen:

- **Manipulación de Archivos y Directorios**: Permite realizar operaciones como crear, eliminar, mover archivos y directorios, y consultar sus propiedades.
- **Ejecución de Comandos del Sistema**: Facilita la ejecución de comandos del sistema operativo desde un programa Python.
- **Gestión de Variables de Entorno**: Ofrece funciones para leer y modificar las variables de entorno del sistema.
- **Obtención de Información del Sistema**: Proporciona métodos para obtener información relevante sobre el sistema operativo, como la estructura de directorios, detalles del usuario, procesos, etc.

**Biblioteca sys**

La biblioteca ‘**sys**‘ es fundamental para interactuar con el entorno de ejecución del programa Python. A diferencia de ‘**os**‘, que se centra en el sistema operativo, ‘**sys**‘ está más orientada a la interacción con el intérprete de Python. Sus principales usos incluyen:

- **Argumentos de Línea de Comandos**: Permite acceder y manipular los argumentos que se pasan al programa Python desde la línea de comandos.
- **Gestión de la Salida del Programa**: Facilita el control sobre la salida estándar (**stdout**) y la salida de error (**stderr**), lo cual es esencial para la depuración y la presentación de resultados.
- **Información del Intérprete**: Ofrece acceso a configuraciones y funcionalidades relacionadas con el intérprete de Python, como la versión de Python en uso, la lista de módulos importados y la gestión de la ruta de búsqueda de módulos.

Ambas bibliotecas son cruciales para el desarrollo de aplicaciones Python que requieren interacción avanzada con el entorno de sistema y el intérprete. Su comprensión y uso adecuado permite a los desarrolladores escribir código más robusto, portable y eficiente.

```python
import os

directorio_actual = os.getcwd()

files = os.listdir(directorio_actual) # es una lista

os.mkdir("mi_directorio")

# Determinar si un recurso existe o no

print(f"\n[+] Existe el archivo 'mi_archivo.txt' -> {os.path.exists('mi_archivo.txt')}")

get_env = os.getenv('KITTY_INSTALLATION_DIR')
```


```python
import sys

# argv son los argumentos que el programa recibe
print(f"\n[+] Nombre del script: {sys.argv[0]}") # 0, 1, 2, 3...
print(f"\n[+] Total de argumentos que se le están pasando al programa: {len(sys.argv)}")
sys.exit(1)
```

## Librería requests

La biblioteca ‘**requests**‘ en Python es una de las herramientas más populares y poderosas para realizar solicitudes HTTP. Su diseño es intuitivo y fácil de usar, lo que la hace una opción preferida para interactuar con APIs y servicios web. 

**Introducción a requests**

‘**requests**‘ es una biblioteca de Python que simplifica enormemente el proceso de enviar solicitudes HTTP. Está diseñada para ser más fácil de usar que las opciones incorporadas en Python, como ‘**urllib**‘, proporcionando una API más amigable.

**Características Principales**

- **Simplicidad y Facilidad de Uso**: Con requests, enviar solicitudes GET, POST, PUT, DELETE, entre otras, se puede realizar en pocas líneas de código. Su sintaxis es clara y concisa.
- **Gestión de Parámetros URL**: Permite manejar parámetros de consulta y cuerpos de solicitud con facilidad, automatizando la codificación de URL.
- **Manejo de Respuestas**: ‘**requests**‘ facilita la interpretación de respuestas HTTP, proporcionando un objeto de respuesta que incluye el contenido, el estado, los encabezados, y más.
- **Soporte para Autenticaciones**: Ofrece soporte integrado para diferentes formas de autenticación, incluyendo autenticación básica, digest, y OAuth.
- **Manejo de Sesiones y Cookies**: Permite mantener sesiones y gestionar cookies, lo cual es útil para interactuar con sitios web que requieren autenticación o mantienen estado.
- **Soporte para SSL**: ‘**requests**‘ maneja SSL (Secure Sockets Layer) y TLS (Transport Layer Security), permitiendo realizar solicitudes seguras a sitios HTTPS.
- **Manejo de Excepciones y Errores**: Proporciona métodos para manejar y reportar errores de red y HTTP de manera efectiva.

**Uso Práctico**

La biblioteca se utiliza ampliamente para interactuar con APIs RESTful, automatizar interacciones con sitios web, y en tareas de scraping web. Sus capacidades para manejar solicitudes complejas y sus características de seguridad la hacen ideal para una amplia gama de aplicaciones, desde scripts simples hasta sistemas empresariales complejos.

**Conclusión**

La comprensión y el uso efectivo de ‘**requests**‘ son habilidades esenciales para cualquier desarrollador Python que trabaje con HTTP y APIs web. Esta biblioteca no solo facilita la realización de tareas relacionadas con la red, sino que también ayuda a escribir código más limpio y mantenible.

```python
import requests

response = requests.get("https://google.es")

print(f"\n[+] Status code: {response.status_code}") # para ver el código de estado
print(f"\n[+] Mostrando código fuente de la respuesta:\n")

with open("index.html", "w") as f:
	f.write(response.text)

payload = {'key1': 'value1', 'key2': 'value2', 'key3': 'value3'}
response = requests.get("https://httpbin.org/get", params=payload)
print(response.url)
print(response.text)

response = requests.post("https://httpbin.org/post", data=payload)
print(response.url)
print(response.text)
```

```python
import requests

payload = {'key1': 'value1', 'key2': 'value2', 'key3': 'value3'}
headers = {'User-Agent': 'my-app/1.0.0'}
response = requests.post("https://httpbin.org/post", data=payload, headers=headers)
print(response.url)
print(response.text)
print(response.request.headers)
```

```python
import requests

payload = {'key1': 'value1', 'key2': 'value2', 'key3': 'value3'}
headers = {'User-Agent': 'my-app/1.0.0'}
try:
	response = requests.post("https://httpbin.org/post", data=payload, headers=headers, timeout=1) # le damos a la web como margen 1 segundo para responder
	response.raise_for_status()
except requests.Timeout:
	print(f"\n[!] La petición ha excedido el límite de tiempo de espera")
except requests.HTTPError as http_err:
	print(f"\n[!] Error HTTP: {http_err}")
except requests.RequestException as err:
	print(f"\n[!] Error: {err}")

print(response.url)
print(response.text)
print(response.request.headers)
```

```python
import requests

response = requests.post("https://httpbin.org/get")

data = response.json()

if 'headers' in data and 'User-Agent' in data['headers']:
	print(data['headers']['User-Agent'])
else:
	print(f"\n[!] No existe este campo en la respuesta")
```

**Curiosidades y Aspectos Complementarios de requests**

- **Orígenes y Popularidad**: requests fue creada por Kenneth Reitz en 2011. Su diseño enfocado en la simplicidad y la legibilidad rápidamente la convirtió en una de las bibliotecas más populares en Python. Su lema es “**HTTP for Humans**“, reflejando su objetivo de hacer las solicitudes HTTP accesibles y fáciles para los desarrolladores.
- **Comunidad y Contribuciones**: requests es un proyecto de código abierto y ha recibido contribuciones de numerosos desarrolladores. Esto asegura su constante actualización y adaptación a las nuevas necesidades y estándares de la web.
- **Inspiración en Otros Lenguajes**: El diseño de requests se inspira en otras bibliotecas HTTP de alto nivel de otros lenguajes de programación, buscando combinar lo mejor de cada uno para crear una experiencia de usuario óptima en Python.
- **Extensibilidad**: Aunque requests es poderosa por sí sola, su funcionalidad se puede ampliar con varios complementos. Esto incluye adaptadores para diferentes tipos de autenticación, soporte para servicios como AWS, o herramientas para aumentar su rendimiento.
- **Uso en la Educación y la Industria**: Debido a su simplicidad y potencia, requests se ha convertido en una herramienta de enseñanza estándar para la programación de red en Python. Además, es ampliamente utilizada en la industria para desarrollar aplicaciones que requieren comunicación con servicios web.
- **Casos de Uso Diversos**: Desde la automatización de tareas y el scraping web hasta el testing y la integración con APIs, requests tiene un rango de aplicaciones muy amplio. Su versatilidad la hace adecuada tanto para proyectos pequeños como para aplicaciones empresariales a gran escala.
- **Soporte para Proxies y Timeouts**: requests ofrece un control detallado sobre aspectos como proxies y timeouts, lo cual es crucial en entornos de producción donde la gestión del tráfico de red y la eficiencia son importantes.
- **Manejo Eficiente de Excepciones**: Proporciona una forma clara y consistente de manejar errores de red y HTTP, lo que ayuda a los desarrolladores a escribir aplicaciones más robustas y confiables.

En resumen, requests no solo es una biblioteca de alto nivel para solicitudes HTTP en Python, sino que también es un ejemplo brillante de diseño de software y colaboración comunitaria. Su facilidad de uso, junto con su potente funcionalidad, la convierte en una herramienta indispensable para cualquier desarrollador que trabaje con Python en el ámbito de la web.

- Autenticación:

```python
import requests
from requests.auth import HTTPBasicAuth

# Hay dos formas
#response = requests.get('https://httpbin/basic-auth/foo/bar', auth=HTTPBasicAuth('foo', 'foo'))
response = requests.get('https://httpbin/basic-auth/foo/bar', auth=('foo', 'foo')) # más cómoda esta
print(response.status_code)
```

- Cookies:

```python
import requests

cookies = dict(cookies_are='working')

response = requests.get('https://httpbin/basic-auth/cookies', cookies=cookies)

print(response)
```

- Enviar archivos:

```python
import requests

my_file = {'archivo': open('example.txt', 'r')}

response = requests.post('https://httpbin/basic-auth/post', files=my_file)

print(response)
```

- Conservar la sesión:

```python
import requests

url = 'https://httpbin.org/cookies'
set_cookies_url = 'https://httpbin.org/cookies/set/my_cookie/123123'

s = requests.Session()

response = s.get(set_cookies_url)
response = s.get(url)

print(response.text)
```

- Alterar consultas sobre la marcha:

```python
from requests import Request, Session

url = 'https://httpbin.org/get'

s = Session()

headers = {'Custom-Header': 'my_custom_header'}

req = Request('GET', url, headers=headers)

prepped = req.prepare()
prepped.headers['Custom-Header'] = 'my_header_changed'
prepped.headers['Custom-Header2'] = 'another_header'# añadir nueva cabecera
s.send()

print(response.text)
```

- Tener histórico de redirecciones (como un nslookup):

```python
import requests

url = 'http.github.com'
r = requests.get(url)
# r = requests.get(url, allor_redirects=False) # para que no se hagan redireccionamientos
print(r.url) # [OUTPUT] https://github.com, te hace la redirección automática
print(r.history) # podría iterarse con un for para ver propiedades
```

- Arrastrar la sesión usando `with`:

```python
import requests

with requests.Session() as session:
	response1 = session.get('https://httpbin.org/get')
	print(response1.text)
```

## Librería Urllib3

‘**urllib3**‘ es una biblioteca de Python ampliamente utilizada para realizar solicitudes HTTP y HTTPS. Es conocida por su robustez y sus numerosas características, que la hacen una herramienta versátil para una variedad de aplicaciones de red. A continuación, se presenta una descripción detallada de ‘**urllib3**‘ y sus capacidades.

**Descripción Detallada de la Biblioteca urllib3**

**Funcionalidades Clave**

- **Gestión de Pool de Conexiones**: Una de las características más destacadas de ‘**urllib3**‘ es su manejo de pools de conexiones, lo que permite reutilizar y mantener conexiones abiertas. Esto es eficiente en términos de rendimiento, especialmente cuando se hacen múltiples solicitudes al mismo host.
- **Soporte para Solicitudes HTTP y HTTPS**: ‘**urllib3**‘ ofrece un soporte sólido para realizar solicitudes tanto HTTP como HTTPS, brindando la flexibilidad necesaria para trabajar con una variedad de servicios web.
- **Reintentos Automáticos y Redirecciones**: Viene con un sistema incorporado para manejar reintentos automáticos y redirecciones, lo cual es esencial para mantener la robustez de las aplicaciones en entornos de red inestables.
- **Manejo de Diferentes Tipos de Autenticación**: Proporciona soporte para varios esquemas de autenticación, incluyendo la autenticación básica y digest, lo que la hace apta para interactuar con una amplia gama de APIs y servicios web.
- **Soporte para Características Avanzadas del HTTP**: Incluye soporte para características como la compresión de contenido, el streaming de solicitudes y respuestas, y la manipulación de cookies, ofreciendo así un control detallado sobre las operaciones de red.
- **Gestión de SSL/TLS**: ‘**urllib3**‘ tiene capacidades avanzadas para manejar la seguridad SSL/TLS, incluyendo la posibilidad de trabajar con certificados personalizados y la verificación de la conexión segura.
- **Tratamiento de Excepciones y Errores**: La biblioteca maneja de manera eficiente las excepciones y errores, permitiendo a los desarrolladores gestionar situaciones como tiempos de espera, conexiones fallidas y errores de protocolo.

**Aplicaciones y Uso**

‘**urllib3**‘ se utiliza en una variedad de contextos, desde scraping web y automatización de tareas, hasta la construcción de clientes para interactuar con APIs complejas. Su capacidad para manejar conexiones de manera eficiente y segura la hace adecuada para aplicaciones que requieren un alto grado de interacción de red, así como para escenarios donde el rendimiento y la fiabilidad son cruciales.

**Importancia en el Ecosistema de Python**

Si bien existen otras bibliotecas como ‘**requests**‘ que son más amigables para principiantes, ‘**urllib3**‘ se destaca por su control detallado y su rendimiento en situaciones que requieren un manejo más profundo de las conexiones de red. Es una biblioteca fundamental para desarrolladores que buscan un control más granular sobre sus operaciones HTTP/HTTPS en Python.

```python
import urllib3
import json

http = urllib3.PoolManager() # controlador de conexiones

response = http.request('GET', 'https://httpbin.org/get')
print(response.data.decode()) # la librería no interpreta saltos de línea y demás, por eso el decode()

data = 'Esto es una prueba'
encoded_data = data.encode()
response = http.request('POST', 'https://httpbin.org/post', body=encoded_data) # el body es para que el servidor no lo interprete como un formulario (en bruto)
print(response.data.decode())

# con JSON
data = {'atributo': 'valor'}
encoded_data = json.dumps(data).encode()
response = http.request('POST', 'https://httpbin.org/post', body=encoded_data) # el body es para que el servidor no lo interprete como un formulario (en bruto)
print(response.data.decode())

response = http.request('POST', 'https://httpbin.org/post', fields=encoded_data) # el fields es para que el servidor lo interprete como un formulario
print(response.data.decode())
```

- Redirecciones:

```python
import urllib3

http = urllib3.PoolManager()

response = http.request(
		'GET',
		'https://httpbin.org/redirect/1',
		redirect=False
)

print(response.status)
print(response.get_redirect_location())
```

- Deshabilitar warnings ssl:

```python
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
http = urllib3.PoolManager(cert_reqs='CERT_NONE')
```

## Librería threading y multiprocessing

Las bibliotecas ‘**threading**‘ y ‘**multiprocessing**‘ en Python son herramientas esenciales para la programación concurrente y paralela. Proporcionan mecanismos para ejecutar múltiples tareas simultáneamente, aprovechando mejor los recursos del sistema. A continuación, se presenta una descripción detallada de ambas bibliotecas y sus diferencias.

**Descripción Detallada de threading y multiprocessing**

**Biblioteca threading**

‘**threading**‘ es una biblioteca para la programación concurrente que permite a los programas ejecutar múltiples ‘**hilos**‘ de ejecución al mismo tiempo. Los hilos son entidades más ligeras que los procesos, comparten el mismo espacio de memoria y son ideales para tareas que requieren poco procesamiento o que están limitadas por E/S.

- **Uso Principal**: Ideal para tareas que no son intensivas en CPU o que esperan recursos (como E/S de red o de archivos).
- **Ventajas**: Bajo costo de creación y cambio de contexto, compartición eficiente de memoria y recursos entre hilos.
- **Desventajas**: Limitada por el Global Interpreter Lock (GIL) en CPython, que previene la ejecución de múltiples hilos de Python al mismo tiempo en un solo proceso.

**Biblioteca multiprocessing**

‘**multiprocessing**‘, por otro lado, se enfoca en la creación de procesos. Cada proceso en multiprocessing tiene su propio espacio de memoria. Esto significa que pueden ejecutarse en paralelo real en sistemas con múltiples núcleos de CPU, superando la limitación del GIL.

- **Uso Principal**: Ideal para tareas intensivas en CPU que requieren paralelismo real.
- **Ventajas**: Capacidad para realizar cálculos intensivos en paralelo, aprovechando múltiples núcleos de CPU.
- **Desventajas**: Mayor costo en recursos y complejidad en la comunicación entre procesos debido a espacios de memoria separados.

**Diferencias Clave**

- **Modelo de Ejecución**: ‘**threading**‘ ejecuta hilos en un solo proceso compartiendo el mismo espacio de memoria, mientras ‘**multiprocessing**‘ ejecuta múltiples procesos con memoria independiente.
- **Uso de CPU**: ‘**multiprocessing**‘ es más adecuado para tareas que requieren mucho cálculo y pueden beneficiarse de múltiples núcleos de CPU, mientras que ‘**threading**‘ es mejor para tareas limitadas por E/S.
- **Global Interpreter Lock (GIL)**: ‘**threading**‘ está limitado por el GIL en CPython, lo que restringe la ejecución en paralelo de hilos, mientras que ‘**multiprocessing**‘ no tiene esta limitación.
- **Gestión de Recursos**: ‘**threading**‘ es más eficiente en términos de memoria y creación de hilos, pero ‘**multiprocessing**‘ es más eficaz para tareas aisladas y seguras en cuanto a datos.

**Conclusión**

Entender y utilizar adecuadamente ‘**threading**‘ y ‘**multiprocessing**‘ es crucial para optimizar aplicaciones Python, especialmente en términos de rendimiento y eficiencia. La elección entre ambas depende de las necesidades específicas de la tarea, como el tipo de carga de trabajo (CPU-intensiva vs E/S-intensiva) y los requisitos de arquitectura de la aplicación.

```python
# Ejemplo secuencial
import threading
import time

def tarea(num_tarea):
	print(f"\n[+] Tarea {num_tarea} iniciando")
	time.sleep(2)
	print(f"\n[+] Tarea {num_tarea} finalizando")

tarea(1)
tarea(2)
```

```python
# Ejemplo paralelo
import threading
import time

def tarea(num_tarea):
	print(f"\n[+] Tarea {num_tarea} iniciando")
	time.sleep(2)
	print(f"\n[+] Tarea {num_tarea} finalizando")

thread1 = threading.Thread(target=tarea, args=(1,)) # cuando una tupla tiene 1 solo elemento, se pone una coma después (x,)
thread2 = threading.Thread(target=tarea, args=(2,))

thread1.start()
thread2.start()

thread1.join()
thread2.join()
```

```python
import multiprocessing
import time

def tarea(num_tarea):
	print(f"\n[+] Tarea {num_tarea} iniciando")
	time.sleep(2)
	print(f"\n[+] Tarea {num_tarea} finalizando")

proceso1 = multiprocessing.Process(target=tarea, args=(1,))
proceso2 = multiprocessing.Process(target=tarea, args=(2,))

proceso1.start()
proceso2.start()

proceso1.join()
proceso2.join()

print(f"\n[+] Los procesos han finalizado exitosamente")
```

```python
import threading
import time
import requests

def realizar_peticion(url):
	response = requests.get(url)
	print(f"\n[+] URL [{url}]: {len(response.content)} bytes")

dominios = ['https://wikipedia.org', 'https://google.es', 'https://yahoo.com']

start_time = time.time()

hilos = [] # lista de hilos
for url in dominios:
	hilo = threading.Thread(target=realizar_peticion, args(url,))
	hilo.start()
	hilos.append(hilo)

for hilo in hilos:
	hilo.join()

end_time = time.time()

print(f"\n[+] Tiempo total transcurrido: {end_time - start_time}")
```

```python
import multiprocessing
import time
import requests

def realizar_peticion(url):
	response = requests.get(url)
	print(f"\n[+] URL [{url}]: {len(response.content)} bytes")

dominios = ['https://wikipedia.org', 'https://google.es', 'https://yahoo.com']

start_time = time.time()

procesos = [] # lista de procesos
for url in dominios:
	proceso = multiprocessing.Process(target=realizar_peticion, args(url,))
	proceso.start()
	procesos.append(proceso)

for proceso in procesos:
	proceso.join()

end_time = time.time()

print(f"\n[+] Tiempo total transcurrido: {end_time - start_time}")
```

> Continúa en [Aplicaciones de Escritorio con Python 🔋](python_GUIs.md)

