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