---
title: Python Ofensivo 🐍
tags:
  - Theory
  - Hack4u
---
>[!Warning]
>*This course is fully in spanish :d*


## Características y ventajas de Python

Python es un lenguaje de programación de alto nivel, interpretado y de propósito general que se ha popularizado por su sintaxis legible y clara. Es un lenguaje versátil que permite a los programadores trabajar rápidamente e integrar sistemas de manera más efectiva.

**Características Principales:**

- **Sintaxis simple y fácil de aprender**: Python es famoso por su legibilidad, lo que facilita el aprendizaje para los principiantes y permite a los desarrolladores expresar conceptos complejos en menos líneas de código que serían necesarias en otros lenguajes.
- **Interpretado**: Python es procesado en tiempo de ejecución por el intérprete. Puedes ejecutar el programa tan pronto como termines de escribir los comandos, sin necesidad de compilar.
- **Tipado dinámico**: Python sigue las variables en tiempo de ejecución, lo que significa que puedes cambiar el tipo de datos de una variable en tus programas.
- **Multiplataforma**: Python se puede ejecutar en una variedad de sistemas operativos como Windows, Linux y MacOS.
- **Bibliotecas extensas**: Python cuenta con una gran biblioteca estándar que está disponible sin cargo alguno para todos los usuarios.
- **Soporte para múltiples paradigmas de programación**: Python soporta varios estilos de programación, incluyendo programación orientada a objetos, imperativa y funcional.

**Ventajas de Usar Python:**

- **Productividad mejorada**: La simplicidad de Python aumenta la productividad de los desarrolladores ya que les permite enfocarse en resolver el problema en lugar de la complejidad del lenguaje.
- **Amplia comunidad**: Una comunidad grande y activa significa que es fácil encontrar ayuda, colaboración y contribuciones de terceros.
- **Aplicabilidad en múltiples dominios**: Python se utiliza en una variedad de aplicaciones, desde desarrollo web hasta inteligencia artificial, ciencia de datos y automatización.
- **Compatibilidad y colaboración**: Python se integra fácilmente con otros lenguajes y herramientas, y es una excelente opción para equipos de desarrollo colaborativos.

Con estas características y ventajas, Python se ha establecido como un lenguaje clave en el desarrollo de software moderno. Su facilidad de uso y su amplia aplicabilidad lo hacen una elección excelente tanto para programadores principiantes como para expertos.

## Diferencias entre Python2, Python3, pip2 y pip3

Python 2 y Python 3 son dos versiones del lenguaje de programación Python, cada una con sus propias características y diferencias clave. PIP2 y PIP3 son las herramientas de gestión de paquetes correspondientes a cada versión, utilizadas para instalar y administrar bibliotecas y dependencias.

**Python 2 vs Python 3:**

- **Sintaxis de print**: En Python 2, ‘print’ es una declaración, mientras que en Python 3, ‘print()’ es una función, lo que requiere el uso de paréntesis.
- **División de enteros**: Python 2 realiza una división entera por defecto, mientras que Python 3 realiza una división real (flotante) por defecto.
- **Unicode**: Python 3 usa Unicode (texto) como tipo de dato por defecto para representar cadenas, mientras que Python 2 utiliza ASCII.
- **Librerías**: Muchas librerías populares de Python 2 han sido actualizadas o reescritas para Python 3, con mejoras y nuevas funcionalidades.
- **Soporte**: Python 2 llegó al final de su vida útil en 2020, lo que significa que ya no recibe actualizaciones, ni siquiera para correcciones de seguridad.

**PIP2 vs PIP3:**

- **Gestión de paquetes**: PIP2 y PIP3 son herramientas que permiten instalar paquetes para Python 2 y Python 3, respectivamente. Es importante usar la versión correcta para garantizar la compatibilidad con la versión de Python que estés utilizando.
- **Comandos de instalación**: El uso de pip o pip3 antes de un comando determina si el paquete se instalará en Python 2 o Python 3. Algunos sistemas operativos pueden requerir especificar pip2 o pip3 explícitamente para evitar ambigüedades.
- **Ambientes virtuales**: Es una buena práctica usar ambientes virtuales para mantener separadas las dependencias de proyectos específicos y evitar conflictos entre versiones de paquetes para Python 2 y Python 3.

La transición de Python 2 a Python 3 ha sido significativa en la comunidad de desarrolladores de Python, y es fundamental que los programadores comprendan las diferencias y sepan cómo trabajar con ambas versiones del lenguaje y sus herramientas asociadas.

## El intérprete de Python

El intérprete de Python es el corazón del lenguaje de programación Python; es el motor que ejecuta el código que escriben los programadores. Cuando hablamos del “**intérprete de Python**“, nos referimos al programa que lee y ejecuta el código Python en tiempo real.

**Funciones Clave del Intérprete de Python:**

- **Ejecución de Código**: El intérprete ejecuta el código escrito en Python línea por línea, lo que facilita la depuración y permite a los desarrolladores probar fragmentos de código de forma interactiva.
- **Modo Interactivo**: El intérprete puede usarse en un modo interactivo que permite a los usuarios ejecutar comandos de Python uno a uno y ver los resultados de inmediato, lo cual es excelente para el aprendizaje y la experimentación.
- **Modo de Script**: Además del modo interactivo, el intérprete puede ejecutar programas completos o scripts que se escriben en archivos con la extensión ‘**.py**‘.
- **Compilación a Bytecode**: Aunque Python es un lenguaje interpretado, internamente, el intérprete compila el código a bytecode antes de ejecutarlo, lo que mejora el rendimiento.
- **Máquina Virtual de Python**: El bytecode compilado se ejecuta en la Máquina Virtual de Python (Python Virtual Machine – PVM), que es una abstracción que hace que el código de Python sea portable y se pueda ejecutar en cualquier sistema operativo donde el intérprete esté disponible.

**Ventajas del Intérprete de Python:**

- **Facilidad de Uso**: La capacidad de ejecutar código inmediatamente y de manera interactiva hace de Python una herramienta excelente para principiantes y para el desarrollo rápido de aplicaciones.
- **Portabilidad**: El intérprete de Python está disponible en múltiples plataformas, lo que significa que los programas de Python pueden ejecutarse en casi cualquier sistema sin modificaciones.
- **Extensibilidad**: El intérprete de Python permite la extensión con módulos escritos en otros lenguajes como C o C++, lo que puede ser utilizado para optimizar el rendimiento.

El intérprete de Python es una herramienta poderosa y flexible que hace que el lenguaje sea accesible y eficiente para una amplia variedad de aplicaciones de programación. Comprender cómo funciona el intérprete es fundamental para cualquier programador que desee dominar Python.

## Shebang y convenios en Python

En el desarrollo con Python, el shebang y los convenios de codificación son aspectos importantes que facilitan la escritura de scripts claros y portables.

**Shebang en Python:**

El shebang es una línea que se incluye al principio de un script ejecutable para indicar al sistema operativo con qué intérprete debe ejecutarse el archivo. En los scripts de Python, el shebang común es:

- **#!/usr/bin/env python3**

Esta línea le dice al sistema que utilice el entorno (**env**) para encontrar el intérprete de Python 3 y ejecutar el script con él. Es fundamental para asegurar que el script se ejecute con Python 3 en sistemas donde Python 2 todavía está presente.

**Convenios en Python:**

Los convenios de codificación son un conjunto de recomendaciones que guían a los desarrolladores de Python para escribir código claro y consistente. El más conocido es ‘**PEP 8**‘, que abarca:

- **Nombres de Variables**: Utilizar ‘**lower_case_with_underscores**‘ para nombres de variables y funciones, ‘**UPPER_CASE_WITH_UNDERSCORES**‘ para constantes, y ‘**CamelCase**‘ para clases.
- **Longitud de Línea**: Limitar las líneas a 79 caracteres para código y 72 para comentarios y docstrings.
- **Indentación**: Usar 4 espacios por nivel de indentación.
- **Espacios en Blanco**: Seguir las prácticas recomendadas sobre el uso de espacios en blanco, como no incluir espacios adicionales en listas, funciones y argumentos de funciones.
- **Importaciones**: Las importaciones deben estar en líneas separadas y agrupadas en el siguiente orden: módulos de la biblioteca estándar, módulos de terceros y luego módulos locales.
- **Compatibilidad entre Python 2 y 3**: Aunque Python 2 ha llegado al final de su vida útil, algunos convenios pueden seguirse para mantener la compatibilidad.

El cumplimiento de estos convenios no solo mejora la legibilidad del código, sino que también facilita la colaboración entre desarrolladores y el mantenimiento a largo plazo del software.

El uso adecuado del shebang y la adhesión a los convenios de Python son señales de un desarrollador cuidadoso y profesional. Integrar estos aspectos en tus prácticas de codificación es crucial para el desarrollo de software efectivo y eficiente en Python.

> [!Tip]
> Comprueba dónde está instalado tu python con `which python3`

>[!Note]
>**¿Para qué sirve `if __name__ == '__main__'`?**
>Sirve para comprobar que el módulo que se está ejecutando es el principal, es decir, que no se está llamando desde otro script (que no esté siendo importado en otro script)

### Convenios

- **lowerCamelCase**
- **UpperCamelCase**
- **SCREAMING_SNAKE_CASE**
- **PEP 8**
- **snake_case**

>[!Tip]
>No es recomendable usar -> l (l minúscula) O (o mayúscula) I (i mayúscula), pues pueden dar lugar a confusión dependiendo de la letra

## Variables y tipos de datos

Las variables en Python son como nombres que se le asignan a los datos que manejamos. Piensa en una variable como un nombre que pones a un valor, para poder referirte a él y utilizarlo en diferentes partes de tu código.

En la clase actual, vamos a enfocarnos en comprender las variables y algunos de los tipos de datos fundamentales en Python. Estos conceptos son esenciales, ya que nos permiten almacenar y manipular la información en nuestros programas.

**Variables**

Una variable en Python es como un nombre que se le asigna a un dato. No es necesario declarar el tipo de dato, ya que Python es inteligente para inferirlo.

**Cadenas (Strings)**

Las cadenas son secuencias de caracteres que se utilizan para manejar texto. Son inmutables, lo que significa que una vez creadas, no puedes cambiar sus **caracteres individuales**.

**Números**

Python maneja varios tipos numéricos, pero nos centraremos principalmente en:

- **Enteros (Integers)**: Números sin parte decimal.
- **Flotantes (Floats)**: Números que incluyen decimales.

**Listas**

Las listas son colecciones ordenadas y mutables que pueden contener elementos de diferentes tipos. Son ideales para almacenar y acceder a secuencias de datos.

Y para trabajar con estas listas, así como con cadenas y rangos de números, utilizaremos los bucles ‘**for**‘, que nos permiten iterar sobre cada elemento de una secuencia de manera eficiente.

Estas son solo algunas de las estructuras de datos con las que trabajaremos por el momento. A medida que avancemos en las próximas clases, exploraremos más tipos de datos y estructuras más complejas, ampliando nuestras herramientas para resolver problemas y construir programas más sofisticados.

