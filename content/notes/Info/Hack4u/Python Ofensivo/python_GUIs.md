---
title: Aplicaciones de Escritorio con Python 🔋
tags:
  - Theory
  - Hack4u
---
>[!Warning]
>*This course is fully in spanish :d*

![](Pasted%20image%2020240826120138.png)

## Introducción a las interfaces gráficas de usuario (GUI)

**Tkinter** es una biblioteca estándar de Python para la creación de interfaces gráficas de usuario (GUI). Es una interfaz de programación para ‘**Tk**‘, un toolkit de GUI que es parte de Tcl/Tk. Tkinter es notable por su simplicidad y eficiencia, siendo ampliamente utilizado en aplicaciones de escritorio y herramientas educativas.

**¿Por qué Tkinter?**

- **Facilidad de Uso**: Tkinter es amigable para principiantes. Su estructura sencilla y clara lo hace ideal para aprender los conceptos básicos de la programación de GUI.
- **Portabilidad**: Las aplicaciones creadas con Tkinter pueden ejecutarse en diversos sistemas operativos sin necesidad de modificar el código.
- **Amplia Disponibilidad**: Al ser parte de la biblioteca estándar de Python, Tkinter está disponible por defecto en la mayoría de las instalaciones de Python, lo que elimina la necesidad de instalaciones adicionales.

En esta sección del curso, nos sumergiremos en el mundo de Tkinter, empezando con una introducción detallada que nos permitirá entender y utilizar sus múltiples funcionalidades. A través de proyectos prácticos, aplicaremos estos conocimientos para construir desde aplicaciones simples hasta interfaces más complejas, proporcionando una base sólida para cualquiera interesado en el desarrollo de GUI con Python.

## Desarrollo de aplicaciones GUI con Tkinter

**Tkinter: Explorando Componentes Clave**

**1. tk.Label**

- **Descripción**: ‘**tk.Label**‘ es un widget en Tkinter utilizado para mostrar texto o imágenes. El texto puede ser estático o actualizarse dinámicamente.
- **Uso Común**: Se usa para añadir etiquetas informativas en una GUI, como títulos, instrucciones o información de estado.
- **Características Clave**:
    - **text**: Para establecer el texto que se mostrará.
    - **font**: Para personalizar la tipografía.
    - **bg y fg**: Para establecer el color de fondo (bg) y de texto (fg).
    - **image**: Para mostrar una imagen.
    - **wraplength**: Para especificar a qué ancho el texto debería envolverse.

**2. mainloop()**

- **Descripción**: ‘**mainloop()**‘ es una función esencial en Tkinter que ejecuta el bucle de eventos de la aplicación. Este bucle espera eventos, como pulsaciones de teclas o clics del mouse, y los procesa.
- **Importancia**: Sin ‘**mainloop()**‘, la aplicación GUI no responderá a eventos y parecerá congelada. Es lo que mantiene viva la aplicación.

**3. pack()**

- **Descripción**: ‘**pack()**‘ es un método de geometría usado para colocar widgets en una ventana.
- **Funcionalidad**: Organiza los widgets en bloques antes de colocarlos en la ventana. Los widgets se “empaquetan” en el orden en que se llama a ‘**pack()**‘.
- **Características Clave**:
    - **side**: Para especificar el lado de la ventana donde se ubicará el widget (por ejemplo, top, bottom, left, right).
    - **fill**: Para determinar si el widget se expande para llenar el espacio disponible.
    - **expand**: Para permitir que el widget se expanda para ocupar cualquier espacio adicional en la ventana.

**4. grid()**

- **Descripción**: ‘**grid()**‘ es otro método de geometría utilizado en Tkinter para colocar widgets.
- **Funcionalidad**: Organiza los widgets en una cuadrícula. Se especifica la fila y la columna donde debe ir cada widget.
- **Características Clave**:
    - **row y column**: Para especificar la posición del widget en la cuadrícula.
    - **rowspan y columnspan**: Para permitir que un widget ocupe múltiples filas o columnas.
    - **sticky**: Para determinar cómo se alinea el widget dentro de su celda (por ejemplo, N, S, E, W).

**Conclusión**

Estos componentes de Tkinter (tk.Label, mainloop(), pack(), grid()) son fundamentales para la creación de aplicaciones GUI eficientes y atractivas. Comprender su funcionamiento y saber cómo implementarlos adecuadamente es crucial para cualquier desarrollador que busque crear interfaces de usuario interactivas y funcionales con Python y Tkinter.

```python
import tkinter as tk

def accion_de_boton():
	print("Se ha presionado el botón")
	
root = tk.Tk() # Ventana principal (raíz)
#root.title("Mi primera aplicación") # nombre de la ventana
label1 = tk.Label(root, text="¡Hola mundo!", bg="red")
label1.pack() # para representar un label, # grid(), # place()
button = tk.Button(root, text="Presióname para que se tense", command=accion_de_boton)
button.pack()
label2 = tk.Label(root, text="Label222222", bg="blue")
label3 = tk.Label(root, text="Label333333", bg="green")
label2.pack(fill=tk.X) # para que se resizee correctamente
label3.pack(side=tk.LEFT, fill=tk.Y) # resizee y pegado al lado izquierdo
root.mainloop() # permite ejecutar y manejar todos los eventos de dentro de la aplicación
```

**Tkinter: Profundizando en Componentes y Gestión de Layout**

**1. place()**

- **Descripción**: ‘**place()**‘ es un método de gestión de geometría en Tkinter que permite posicionar widgets en ubicaciones específicas mediante coordenadas x-y.
- **Características Clave**:
    - **‘x’ y ‘y’**: Especifican la posición del widget en términos de coordenadas.
    - **width y height**: Definen el tamaño del widget.
    - **anchor**: Determina desde qué punto del widget se aplican las coordenadas (por ejemplo, ‘**nw**‘ para esquina superior izquierda).
    - **Posiciones Relativas**: Se pueden utilizar valores relativos (por ejemplo, ‘**relx**‘, ‘**rely**‘) para posicionar widgets en relación con el tamaño de la ventana, lo que hace que la interfaz sea más adaptable al cambiar el tamaño de la ventana.

**2. tk.Entry()**

- **Descripción**: ‘**tk.Entry()**‘ es un widget en Tkinter que permite a los usuarios introducir una línea de texto.
- **Uso Común**: Ideal para campos de entrada de texto como nombres de usuario, contraseñas, etc.
- **Funcionalidades Clave**:
    - **get()**: Para obtener el texto del campo de entrada.
    - **delete()**: Para borrar texto del campo de entrada.
    - **insert()**: Para insertar texto en una posición específica.

**3. tk.Button()**

- **Descripción**: ‘**tk.Button()**‘ es un widget que los usuarios pueden presionar para realizar una acción.
- **Uso Común**: Ejecutar una función o comando cuando se hace clic en él.
- **Características Clave**:
    - **text**: Define el texto que aparece en el botón.
    - **command**: Establece la función que se llamará cuando se haga clic en el botón.

**4. geometry()**

- **Descripción**: ‘**geometry()**‘ es una función que define las dimensiones y la posición inicial de la ventana principal.
- **Funcionalidad**: Permite especificar el tamaño y la ubicación de la ventana en el formato ‘**ancho x alto + X + Y**‘.
- **Importancia**: Es fundamental para establecer el tamaño inicial de la ventana y su posición en la pantalla.

**5. tk.Text()**

- **Descripción**: ‘**tk.Text()**‘ es un widget que permite la entrada y visualización de múltiples líneas de texto.
- **Uso Común**: Ideal para campos de texto más extensos, como áreas de comentarios, editores de texto, etc.
- **Funcionalidades Clave**:
    - Similar a ‘**tk.Entry()**‘, pero diseñado para manejar texto de varias líneas.
    - Permite funciones como copiar, pegar, seleccionar texto.

**Conclusión**

Estos componentes y funciones (place(), tk.Entry(), tk.Button(), geometry(), tk.Text()) son esenciales en la construcción de interfaces de usuario ricas y funcionales con Tkinter. Proporcionan la flexibilidad necesaria para crear aplicaciones GUI interactivas y atractivas, adaptándose a una amplia gama de necesidades de diseño de interfaz.

**Tkinter: Explorando Widgets Avanzados y Funcionalidades de Diálogo**

**1. Frame()**

- **Descripción**: ‘**Frame()**‘ es un widget en Tkinter utilizado como contenedor para otros widgets.
- **Uso Común**: Organizar el layout de la aplicación, agrupando widgets relacionados.
- **Características Clave**:
    - Actúa como un contenedor invisible que puede contener otros widgets.
    - Útil para mejorar la organización y la gestión del layout en aplicaciones complejas.

**2. Canvas()**

- **Descripción**: ‘**Canvas()**‘ es un widget que proporciona un área para dibujar gráficos, líneas, figuras, etc.
- **Funciones de Dibujo**:
    - **create_oval()**: Crea figuras ovales o círculos. Los parámetros especifican las coordenadas del rectángulo delimitador.
    - **create_rectangle()**: Dibuja rectángulos. Los parámetros definen las coordenadas de las esquinas.
    - **create_line()**: Permite dibujar líneas. Se especifican las coordenadas de inicio y fin de la línea.
- **Uso Común**: Crear gráficos, interfaces de juegos, o elementos visuales personalizados.

**3. Menu()**

- **Descripción**: ‘**Menu()**‘ se utiliza para crear menús en una aplicación Tkinter.
- **Uso Común**: Añadir barras de menús con opciones como ‘**Archivo**‘, ‘**Editar**‘, ‘**Ayuda**‘, etc.
- **Características Clave**:
    - Se pueden crear menús desplegables y menús contextuales.
    - Los menús pueden contener comandos, opciones de selección y otros submenús.

**4. messagebox**

- **Descripción**: ‘**messagebox**‘ es un módulo en Tkinter que proporciona ventanas emergentes de diálogo.
- **Funciones Comunes**:
    - **showinfo(), showwarning(), showerror()**: Muestran mensajes informativos, de advertencia y de error, respectivamente.
- **Uso Común**: Informar al usuario sobre eventos, confirmaciones, errores o advertencias.

**5. filedialog**

- **Descripción**: ‘**filedialog**‘ es un módulo que ofrece diálogos para seleccionar archivos y directorios.
- **Funciones Clave**:
    - **askopenfilename()**: Abre un cuadro de diálogo para seleccionar un archivo para abrir.
    - **asksaveasfilename()**: Abre un cuadro de diálogo para seleccionar la ubicación y el nombre del archivo para guardar.
    - **askdirectory()**: Permite al usuario seleccionar un directorio.
- **Uso Común**: Integrar la funcionalidad de apertura y guardado de archivos en aplicaciones.

**Conclusión**

El dominio de estos widgets y módulos (Frame(), Canvas(), Menu(), messagebox, filedialog) es crucial para desarrollar aplicaciones GUI interactivas y completas en Tkinter. Cada uno aporta funcionalidades específicas que permiten crear interfaces de usuario más ricas y dinámicas, adaptadas a una amplia variedad de necesidades.

## Proyecto Bloc de Notas

> Revisar [Bloc de Notas](https://github.com/gitblanc/Hack4u/blob/main/python_ofensivo/Bloc%20de%20Notas/Editor.py)

## Proyecto Calculadora

> Revisar [Calculadora](https://github.com/gitblanc/Hack4u/blob/main/python_ofensivo/Calculadora/calculadora.py)

## Desarrollo de aplicaciones GUI avanzado con CustomTkinter

**CustomTkinter** es una extensión de la conocida biblioteca Tkinter de Python, diseñada para facilitar la creación de interfaces gráficas de usuario (GUI) con un estilo más moderno y personalizable. A continuación, te detallo sus características y diferencias con respecto a Tkinter tradicional:

**Características de CustomTkinter**

- **Estilo Moderno y Personalizable**: CustomTkinter ofrece widgets con un diseño más moderno y atractivo en comparación con los estándares de Tkinter. Estos widgets pueden personalizarse ampliamente en términos de colores, formas y efectos visuales.
- **Facilidad de Uso**: Mantiene la simplicidad y facilidad de uso de Tkinter, permitiendo a los desarrolladores crear interfaces gráficas de manera intuitiva, pero con un aspecto visual más atractivo y profesional.
- **Compatibilidad**: Es compatible con el código Tkinter existente, lo que permite a los desarrolladores mejorar las interfaces de aplicaciones existentes sin necesidad de reescribir todo desde cero.
- **Widgets Mejorados**: Incluye versiones mejoradas de los widgets estándar de Tkinter, como botones, etiquetas, campos de texto, etc., con mejoras en la interactividad y el diseño.

**Diferencias con Tkinter**

- **Diseño Visual**: La diferencia más notable es el estilo visual. CustomTkinter proporciona un aspecto más moderno y elegante, mientras que Tkinter tiene un aspecto más tradicional y básico.
- **Personalización de Widgets**: CustomTkinter permite una mayor personalización en la apariencia de los widgets, como temas oscuros, bordes redondeados, y efectos de animación, que no están disponibles directamente en Tkinter estándar.
- **Facilidad de Transición**: Aunque CustomTkinter es una extensión, los desarrolladores familiarizados con Tkinter encontrarán la transición suave, ya que muchos de los conceptos y estructuras son similares.
- **Comunidad y Soporte**: Tkinter, al ser una biblioteca más antigua y establecida, tiene una comunidad más grande y una amplia gama de recursos y documentación. CustomTkinter, siendo más nuevo, está en proceso de crecimiento en términos de comunidad y recursos disponibles.

En resumen, CustomTkinter se posiciona como una excelente opción para los desarrolladores que buscan mejorar la estética y la funcionalidad de sus interfaces gráficas en Python, manteniendo al mismo tiempo la simplicidad y la familiaridad de Tkinter.

**Comandos de encriptación:**

- **openssl genpkey -algorithm RSA -out server-key.key -aes256**

Esta instrucción genera una nueva clave privada RSA. La opción ‘**-algorithm RSA**‘ especifica el uso del algoritmo RSA. ‘**-out server-key.key**‘ indica que la clave generada se guardará en un archivo llamado ‘**server-key.key**‘. La opción ‘**-aes256**‘ significa que la clave privada será cifrada usando el algoritmo AES-256, lo que añade una capa de seguridad al requerir una contraseña para acceder a la clave.

- **openssl req -new -key server-key.key -out server.csr**

Esta línea crea una nueva Solicitud de Firma de Certificado (CSR) utilizando la clave privada RSA que generaste. ‘**-new**‘ indica que se trata de una nueva solicitud, ‘**-key server-key.key**‘ especifica que se usará la clave privada almacenada en ‘**server-key.key**‘, y ‘**-out server.csr**‘ guarda la CSR generada en un archivo llamado ‘**server.csr**‘. La CSR es necesaria para solicitar un certificado digital a una Autoridad Certificadora (CA).

- **openssl x509 -req -days 365 -in server.csr -signkey server-key.key -out server-cert.pem**

Este comando genera un certificado autofirmado basado en la CSR. ‘**-req**‘ indica que se está procesando una CSR, ‘**-days 365**‘ establece la validez del certificado por un año, ‘**-in server.csr**‘ especifica la CSR de entrada, ‘**-signkey server-key.key**‘ utiliza la misma clave privada para firmar el certificado, y ‘**-out server-cert.pem**‘ guarda el certificado generado en un archivo llamado ‘**server-cert.pem**‘.

- **openssl rsa -in server-key.key -out server-key.key**

Este comando se utiliza para quitar la contraseña de una clave privada RSA protegida. ‘**-in server-key.key**‘ especifica el archivo de la clave privada cifrada como entrada, y ‘**-out server-key.key**‘ indica que la clave privada sin cifrar se guardará en el mismo archivo. Al ejecutar este comando, se te pedirá la contraseña actual de la clave privada. Una vez proporcionada, OpenSSL generará una versión sin cifrar de la clave privada y la guardará en el mismo archivo, sobrescribiendo la versión cifrada.

Este paso se hace a menudo para simplificar la automatización en entornos donde ingresar una contraseña manualmente no es práctico. Sin embargo, es importante ser consciente de que al eliminar la contraseña, la clave privada se vuelve más vulnerable al acceso no autorizado.

```shell
openssl genpkey -algorithm RSA -out server-key.key -aes256
openssl req -new -key server-key.key -out server.csr
openssl x509 -req -days 365 -in server.csr -signkey server-key.key -out server-cert.pem
openssl rsa -in server-key.key -out server-key.key
```

## Proyecto Chat Multiusuario y Cifrado E2E

> Revisar [Chat cifrado](https://github.com/gitblanc/Hack4u/tree/main/python_ofensivo/Chat%20Multiusuario%20y%20cifrado%20E2E)

> Continúa en [Python Ofensivo 🦭](python_ofensivo.md)