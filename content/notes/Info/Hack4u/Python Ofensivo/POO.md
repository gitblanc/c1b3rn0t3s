---
title: POO 🍌
tags:
  - Theory
  - Hack4u
---
>[!Warning]
>*This course is fully in spanish :d*

![](Pasted%20image%2020240826120138.png)

## Clases y objetos

La Programación Orientada a Objetos (POO) es un paradigma de programación que utiliza objetos y clases en su enfoque central. Es una manera de estructurar y organizar el código que refleja cómo los desarrolladores piensan sobre el mundo real y las entidades dentro de él.

**Clases**

Las clases son los fundamentos de la POO. Actúan como plantillas para la creación de objetos y definen atributos y comportamientos que los objetos creados a partir de ellas tendrán. En Python, una clase se define con la palabra clave `class` y proporciona la estructura inicial para todo objeto que se derive de ella.

**Instancias de Clase y Objetos**

Un objeto es una instancia de una clase. Cada vez que se crea un objeto, se está creando una instancia que tiene su propio espacio de memoria y conjunto de valores para los atributos definidos por su clase. Los objetos encapsulan datos y funciones juntos en una entidad discreta.

**Métodos de Clase**

Los métodos de clase son funciones que se definen dentro de una clase y solo pueden ser llamados por las instancias de esa clase. Estos métodos son el mecanismo principal para interactuar con los objetos, permitiéndoles realizar operaciones o acciones, modificar su estado o incluso interactuar con otros objetos.

En esta clase, te proporcionaremos las herramientas y el entendimiento necesario para comenzar a diseñar y desarrollar tus propias clases y a crear instancias de esas clases en objetos funcionales. Aprenderemos cómo los métodos de clase operan y cómo puedes utilizarlos para dar vida al comportamiento de tus objetos en Python. Este conocimiento será esencial a medida que continúes aprendiendo y aplicando los principios de la POO en proyectos más complejos.

```python
class Persona:
	def __init__(self, nombre, edad): # constructor
		self.nombre = nombre
		self.edad = edad

	def saludo(self): # el self hace referencia al objeo que se le está pasando
		return f"Hola, soy {self.nombre} y tengo {self.edad} años"

marcelo = Persona("Pepito", 28)
print(marcelo.saludo())
```

```python
class CuentaBancaria:
	def __init__(self, cuenta, nombre, dinero=0): # valor por defecto = 0
		self.cuenta = cuenta
		self.nombre = nombre
		self.dinero = dinero
		
	def depositar_dinero(self, ingreso):
		self.dinero += ingreso
		return f"[+] Se ha depositado un total de {ingreso} €. El balance actual es de {self.dinero} €"

manolo = CuentaBancaria("13246", "Manolo Pepito", 10000)
print(manolo.depositar_dinero(400))
```

Dentro del paradigma de la Programación Orientada a Objetos en Python, existen conceptos avanzados como los decoradores, métodos de clase y métodos estáticos que enriquecen y expanden las posibilidades de cómo interactuamos con las clases y sus instancias.

**Decoradores**

Los decoradores son una herramienta poderosa en Python que permite modificar el comportamiento de una función o método. Funcionan como “envoltorios”, que agregan funcionalidad antes y después del método o función decorada, sin cambiar su código fuente. En POO, los decoradores son frecuentemente utilizados para agregar funcionalidades de manera dinámica a los métodos, como la sincronización de hilos, la memorización de resultados o la verificación de permisos.

**Métodos de Clase**

Un método de clase es un método que está ligado a la clase y no a una instancia de la clase. Esto significa que el método puede ser llamado sobre la clase misma, en lugar de sobre un objeto de la clase. Se definen utilizando el decorador **@classmethod** y su primer argumento es siempre una referencia a la clase, convencionalmente llamada **cls**. Los métodos de clase son utilizados a menudo para definir métodos “factory” que pueden crear instancias de la clase de diferentes maneras.

**Métodos Estáticos**

Los métodos estáticos, definidos con el decorador **@staticmethod**, no reciben una referencia implícita ni a la instancia (self) ni a la clase (cls). Son básicamente como funciones regulares, pero pertenecen al espacio de nombres de la clase. Son útiles cuando queremos realizar alguna funcionalidad que está relacionada con la clase, pero que no requiere acceder a la instancia o a los atributos de la clase.

Estos elementos de la POO en Python nos permiten crear abstracciones más claras y mantener el código organizado, modular y flexible, facilitando el mantenimiento y la extensibilidad del software.

```python
class Rectangulo:
	def __init__(self, ancho, alto):
		self.ancho = ancho
		self.alto = alto

	@property  # decorador que indica que es una propiedad del objeto
	def area(self):
		return self.ancho * self.alto

	def __str__(self):
		return f"\n[+] Propiedades del rectángulo: [Ancho: {self.ancho}][Alto: {self.alto}]"

	def __eq__(self, otro):
		return self.ancho == otro.ancho and self.alto == otro.alto

rect1 = Rectangulo(20, 80)
print(rect1)
print(f"\n[+] El área es {rect1.area}")
print(f"\n[+] ¿Son iguales? -> {rect1 == rect2}")
```

```python
class Libro:
	bestseller_value = 5000
	IVA = 0.21

	def __init__(self, titulo, autor, precio)
		self.titulo = titulo
		self.autor = autor
		self.precio = precio

	@staticmethod # decorador para crear un método estático
	def es_bestseller(total_ventas):
		return total_ventas > Libro.bestseller_value

	@classmethod # decorador para recibir la propia clase
	def precio_con_iva(cls, precio):
		return precio + precio * cls.IVA # esto tiene utilidad para las herencias

mi_libro = Libro("¿Cómo ser un lammer?", "Marcelo Vázquez", 17.5)
print(Libro.es_bestseller(7000))
print(f"\n[+] El precio del libro con IVA incluido es de {round(Libro.precio_con_iva(mi_libro.precio), 2)} €")
```

## Métodos estáticos y métodos de clase

Los métodos estáticos y los métodos de clase son dos herramientas poderosas en la programación orientada a objetos en Python, que ofrecen flexibilidad en cómo se puede acceder y utilizar la funcionalidad asociada con una clase.

**Métodos de Clase**

Se definen con el decorador **@classmethod**, lo que les permite tomar la clase como primer argumento, generalmente nombrada **cls**. Este acceso a la clase permite que los métodos de clase interactúen con la estructura de la clase en sí, como modificar atributos de clase que afectarán a todas las instancias. Se utilizan para tareas que requieren conocimiento del estado global de la clase, como la construcción de instancias de maneras específicas, también conocidos como métodos factory.

**Métodos Estáticos**

Se definen con el decorador **@staticmethod** y no reciben un argumento implícito de referencia a la clase o instancia. Son similares a las funciones regulares definidas dentro del cuerpo de una clase. Se utilizan para funciones que, aunque conceptualmente pertenecen a la clase debido a la relevancia temática, no necesitan acceder a ningún dato específico de la clase o instancia. Proporcionan una manera de encapsular la funcionalidad dentro de una clase, manteniendo la cohesión y la organización del código.

Ambos métodos contribuyen a un diseño de software más limpio y modular, permitiendo una clara separación entre la funcionalidad que opera con respecto a la clase en su totalidad y la funcionalidad que es independiente de las instancias de clase y de la clase misma. La elección entre utilizar un método de clase o un método estático a menudo depende del requisito específico de acceso o no a la clase o a sus instancias.

```python
class Calculadora:
	@staticmethod
	def suma(num1, num2)
		return num1 + num2

	@staticmethod
	def resta(num1, num2)
		return num1 - num2

print(Calculadora.suma(2,8))
print(Calculadora.resta(8,4))
```

```python
class Automovil:
	def __init__(self, marca, modelo):
		self.marca = marca
		self.modelo = modelo

	@classmethod
	def deportivos(cls, marca):
		return cls(marca, "Deportivo")

	@classmethod
	def sedan(cls, marca):
		return cls(marca, "Sedán")

	def __str__(self):
		return f"La marca {self.marca} es un modelo {self.modelo}"

deportivo = print(Automovil.deportivos("Ferrari"))
sedan = print(Automovil.sedan("Toyota"))
```

## Comprendiendo mejor el uso de self

El uso de self es uno de los aspectos más fundamentales y a la vez confusos para quienes se adentran en la Programación Orientada a Objetos (POO) en Python. Este identificador es crucial para entender cómo Python maneja los métodos y atributos dentro de sus clases y objetos.

**Definición de self**

A nivel conceptual, **self** es una referencia al objeto actual dentro de la clase. Es el primer parámetro que se pasa a cualquier método de una clase en Python. A través de self, un método puede acceder y manipular los atributos del objeto y llamar a otros métodos dentro del mismo objeto.

**Uso de self**

Cuando se crea una nueva instancia de una clase, Python pasa automáticamente la instancia recién creada como el primer argumento al método **__init__** y a otros métodos definidos en la clase que tienen self como su primer parámetro. Esto es lo que permite que un método opere con datos específicos del objeto y no con datos de la clase en general o de otras instancias de la clase.

**Importancia de self**

El concepto de self es importante en la POO ya que asegura que los métodos y atributos se apliquen al objeto correcto. Sin self, no podríamos diferenciar entre las operaciones y datos de diferentes instancias de una clase.

En esta clase, nos enfocaremos en comprender a fondo cómo y por qué self es usado en Python, explorando su papel en la interacción con las instancias de la clase. Desarrollaremos una comprensión clara de cómo self permite que las clases en Python sean intuitivas y eficientes, manteniendo un estado consistente a través de las operaciones del objeto. Este conocimiento es esencial para trabajar con clases y objetos de manera efectiva y aprovechar la potencia de la POO.

## Herencia y polimorfismo

La herencia y el polimorfismo son conceptos fundamentales en la programación orientada a objetos que permiten la creación de una estructura de clases flexible y reutilizable.

**Herencia**

Es un principio de la POO que permite a una clase heredar atributos y métodos de otra clase, conocida como su clase base o superclase. La herencia facilita la reutilización de código y la creación de una jerarquía de clases. Las subclases heredan las características de la superclase, lo que permite que se especialicen o modifiquen comportamientos existentes.

```python
class Animal:
	def __init__(self,nombre):
		self.nombre = nombre

	def hablar(self):
		#return f"{self.nombre} dice ¡Miau!"
		#pass # [opcional] para habilitar la herencia, se define el método en la clase padre
		raise NotImplementedError("Las subclases definidas deben implementar este método") # lanza un error si el método no está definido en la clase que hereda

class Gato(Animal): # Gato hereda de Animal
	def hablar(self):
		return f"{self.nombre} dice ¡Miau!"

class Perro(Animal):
	def hablar(self):
		return f"{self.nombre} dice ¡Guau!"
	

gato = Gato("Firulais")
perro = Perro("Cachopo")

print(gato.hablar())
print(perro.hablar())
```

**Polimorfismo**

Este concepto se refiere a la habilidad de objetos de diferentes clases de ser tratados como instancias de una clase común. El polimorfismo permite que una función o método interactúe con objetos de diferentes clases y los trate como si fueran del mismo tipo, siempre y cuando compartan la misma interfaz o método. Esto significa que el mismo método puede comportarse de manera diferente en distintas clases, un concepto conocido como sobrecarga de métodos.

Ambos, la herencia y el polimorfismo, son piedras angulares de la POO y son ampliamente utilizados para diseñar sistemas que son fácilmente extensibles y mantenibles.

En esta clase, exploraremos cómo implementar herencia en Python y cómo se puede aprovechar el polimorfismo para escribir código más general y potente. Estos conceptos nos ayudarán a entender mejor cómo construir jerarquías de clases y cómo los diferentes objetos pueden interactuar entre sí de manera flexible.

```python
class Animal:
	def __init__(self,nombre):
		self.nombre = nombre

	def hablar(self):
		#return f"{self.nombre} dice ¡Miau!"
		#pass # [opcional] para habilitar la herencia, se define el método en la clase padre
		raise NotImplementedError("Las subclases definidas deben implementar este método") # lanza un error si el método no está definido en la clase que hereda

class Gato(Animal): # Gato hereda de Animal
	def hablar(self):
		return f"{self.nombre} dice ¡Miau!"

class Perro(Animal):
	def hablar(self):
		return f"{self.nombre} dice ¡Guau!"
	
def hacer_hablar(objeto):
	print(objeto.hablar())

gato = Gato("Firulais")
perro = Perro("Cachopo")

hacer_hablar(gato)
hacer_hablar(perro)
```

```python
super().__init__() # para llamar al método de la clase padre desde la clase que hereda
```

## Encapsulamiento y métodos especiales

El encapsulamiento en la programación orientada a objetos (POO) maneja principalmente tres niveles de visibilidad para los atributos y métodos de una clase: públicos, protegidos y privados. En Python, esta distinción se realiza mediante convenciones en la nomenclatura, más que a través de estrictas restricciones de acceso como en otros lenguajes.

**Atributos Públicos**

Son accesibles desde cualquier parte del programa y, por convención, no tienen un prefijo especial. Se espera que estos atributos sean parte de la interfaz permanente de la clase.

**Atributos Protegidos**

Se indica con un único guion bajo al principio del nombre (por ejemplo, `_atributo`). Esto es solo una convención y no impide el acceso desde fuera de la clase, pero se entiende que estos atributos están protegidos y no deberían ser accesibles directamente, excepto dentro de la propia clase y en subclases.

**Atributos Privados**

En Python, los atributos privados se indican con un doble guion bajo al principio del nombre (por ejemplo, `__atributo`). Esto activa un mecanismo de cambio de nombre conocido como **name mangling**, donde el intérprete de Python altera internamente el nombre del atributo para hacer más difícil su acceso desde fuera de la clase.

**Métodos Especiales**

Los métodos especiales en Python son también conocidos como métodos mágicos y son identificados por doble guion bajo al inicio y al final (`__metodo__`). Permiten a las clases en Python emular el comportamiento de los tipos incorporados y responder a operadores específicos. Por ejemplo, el método `__init__` se utiliza para inicializar una nueva instancia de una clase, `__str__` se invoca para una representación en forma de cadena legible del objeto y `__len__` devuelve la longitud del objeto.

Algunos métodos especiales importantes en POO son:

- `__init__(self, […])`: Inicializa una nueva instancia de la clase.
- **__str__(self)**: Devuelve una representación en cadena de texto del objeto, invocado por la función **str(object)** y **print**.
- **__repr__(self)**: Devuelve una representación del objeto que debería, en teoría, ser una expresión válida de Python, invocado por la función **repr(object)**.
- **__eq__(self, other)**: Define el comportamiento del operador de igualdad `==`.
- **__lt__(self, other), __le__(self, other), __gt__(self, other), __ge__(self, other)**: Definen el comportamiento de los operadores de comparación (**<**, **<=**, **>** y **>=** respectivamente).
- **__add__(self, other), __sub__(self, other), __mul__(self, other), etc.**: Definen el comportamiento de los operadores aritméticos (**+**, **–**, *****, etc.).

El encapsulamiento y los métodos especiales son herramientas poderosas que, cuando se utilizan correctamente, pueden mejorar la seguridad, la flexibilidad y la claridad en la construcción de aplicaciones. A lo largo de esta clase, exploraremos en detalle cómo implementar y utilizar estos conceptos y métodos para crear clases robustas y mantenibles en Python.

```python
self._dinero # atributo protegido
self.__dinero # atributo privado
```

```python
class Ejemplo:
	def __init__(self):
		self._atributo_protegido = "Soy un atributo protegido y no deberías poder verme"
		self.__atributo_privado = "Soy un atributo privado y no deberías poder verme"

ejemplo = Ejemplo()
print(ejemplo._atributo_protegido) # se ve en consola
print(ejemplo.__atributo_privado) # no se ve en consola, por el name mangling
print(ejemplo._Ejemplo__atributo_privado) # ahora sí se vería en consola
```

```python
class Caja:
	# creamos una tupla para que independientemente del número de elementos que estamos representando se almacene en items
	def __init__(self, *items): # el * permite contemplar múltiples elementos
		self.items = items

	def mostrar_items(self):
		for item in self.items:
			print(item)

	# Métodos especiales
	
	def __len__(self):
		return len(self.items)

	def __getitem__(self, index):
		return self.items[index]

caja = Caja("Manzana", "Plátano", "Kiwi", "Pera", "Melocotón")
caja.mostrar_items()
# Hay que definir los métodos especiales para que funcione lo siguiente
print(len(caja))
print(caja[2])
```

```python
# Iterable
class Contador:
	def __init__(self, limite):
		self.limite  = limite

	# Método para convertir un objeto que es iterable. Es imperativo implementar también __next__() Devuelve un iterador
	def __iter__(self):
		self.contador = 0
		return self

	def __next__(self):
		if self.contador < self.limite:
			self.contador +=1
			return self.contador
		else:
			raise StopIteration # para la iteración

c = Contador(5)

for i in c:
	print(i)
```

## Decoradores y propiedades

En esta clase, profundizaremos en estas poderosas características de Python que mejoran significativamente la forma en que podemos manejar y modificar el comportamiento de nuestras clases y funciones.

**Decoradores**

Los decoradores en Python son una forma elegante de modificar las funciones o métodos. Se utilizan para extender o alterar el comportamiento de la función sin cambiar su código fuente. Un decorador es en sí mismo una función que toma otra función como argumento y devuelve una nueva función que, opcionalmente, puede agregar alguna funcionalidad antes y después de la función original.

**Propiedades**

Las propiedades son un caso especial de decoradores que permiten a los desarrolladores añadir “**getter**“, “**setter**” y “**deleter**” a los atributos de una clase de manera elegante, controlando así el acceso y la modificación de los datos. En Python, esto se logra con el decorador ‘**@property**‘, que transforma un método para acceder a un atributo como si fuera un atributo público.

**Getters y Setters**

- El “**getter**” obtiene el valor de un atributo manteniendo el encapsulamiento y permitiendo que se ejecute una lógica adicional durante el acceso.
- El “**setter**” establece el valor de un atributo y puede incluir validación o procesamiento antes de que el cambio se refleje en el estado interno del objeto.
- El “**deleter**” puede ser utilizado para definir un comportamiento cuando un atributo es eliminado con del.

Durante la clase, discutiremos cómo los decoradores pueden ser aplicados no solo para métodos y propiedades, sino también para funciones en general. También exploraremos cómo las propiedades se pueden utilizar para crear una interfaz pública para atributos privados/ protegidos, mejorando la encapsulación y manteniendo la integridad de los datos de una clase.

Este conocimiento es crucial para escribir código Python idiomático y eficiente, aprovechando al máximo lo que el lenguaje tiene para ofrecer en términos de flexibilidad y potencia en el diseño de software.

```python
def mi_decorador(funcion): # Función de orden superior
	def envoltura():
		print("Estoy saludando en la envoltura del decorador antes de llamar a la función")
		funcion()
		print("Estoy saludando en la envoltura del decorador después de llamar a la función")
	return envoltura

@mi_decorador
def saludo():
	print("Hola, estoy saludando dentro de mi función saludo")

saludo()
```

```python
class Persona:
	def __init__(self, nombre, edad):
		self._nombre = nombre
		self._edad = edad

	@property 
	def edad(self): # Getter
		return self._edad

	@edad.setter # Setter
	def edad(self, nueva_edad):
		if nueva_edad > 0:
			self._edad = nueva_edad
		else:
			raise ValueError("[! la edad no puede ser 0 o negativa")

manolo = Persona("Manolo", 23)
manolo.edad = 14 # Setter
print(manolo.edad) # Getter
```

```python
def presentacion(**kwargs): # pares clave valor
	#print(kwargs) # es un diccionario
	for clave, valor in kwargs.items():
		print(f"{clave}: {valor}")

presentacion(nombre="Marcelo", edad = 28, ciudad = "Santa Cruz de Tenerife", profesion = "Lammer")
```

>[!Note]
> `*args` es para argumentos posicionales
> `**kwargs` es para argumentos pares clave-valor

```python
class Circunferencia:
	def __init__(self, radio):
		self._radio = radio

	@property
	def radio(self): # Getter
		return self._radio

	@property
	def diametro(self): # Getter
		return self._radio * 2

	@property
	def area(self): # Getter
		return 3.1415 * (self._radio ** 2)

	@radio.setter
	def radio(self, valor): # Setter
		if valor > 0:
			self._radio = valor

c = Circunferencia(5)
print(c.radio)
print(c.diametro)
print(round(c.area, 2))

c.radio = 10

print(c.radio)
print(c.diametro)
print(round(c.area, 2))
```

> *Continúa con [Módulos y paquetes en Python 🐡](modulos_y_paquetes.md)*