---
title: Replacement
tags:
  - CTF
  - HackTheBox
  - Coding
---
![](Pasted%20image%2020241025161452.png)

```python
# Función para reemplazar solo las letras `t` minúsculas
def replace_specific_letter(text, target_letter, replacement_letter):
    # Verifica si la letra de destino está en minúsculas y solo reemplaza esas instancias
    if target_letter.islower():
        modified_text = ''.join([replacement_letter if char == target_letter else char for char in text])
    else:
        # Si no, simplemente reemplaza todas las apariciones de la letra exacta dada
        modified_text = text.replace(target_letter, replacement_letter)
    return modified_text

# Entradas de usuario
text = str(input())

target_letter = str(input())
replacement_letter = str(input())

# Llamada a la función
modified_text = replace_specific_letter(text, target_letter, replacement_letter)

print(modified_text)
```