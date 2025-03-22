---
title: The Summoner's Incantation
tags:
  - CTF
  - HackTheBox
  - CyberApocalypse
  - Coding
date: 2025-03-21T00:00:00Z
---
![](Pasted%20image%2020250321195549.png)

![](Pasted%20image%2020250321195603.png)

![](Pasted%20image%2020250321195618.png)

![](Pasted%20image%2020250321195633.png)

```python
import ast

# Leer la entrada como un string
input_text = input()  # Ejemplo: "[3, 2, 5, 10, 7]"

# Convertir el string a una lista real de enteros
tokens = ast.literal_eval(input_text)

def max_energy(tokens):
    if not tokens:
        return 0
    if len(tokens) == 1:
        return tokens[0]

    prev2, prev1 = tokens[0], max(tokens[0], tokens[1])

    for i in range(2, len(tokens)):
        curr = max(prev1, tokens[i] + prev2)
        prev2, prev1 = prev1, curr  # Actualizamos valores

    return prev1

# Llamamos a la función con la lista convertida
print(max_energy(tokens))
```

![](Pasted%20image%2020250321200451.png)