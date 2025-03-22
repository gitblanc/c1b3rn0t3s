---
title: Dragon Fury
tags:
  - CTF
  - HackTheBox
  - CyberApocalypse
  - Coding
date: 2025-03-21T00:00:00Z
---
![](Pasted%20image%2020250322102814.png)

![](Pasted%20image%2020250322102850.png)

![](Pasted%20image%2020250322102903.png)
![](Pasted%20image%2020250322103348.png)

**Backtracking / Exhaustive Search**  
**Explanation:**

- Given multiple lists (subarrays) containing possible damage values, we needed to select exactly one value from each list so that their sum equaled `T`.
- **Backtracking** was used because it efficiently explores all possible combinations to find the guaranteed unique solution.
- An alternative approach could have been **Dynamic Programming** if we had multiple solutions and needed to optimize the selection process.

```python
import ast
from itertools import product

def find_damage_combination(damage_list, target):
    
    for combination in product(*damage_list):
        if sum(combination) == target:
            return list(combination)
    
    return []

# Leer la entrada
damage_list = ast.literal_eval(input().strip())
target = int(input().strip())

# Resolver y mostrar la salida
result = find_damage_combination(damage_list, target)
print(result)
```