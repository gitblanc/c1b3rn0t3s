---
title: MiniMax
tags:
  - CTF
  - HackTheBox
  - Coding
---
![](Pasted%20image%2020241025161811.png)

```python
def find_coordinates(data):
    # Convert the string input to a list of floats
    numbers = list(map(float, data.split()))
    
    # Find the minimum and maximum numbers
    min_num = min(numbers)
    max_num = max(numbers)
    
    # Print the minimum and maximum
    print(min_num)
    print(max_num)

# Example input
data = input()
find_coordinates(data)

```