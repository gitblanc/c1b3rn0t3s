---
title: md5 number generator
---
```python
import hashlib
import sys

if len(sys.argv) != 3:
    print("Usage: <MIN_NUMBER> <MAX_NUMBER>")
    sys.exit(0)

MIN_NUMBER = int(sys.argv[1])
MAX_NUMBER = int(sys.argv[2])

def md5_encode():
    for i in range(MIN_NUMBER, MAX_NUMBER + 1):
        print(i, hashlib.md5(str(i).encode()).hexdigest())

md5_encode()
```

