---
title: ClockWork Gurdian
tags:
  - CTF
  - HackTheBox
  - CyberApocalypse
  - Coding
date: 2025-03-21T00:00:00Z
---
![](Pasted%20image%2020250322104043.png)

![](Pasted%20image%2020250322104641.png)

**BFS (Breadth-First Search)**  
**Explanation:**

- Since the problem involved finding the shortest path in a **grid with obstacles**, **BFS** was the best choice.
- BFS is ideal for such problems because:
    - It explores all possible routes level by level (layered exploration).
    - It guarantees the shortest path in **O(N × M)** time for an `N × M` grid.
- An alternative would be __A_ (A-Star Search)_* if we had additional cost heuristics, but **BFS** was sufficient since all moves had the same cost.

```python
from collections import deque
import ast
import sys

def shortest_safe_path(grid):
    rows, cols = len(grid), len(grid[0])
    directions = [(-1, 0), (1, 0), (0, -1), (0, 1)]  # Up, Down, Left, Right
    
    # Find the exit position
    exit_pos = None
    for r in range(rows):
        for c in range(cols):
            if grid[r][c] == 'E':
                exit_pos = (r, c)
                break
    
    if exit_pos is None or grid[0][0] == 1:
        return -1  # No exit found or start is blocked
    
    # BFS setup
    queue = deque([(0, 0, 0)])  # (row, col, steps)
    visited = set()
    visited.add((0, 0))
    
    while queue:
        r, c, steps = queue.popleft()
        
        if (r, c) == exit_pos:
            return steps  # Found the shortest path
        
        for dr, dc in directions:
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols and (nr, nc) not in visited:
                if grid[nr][nc] == 0 or grid[nr][nc] == 'E':  # Safe cell or exit
                    visited.add((nr, nc))
                    queue.append((nr, nc, steps + 1))
    
    return -1  # No path found

# Example usage
grid = ast.literal_eval(sys.stdin.read().strip())

print(shortest_safe_path(grid))
```