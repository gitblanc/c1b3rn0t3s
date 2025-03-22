---
title: Enchanted Cipher
tags:
  - CTF
  - HackTheBox
  - CyberApocalypse
  - Coding
date: 2025-03-21T00:00:00Z
---
The cipher operates as follows:

- Alphabetical characters are processed in groups of 5 (ignoring non-alphabetical characters).
- For each group, a random shift between 1 and 25 is chosen and applied to every letter in that group.
- After the encoded message, an additional line indicates the total number of shift groups, followed by another line listing the random shift values used for each group.

Your quest is to decode the given input and restore the original plaintext.

![](Pasted%20image%2020250321210240.png)

```python
def decode_cipher(encoded_message, shifts):
    decoded = []
    alpha_count = 0  # Count only alphabetic characters for grouping

    for char in encoded_message:
        if char.isalpha():
            # Only process alphabetic characters
            group_index = alpha_count // 5  # Determine which group the character belongs to
            shift = shifts[group_index % len(shifts)]  # Get the shift for this group

            # Apply reverse shift (subtract) with wrap-around
            char_lower = char.lower()
            decoded_char = chr(((ord(char_lower) - ord('a') - shift) % 26) + ord('a'))
            decoded.append(decoded_char)

            alpha_count += 1
        else:
            # Keep non-alphabetic characters (spaces) as they are
            decoded.append(char)

    return ''.join(decoded)

def parse_input(input_str):
    # Remove brackets and split by comma
    input_str = input_str.strip()
    if input_str.startswith('[') and input_str.endswith(']'):
        input_str = input_str[1:-1]

    # Convert each element to integer
    tokens = [int(x.strip()) for x in input_str.split(',')]
    return tokens

def remove_spaces(text):
    """Remove all spaces from the input text"""
    return text.replace(" ", "")


# Read all input at once and split by lines
encrypted_message = input()
num_groups = int(input().strip())
shifts = input().strip()


# Parse shifts from the input
shifts = parse_input(shifts)

# Decode and print the result
result = decode_cipher(encrypted_message, shifts)
print(result)
```

