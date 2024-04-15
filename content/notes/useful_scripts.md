---
title: Useful scripts 🌊
---

# Combining passwords for brute force:

```bash
#!/bin/bash

# Comprueba que se han pasado tres argumentos al script
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <words> <combinations> <output_file>"
  exit 1
fi

# Asigna los argumentos a variables
WORDLIST="$1"
COMBINATIONS="$2"
FINAL_WORDLIST="$3"

# Procesa la wordlist y las combinaciones
while read -r line; do
  while read -r combo; do
    echo "${line}${combo}"
  done < "$COMBINATIONS"
done < "$WORDLIST" > "$FINAL_WORDLIST"

echo "New wordlist has been created: $FINAL_WORDLIST"
```

# Convert a wordlist to its md5 equivalent (all passwords to md5):

```shell
while read -r password; do echo -n "$password" | openssl md5 | awk '{print $2}'; done < wordlist.txt > hashes_md5.txt
```

## More efficient one:

```python
import hashlib
import sys

def generate_md5_hash(input_file, output_file):
    try:
        with open(input_file, 'r') as f_in, open(output_file, 'w') as f_out:
            for line in f_in:
                password = line.strip()
                # Generate MD5 hash
                md5_hash = hashlib.md5(password.encode()).hexdigest()
                f_out.write(md5_hash + '\n')
        print(f"MD5 hashes have been successfully written to {output_file}")
    except FileNotFoundError:
        print(f"Error: The file {input_file} was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 generate_md5.py <input_wordlist> <output_file>")
    else:
        input_file = sys.argv[1]
        output_file = sys.argv[2]
        generate_md5_hash(input_file, output_file)
```

# Duplicate to x times each word of a wordlist

```python
import sys

def repeat_words(wordlist_path, max_repeats, output_path):
    try:
        with open(wordlist_path, 'r') as file:
            words = file.readlines()
    except FileNotFoundError:
        print(f"File not found: {wordlist_path}")
        sys.exit(1)

    with open(output_path, 'w') as outfile:
        for word in words:
            word = word.strip()  # Remove any trailing whitespace or newline characters
            for i in range(1, max_repeats + 1):
                outfile.write(word * i + '\n')

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 script.py /path/to/wordlist MAX_REPEATS output_wordlist")
        sys.exit(1)

    wordlist_path = sys.argv[1]
    max_repeats = int(sys.argv[2])
    output_path = sys.argv[3]

    repeat_words(wordlist_path, max_repeats, output_path)
```
