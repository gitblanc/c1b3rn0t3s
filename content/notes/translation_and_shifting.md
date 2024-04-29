---
title: Translation and Shifting (Format encoding) 🥭
---

Here are some of the most CTF common formats to encode flags with examples:

- **Binary**: `01101100 01100101 01110100 01110011 00100000 01110100 01110010 01111001 00100000 01110011 01101111 01101101 01100101 00100000 01100010 01101001 01101110 01100001 01110010 01111001 00100000 01101111 01110101 01110100 00100001` -> `lets try some binary out!`
- **Base32**: `MJQXGZJTGIQGS4ZAON2XAZLSEBRW63LNN5XCA2LOEBBVIRRHOM======` -> `base32 is super common in CTF's`
- **Base64**: `RWFjaCBCYXNlNjQgZGlnaXQgcmVwcmVzZW50cyBleGFjdGx5IDYgYml0cyBvZiBkYXRhLg==` -> `Each Base64 digit represents exactly 6 bits of data.`
- **Hexadecimal**: `68 65 78 61 64 65 63 69 6d 61 6c 20 6f 72 20 62 61 73 65 31 36 3f` -> `hexadecimal or base16?`
- **ROT13**: `Ebgngr zr 13 cynprf!` -> `Rotate me 13 places!`
- **ROT47**: `*@F DA:? >6 C:89E C@F?5 323J C:89E C@F?5 Wcf E:>6DX` -> `you spin me right round baby right round (47 times)`
- **Morse**: `- . .-.. . -.-. --- -- -- ..- -. .. -.-. .- - .. --- -.. -. -.-. --- -.. .. -. --.` -> `TELECOMMUNICATION  ENCODING `
- **Decimal**: `85 110 112 97 99 107 32 116 104 105 115 32 66 67 68` -> `Unpack this BCD`
- **Vigenere Cipher**: [decoder1](https://www.dcode.fr/vigenere-cipher), [decoder2](https://cryptii.com/pipes/vigenere-cipher), [decoder3](https://www.guballa.de/vigenere-solver)
	- Beaufort Variant: `Tizmg_nv_zxxvhh_gl_gsv_nzk_kovzhv`
- **More Cipher** (rare Caesar): [quipqiup](https://quipqiup.com/) (Like `Lwuv oguukpi ctqwpf.`)
- If you see something like: `581695969015253365094191591547859387620042736036246486373595515576333693`, try the following script:

```python
n = 581695969015253365094191591547859387620042736036246486373595515576333693
h = hex(n)[2:]
print(bytearray.fromhex(h).decode())
```

- If you don't know the cipher, try here pasting the message: [dcode](https://www.dcode.fr/)
