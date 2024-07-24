---
title: Translation and Shifting (Format encoding) 🥭
---
## Identify the cipher

- [Boxentriq](https://www.boxentriq.com/code-breaking/cipher-identifier)

## CTF Formats

Here are some of the most CTF common formats to encode flags with examples:

- **Binary**: `01101100 01100101 01110100 01110011 00100000 01110100 01110010 01111001 00100000 01110011 01101111 01101101 01100101 00100000 01100010 01101001 01101110 01100001 01110010 01111001 00100000 01101111 01110101 01110100 00100001` -> `lets try some binary out!`
- **Base32**: `MJQXGZJTGIQGS4ZAON2XAZLSEBRW63LNN5XCA2LOEBBVIRRHOM======` -> `base32 is super common in CTF's`
- **Base64**: `RWFjaCBCYXNlNjQgZGlnaXQgcmVwcmVzZW50cyBleGFjdGx5IDYgYml0cyBvZiBkYXRhLg==` -> `Each Base64 digit represents exactly 6 bits of data.`
- **Base91**: [dcode](https://www.dcode.fr/base-91-encoding)
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
- **Spoon Programming language**: 

```spoon
111111111100100010101011101011111110101111111111011011011011000001101001001011111111111111001010010111100101000000000000101001101111001010010010111111110010100000000000000000000000000000000000000010101111110010101100101000000000000000000000101001101100101001001011111111111111111111001010000000000000000000000000001010111001010000000000000000000000000000000000000000000001010011011001010010010111111111111111111111001010000000000000000000000000000000001010111111001010011011001010010111111111111100101001000000000000101001111110010100110010100100100000000000000000000010101110010100010100000000000000010100000000010101111100101001111001010011001010010000001010010100101011100101001101100101001011100101001010010100110110010101111111111111111111111111111111110010100100100000000000010100010100111110010100000000000000000000000010100111111111111111110010100101111001010000000000000001010

that means:

The magic word you are looking for is ApplePie
```

## Encoding/Decoding on your machine


### Base64 Encode

```shell
echo https://www.hackthebox.eu/ | base64

aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K
```

### Base64 Decode

```shell
echo aHR0cHM6Ly93d3cuaGFja3RoZWJveC5ldS8K | base64 -d

https://www.hackthebox.eu/
```

### Hex Encode

```shell
echo https://www.hackthebox.eu/ | xxd -p

68747470733a2f2f7777772e6861636b746865626f782e65752f0a
```

### Hex Decode

```shell
echo 68747470733a2f2f7777772e6861636b746865626f782e65752f0a | xxd -p -r

https://www.hackthebox.eu/
```

### ROT13 Encode

```shell
echo https://www.hackthebox.eu/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'

uggcf://jjj.unpxgurobk.rh/
```

### ROT13 Decode

```shell
echo uggcf://jjj.unpxgurobk.rh/ | tr 'A-Za-z' 'N-ZA-Mn-za-m'

https://www.hackthebox.eu/
