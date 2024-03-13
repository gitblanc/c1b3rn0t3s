---
title: Steganografy notes 🐅
---

# Investigate image metadata

- Use command `file image.png`
- Use command `exiftool image.png`
- Use command `xxd image.png`
- Use command `strings image.png`
- Use tool binwalk to search binary images for embedded files and executable code: `binwalk image.png`
  - To extract the file: `binwalk -e image.png`
- Use command: `steghide extract -sf image.png`
- [Steganographic Decoder](https://futureboy.us/stegano/decinput.html)
  - Upload the file to it
- Bruteforce the password and extract contents of an image:

```shell
stegseek -sf image.png /path/to/wordlist
# Then if it extracts something do
file whatever.file # to know what is it
```

- Use command `steghide info image.png`

- Inspect audio files (like `.wav` files) with [Sonic Visualizer](https://www.sonicvisualiser.org/)
  - Click on `Layer > Add Spectrogram`

![](Pasted%20image%2020240306215008.png)

- Now set the scale to dB^2 and the colour to White on Black

![](Pasted%20image%2020240306215637.png)

- Try with the tool [outguess](https://github.com/crorvick/outguess) when you have an image

  - Also there is this other project (manteined) [outguess](https://github.com/resurrecting-open-source-projects/outguess)
  - Then, install it with: `./configure && make`
  - Then, try the command: `./outguess -r /file/to/analyze /path/to/the/output`

- If you find a corrupted image (checking the file header of the image which should be `\x89x50\x4Ex47`), the try this command:

```shell
printf '\x89\x50\x4E\x47' | dd of=IMAGE.png bs=4 conv=notrunc
```

- If you have two strings in different formats, try this python script:

```python
s1 = "44585d6b2368737c65252166234f20626d"
s2 = "1010101010101010101010101010101010"
h = hex(int(s1, 16) ^ int(s2, 16))[2:]
print(bytes.fromhex(h).decode('utf-8'))
```

- You also have the tool [stegsolve](https://wiki.bi0s.in/steganography/stegsolve/)
  - Install with:

```shell
wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
chmod +x stegsolve.jar
mkdir bin
mv stegsolve.jar bin/
```

- Use it with: `java -jar stegsolve.jar`
- You might also need to search for a web in [WaybackMachine](https://archive.org/web/)

- Open `.pcap` files with wireshark and analyze them
