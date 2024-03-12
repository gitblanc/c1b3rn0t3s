---
title: Esoteric languages 💢
---

# Brainfuck language

- An example:

```brainfuck
+++++ ++++[ ->+++ +++++ +<]>+ +++.< +++++ [->++ +++<] >++++ +.<++ +[->-
--<]> ----- .<+++ [->++ +<]>+ +++.< +++++ ++[-> ----- --<]> ----- --.<+
++++[ ->--- --<]> -.<++ +++++ +[->+ +++++ ++<]> +++++ .++++ +++.- --.<+
+++++ +++[- >---- ----- <]>-- ----- ----. ---.< +++++ +++[- >++++ ++++<
]>+++ +++.< ++++[ ->+++ +<]>+ .<+++ +[->+ +++<] >++.. ++++. ----- ---.+
++.<+ ++[-> ---<] >---- -.<++ ++++[ ->--- ---<] >---- --.<+ ++++[ ->---
--<]> -.<++ ++++[ ->+++ +++<] >.<++ +[->+ ++<]> +++++ +.<++ +++[- >++++
+<]>+ +++.< +++++ +[->- ----- <]>-- ----- -.<++ ++++[ ->+++ +++<] >+.<+
++++[ ->--- --<]> ---.< +++++ [->-- ---<] >---. <++++ ++++[ ->+++ +++++
<]>++ ++++. <++++ +++[- >---- ---<] >---- -.+++ +.<++ +++++ [->++ +++++
<]>+. <+++[ ->--- <]>-- ---.- ----. <

## Equivalent to:
User: eli
Password: DSpDiM1wAEwid
```

- Decoder/Encoder here: https://www.dcode.fr/brainfuck-language

# Piet Esoteric Language

- This language is presented in images like this:
  ![](./img/PI3T.png)
- To decode this image content just follow these steps:
  - Download Gimp: `sudo apt install gimp`
  - Open the image wit Gimp and Export it as .ppm file: `Export as > .ppm`
  - Now download the Piet interpreter:
  ```shell
  sudo su
  git clone https://github.com/gleitz/npiet.git
  cd npiet
  ./configure
  make
  ```
  - Execute the image with the interpreter: `./npiet /path/to/the/image.ppm`
- Program on piet here: https://gabriellesc.github.io/piet/
