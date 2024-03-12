---
title: Check integrity of an iso image 👻
---

- Do the following:
  - Download the iso
  - Generate the checksum using this command: `certutil -hashfile /path/to/os.iso sha256`
  - Compare the official sha256 with the generated
