---
title: Python Useful Commands ⚕️
tags: []
---
## Install python2 and python3 

```shell
apt install python2 python3
```

## Install pip2 and pip3

```shell
# pip2
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
python2 get-pip.py

#pip3
apt install python3-pip 
```

## Install a package

```shell
pip3 install PACKAGE
```

## Open the interactive interpreter

```shell
python3
python2

# or
python3 -c 'if your code sucks; do this then...'
```

>[!Tip]
>Press `Ctrl+L` to clean the screen

## Create a Python package

- Go to [https://pypi.org](https://pypi.org) and create an account
	- You will need to add your phone
- Create the file `/root/.pypirc` with the following content:

```txt
[pypi]
	username = __token__
	password = YOUR_API_TOKEN
```

- Create a project:
```shell
cd /path/to/store/package
mkdir PROJECT
touch setup.py README.md
cd PROJECT
touch init.py
touch FIRST_MODULE.py
```

- Inside `init.py` you must define the modules of the package:

```python
# inside the init.py
from .MODULE_NAME import *
```

- Now edit the `setup.py` file:

```python
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
	long_description = fh.read()

setup(
	  name="YOUR_PACKAGE_NAME",
	  version"VERSION",
	  packages=find_packages(),
	  install_requires=[],
	  author="YOUR_NAME",
	  description="whatever",
	  long_description=long_description,
	  long_description_content_type="text/markdown",
	  url="YOUR_URL"
)
```

- Install **twine**: `pip3 install twine`
- Upload the content: `twine upload dist/*`