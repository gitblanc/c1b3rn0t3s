---
title: Setting up batcat
---
## Common clear installation

- First, install batcat:

```shell
sudo apt update
sudo apt install bat
```

- Then open the `~/.zshrc` and add the following alias:

```shell
alias cat='batcat --style=grid,snip --theme=TwoDark --paging=never'
```

- Save it and reload the terminal:

```shell
source ~/.zshrc
```

## Tab Error

- When hitting the Tab you get something like this:

```shell
(eval):1: _python-argcomplete: function definition file not found
```

- Clear the cache and restart the terminal:

```shell
rm ~/.cache/zcompdump
compinit
```