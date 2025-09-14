---
layout: blog
title: TTY treatment
tags: tty shell reverse-shell
comments: false
date: 2025-9-14
---

# TTY treatment

TTY treatment is a technique used in reverse shells for being able to do Ctrl+Z to clear the screen,  Ctrl+C without quitting the reverse shell and be able to access commands history with up and down keys.

## Linux

These are the commands used in linux to treat the tty:

- `$ script /dev/null -c bash` or `$ python3 -c "import pty; pty.spawn('/bin/bash')"`: Used to start a bash shell.
- Press Ctrl+Z keys to background the shell:
    ```bash
    bash-5.2$ ^Z
    zsh: suspended  nc -lvnp 443
    ```
- `❯ stty raw -echo; fg`: Make the shell a tty and foreground the shell.
- `reset xterm`: Reset the shell to show it cleaner.
- `$ export TERM=xterm`: Set the terminal to xterm. This is used for being able to do Ctrl+L.
- `$ export SHELL=bash`: Set the shell to bash for better performance
- `$ stty rows <rows> cols <cols>`: Set rows and columns to adjust shell size to current terminal window size. To see your terminal window size, open a new full terminal window and execute `stty size`. The first number is the number of rows and the second number is the number columns. In my case, it outputs "50 184" so I need to execute `stty rows 50 cols 184` in the reverse shell.

Now, it's created a interactive reverse shell for better performance and management in the machine.
