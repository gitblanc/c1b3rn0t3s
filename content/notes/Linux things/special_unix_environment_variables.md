---
title: Unix Environment Variables 🌋
---
## `${IFS}`

Stands for **Internal Field Separator** in shell scripting. It's a special environment variable used in Bash (and similar shells) to define which characters are used to split a string into fields. By default, the characters used as separators are **space, tab, and newline**.

## `${PATH}`

Defines the list of directories the system searches for executables when a command is entered.

## `${HOME}`

Contains the path to the current user's home directory.

## `${PWD}`

Represents the current working directory.

## `${USER}`

Holds the name of the current user.

## `${SHELL}`

Displays the path of the command interpreter being used by the user.

## `${MAIL}`

Indicates the location of the user's mail.

## `${PS1}`

Defines the primary command prompt (the symbol you see in the terminal).

## `${RANDOM}`

Generates a random number between 0 and 32767 each time it is accessed.

## `${#variable}`

Returns the length of the variable `variable`.

## `${variable:-default}`

Returns the value of `variable`, or `default` if `variable` is not set or is empty.

## `${variable//pattern/replacement}`

Replaces all occurrences of `pattern` in `variable` with `replacement`.

## `${!variable}`

Expands to the value of the variable whose name is the value of `variable`.

## `${variable:offset:length}`

Extracts a substring from `variable`, starting at `offset` and up to `length` characters.

## `${variable^}`

Converts the first character of `variable` to uppercase.

## `${variable,,}`

Converts all characters in `variable` to lowercase.

## `${variable^pattern}`

Capitalizes the first character of each word that matches the specified `pattern`.

## `${variable,,pattern}`

Converts all characters to lowercase for words matching the specified `pattern`.

## `${variable:-default}`

Returns `default` if `variable` is unset or null; otherwise, it returns `variable`.

## `${variable+value}`

Returns `value` if `variable` is set; otherwise, it returns nothing.

## `${variable:?error}`

Returns `variable` if it is set and not null; otherwise, it prints `error` and exits.

## `${BASH_VERSION}`

Displays the version of the Bash shell you are currently using.

## `${0}`

Represents the name of the script or shell itself. This is useful for scripts to know how they were called.

## `${#}`

Returns the number of positional parameters passed to the script or function.

## `$@`

Represents all the positional parameters passed to the script or function, as separate words.

## `$*`

Similar to `$@`, but treats all positional parameters as a single word.

## `$?`

Contains the exit status of the last command executed. A value of `0` indicates success, while any non-zero value indicates an error.

## `$$`

Represents the process ID (PID) of the current shell or script.

## `$!`

Holds the PID of the last background command executed.

## `${FUNCNAME}`

An array variable that holds the names of the current function and all functions in the call stack.

## `${LINENO}`

Indicates the current line number in the script where it is referenced.

## `${HISTFILE}`

Specifies the file in which command history is saved.

## `${HISTSIZE}`

Determines the number of commands to remember in the command history.

## `${BASH_ENV}`

A file that is sourced whenever a new non-interactive shell is started.

## `${PROMPT_COMMAND}`

A command that is executed before the primary prompt is displayed.
