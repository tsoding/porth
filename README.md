# Porth

**WARNING! THIS LANGUAGE IS A WORK IN PROGRESS! ANYTHING CAN CHANGE AT ANY MOMENT WITHOUT ANY NOTICE! USE THIS LANGUAGE AT YOUR OWN RISK!**

It's like [Forth](https://en.wikipedia.org/wiki/Forth_(programming_language)) but written in [Python](https://www.python.org/). But I don't actually know for sure since I never programmed in Forth, I only heard that it's some sort of stack-based programming language. Porth is also stack-based programming language. Which makes it just like Forth am I rite?

Porth is planned to be
- [x] Compiled
- [x] Native
- [x] Stack-based (just like Forth)
- [x] [Turing-complete](./examples/rule110.porth)
- [ ] Self-hosted (Python is used only as an initial bootstrap, once the language is mature enough we gonna rewrite it in itself)
- [ ] Statically typed (the type checking is probably gonna be similar to the [WASM validation](https://binji.github.io/posts/webassembly-type-checking/))

(these are not the selling points, but rather milestones of the development)

## Examples

Hello, World:

```pascal
include "std.porth"

"Hello, World\n" stdout write
```

Simple program that prints numbers from 0 to 99 in an ascending order:

```pascal
include "std.porth"

100 0 while 2dup > do
    dup print 1 +
end
```

## Quick Start

### Simulation

Simulation simply interprets the program.

```console
$ cat program.porth
34 35 + print
$ ./porth.py sim program.porth
69
```

**It is strongly recommended to use [PyPy](https://www.pypy.org/) for the Simulation Mode since CPython is too slow for that. Try to simulate [./euler/problem04.porth](./euler/problem04.porth) using CPython and compare it with PyPy and [Compilation Mode](https://github.com/tsoding/porth/blob/e8254c6091357f28795d052d77a921319a8d284b/README.md#compilation).**

### Compilation

Compilation generates assembly code, compiles it with [nasm](https://www.nasm.us/), and then links it with [GNU ld](https://www.gnu.org/software/binutils/). So make sure you have both available in your `$PATH`.

```console
$ cat program.porth
34 35 + print
$ ./porth.py com program.porth
[INFO] Generating ./program.asm
[CMD] nasm -felf64 ./program.asm
[CMD] ld -o ./program ./program.o
$ ./program
69
```

### Testing

Test cases are located in [./tests/](./tests/) folder. The `*.txt` files contain inputs (command line arguments, stdin) and expected outputs (exit code, stdout, stderr) of the corresponding programs.

Run [./test.py](./test.py) script to execute the programs and assert their outputs:

```console
$ ./test.py run
```

To updated expected outputs of the programs run the `update` subcommand:

```console
$ ./test.py update
```

To update expected command line arguments and stdin of a specific program run the `update input <path/to/program.porth>` subcommand:

```console
$ ./test.py update input ./tests/argv.porth new cmd args
[INFO] Provide the stdin for the test case. Press ^D when you are done...
Hello, World
^D
[INFO] Saving input to ./tests/argv.txt
```

The [./examples/](./examples/) folder contains programs that are ment for showcasing the language rather then testing it, but we still can use them for testing just like the stuff in the [./tests/](./tests/) folder:

```console
$ ./test.py run ./examples/
$ ./test.py update input ./examples/name.porth
$ ./test.py update output ./examples/
```

For more info see `./test.py help`

### Usage

If you wanna use the Porth compiler separately from its codebase you only need two things:
- [./porth.py](./porth.py) - the compiler itself,
- [./std/](./std/) - the standard library.

By default the compiler searches files to include in `./` and `./std/`. You can add more search paths via the `-I` flag before the subcommand: `./porth.py -I <custom-path> com ...`. See `./porth.py help` for more info.

## Language Reference

This is what the language supports so far. **Since the language is a work in progress everything in this section is the subject to change.**

### Data Types

#### Integer

Currently an integer is anything that is parsable by [int](https://docs.python.org/3/library/functions.html#int) function of Python. When the compiler encounters an integer it pushes it onto the data stack for processing by the relevant operations.

Example:

```pascal
10 20 +
```

The code above pushes 10 and 20 onto the data stack and sums them up with `+` operation.

#### String

Currently a string is any sequence of bytes sandwiched between two `"`. No newlines inside of the strings are allowed. Escaping is done by [unicode_escape codec](https://docs.python.org/3/library/codecs.html#text-encodings) of Python. No way to escape `"` themselves for now. No special support for Unicode is provided right now too.

When the compiler encounters a string:
1. the size of the string in bytes is pushed onto the data stack,
2. the bytes of the string are copied somewhere into the memory (the exact location is implementation specific),
3. the pointer to the beginning of the string is pushed onto the data stack.

Those, a single string pushes two values onto the data stack: the size and the pointer.

Example:

```
include "std.porth"
"Hello, World" stdout write
```

The `write` macro from `std.porth` module expects three values on the data stack:
1. the size of the buffer it needs to print,
2. the pointer to the beginning of the buffer,
3. and the output file descriptor where it needs to print to.

The size and the pointer are provided by the string `"Hello, World"`. The file descriptor is `stdout` macro from `std.porth`.

#### Character

Currently a character is a single byte sandwiched between two `'`. Escaping is done by [unicode_escape codec](https://docs.python.org/3/library/codecs.html#text-encodings) of Python. No way to escape `'` themselves for now. No special support for Unicode is provided right now too.

When compiler encounters a character it pushes its value as an integer onto the stack.

Example:

```
'E' print
```

This program pushes integer `69` onto the stack (since the ASCII code of letter `E` is `69`) and prints it with the `print` operation.

### Built-in Words

#### Stack Manipulation

- `dup` - duplicate an element on top of the stack.
```
a = pop()
push(a)
push(a)
```
- `swap` - swap 2 elements on the top of the stack.
```
a = pop()
b = pop()
push(a)
push(b)
```
- `drop` - drops the top element of the stack.
```
pop()
```
- `print` - print the element on top of the stack in a free form to stdout and remove it from the stack.
```
a = pop()
print(a)
```
- `over`
```
a = pop()
b = pop()
push(b)
push(a)
push(b)
```

#### Comparison

- `=` - checks if two elements on top of the stack are equal. Removes the elements from the stack and pushes `1` if they are equal and `0` if they are not.
```
a = pop()
b = pop()
push(int(a == b))
```
- `!=` - checks if two elements on top of the stack are not equal.
```
a = pop()
b = pop()
push(int(a != b))
```
- `>` - checks if the element below the top greater than the top.
```
b = pop()
a = pop()
push(int(a > b))
```
- `<` - checks if the element below the top less than the top.
```
b = pop()
a = pop()
push(int(a < b))
```
- `>=`
```
b = pop()
a = pop()
push(int(a >= b))
```
- `<=`
```
b = pop()
a = pop()
push(int(a >= b))
```

#### Arithmetic

- `+` - sums up two elements on the top of the stack.
```
a = pop()
b = pop()
push(a + b)
```
- `-` - subtracts the top of the stack from the element below.
```
a = pop()
b = pop()
push(b - a)
```
- `*` - multiples the top of the stack with the element below the top of the stack
```
a = pop()
b = pop()
push(b * a)
```
- `divmod`
```
a = pop()
b = pop()
push(b // a)
push(b % a)
```

#### Bitwise

- `shr`
```
a = pop()
b = pop()
push(b >> a)
```
- `shl`
```
a = pop()
b = pop()
push(b << a)
```
- `bor`
```
a = pop()
b = pop()
push(b | a)
```
- `band`
```
a = pop()
b = pop()
push(b & a)
```

#### Control Flow

- `if <then-branch> else <else-branch> end` - pops the element on top of the stack and if the element is not `0` executes the `<then-branch>`, otherwise `<else-branch>`.
- `while <condition> do <body> end` - keeps executing both `<condition>` and `<body>` until `<condition>` produces `0` at the top of the stack. Checking the result of the `<condition>` removes it from the stack.

#### Memory

- `mem` - pushes the address of the beginning of the memory where you can read and write onto the stack.
```
push(mem_addr)
```
- `.` - store a given byte at the address on the stack.
```
byte = pop()
addr = pop()
store(addr, byte)
```
- `,` - load a byte from the address on the stack.
```
addr = pop()
byte = load(addr)
push(byte)
```
- `.64` - store an 8-byte word at the address on the stack.
```
word = pop()
addr = pop()
store(addr, word)
```
- `,64` - load an 8-byte word from the address on the stack.
```
word = pop()
byte = load(word)
push(byte)
```

#### System

- `syscall<n>` - perform a syscall with n arguments where n is in range `[0..6]`. (`syscall1`, `syscall2`, etc)
```
syscall_number = pop()
<move syscall_number to the corresponding register>
for i in range(n):
    arg = pop()
    <move arg to i-th register according to the call convention>
<perform the syscall>
```

### Macros

Define a new word `write` that expands into a sequence of tokens `1 1 syscall3` during the compilation.

```
macro write
    1 1 syscall3
end
```

### Include

Include tokens of file `file.porth`

```
include "file.porth"
```
