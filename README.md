# Porth

**WARNING! THIS LANGUAGE IS A WORK IN PROGRESS! ANYTHING CAN CHANGE AT ANY MOMENT WITHOUT ANY NOTICE! USE THIS LANGUAGE AT YOUR OWN RISK!**

It's like [Forth](https://en.wikipedia.org/wiki/Forth_(programming_language)) but written in [Python](https://www.python.org/). But I don't actually know for sure since I never programmed in Forth, I only heard that it's some sort of stack-based programming language. Porth is also stack-based programming language. Which makes it just like Forth am I rite?

Porth is planned to be
- [x] Compiled
- [x] Native
- [x] Stack-based (just like Forth)
- [x] [Turing-complete](./examples/rule110.porth)
- [x] Statically typed (the type checking is similar to [WASM validation](https://binji.github.io/posts/webassembly-type-checking/))
- [ ] Self-hosted (See [./porth.porth](./porth.porth) for the current progress)
- [ ] Optimized

(these are not the selling points, but rather milestones of the development)

## The Use Case for The Language

Porth is a Computer [Programming Language](https://en.wikipedia.org/wiki/Programming_language). It's designed to write programs for [Computers](https://en.wikipedia.org/wiki/Computer).

## Examples

Hello, World:

```porth
include "std.porth"

"Hello, World\n" puts
```

Simple program that prints numbers from 0 to 99 in an ascending order:

```porth
include "std.porth"

100 0 while 2dup > do
    dup print 1 +
end 2drop
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

### Literals

#### Integer

Currently an integer is anything that is parsable by [int](https://docs.python.org/3/library/functions.html#int) function of Python. When the compiler encounters an integer it pushes it onto the data stack for processing by the relevant operations.

Example:

```porth
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

```porth
include "std.porth"
"Hello, World" puts
```

The `puts` macro from `std.porth` module expects two values on the data stack:
1. the size of the buffer it needs to print,
2. the pointer to the beginning of the buffer.

The size and the pointer are provided by the string `"Hello, World"`.

#### C-style String

It's like a regular string but it does not push its size on the stack and implicitly ends with [NULL-terminator](https://en.wikipedia.org/wiki/Null-terminated_string). Designed specifically to interact with C code or any other kind of code that expects NULL-terminated strings.

```porth
include "std.porth"

0 O_RDONLY "input.txt"c AT_FDCWD openat
//                    ^
//                    |
//                    postfix that indicates a C-style string

if dup 0 < do
    "ERROR: could not open the file\n" eputs
    1 exit
else
    "Successfully opened the file!\n" puts
end

close
```

Here we are using [openat(2)](https://linux.die.net/man/2/openat) Linux syscall to open a file. The syscall expects the pathname to be a NULL-terminated string.

#### Character

Currently a character is a single byte sandwiched between two `'`. Escaping is done by [unicode_escape codec](https://docs.python.org/3/library/codecs.html#text-encodings) of Python. No way to escape `'` themselves for now. No special support for Unicode is provided right now too.

When compiler encounters a character it pushes its value as an integer onto the stack.

Example:

```porth
'E' print
```

This program pushes integer `69` onto the stack (since the ASCII code of letter `E` is `69`) and prints it with the `print` operation.

### Intrinsics (Built-in Words)

#### Stack Manipulation

| Name    | Signature        | Description                                                                                  |
| ---     | ---              | ---                                                                                          |
| `dup`   | `a -- a a`       | duplicate an element on top of the stack.                                                    |
| `swap`  | `a b -- b a`     | swap 2 elements on the top of the stack.                                                     |
| `drop`  | `a b -- a`       | drops the top element of the stack.                                                          |
| `print` | `a b -- a`       | print the element on top of the stack in a free form to stdout and remove it from the stack. |
| `over`  | `a b -- a b a`   | copy the element below the top of the stack                                                  |
| `rot`   | `a b c -- b c a` | rotate the top three stack elements.                                                         |

#### Comparison

| Name | Signature                              | Description                                                  |
| ---  | ---                                    | ---                                                          |
| `= ` | `[a: int] [b: int] -- [a == b : bool]` | checks if two elements on top of the stack are equal.        |
| `!=` | `[a: int] [b: int] -- [a != b : bool]` | checks if two elements on top of the stack are not equal.    |
| `> ` | `[a: int] [b: int] -- [a > b  : bool]` | applies the greater comparison on top two elements.          |
| `< ` | `[a: int] [b: int] -- [a < b  : bool]` | applies the less comparison on top two elements.             |
| `>=` | `[a: int] [b: int] -- [a >= b : bool]` | applies the greater or equal comparison on top two elements  |
| `<=` | `[a: int] [b: int] -- [a <= b : bool]` | applies the greater or equal comparison on top two elements. |

#### Arithmetic

| Name     | Signature                                        | Description                                                                                                              |
| ---      | ---                                              | ---                                                                                                                      |
| `+`      | `[a: int] [b: int] -- [a + b: int]`              | sums up two elements on the top of the stack.                                                                            |
| `-`      | `[a: int] [b: int] -- [a - b: int]`              | subtracts two elements on the top of the stack                                                                           |
| `*`      | `[a: int] [b: int] -- [a * b: int]`              | multiples two elements on top of the stack                                                                               |
| `divmod` | `[a: int] [b: int] -- [a / b: int] [a % b: int]` | perform [Euclidean division](https://en.wikipedia.org/wiki/Euclidean_division) between two elements on top of the stack. |

#### Bitwise

| Name  | Signature                            | Description                   |
| ---   | ---                                  | ---                           |
| `shr` | `[a: int] [b: int] -- [a >> b: int]` | right **unsigned** bit shift. |
| `shl` | `[a: int] [b: int] -- [a << b: int]` | light bit shift.              |
| `or`  | `[a: int] [b: int] -- [a \| b: int]` | bit `or`.                     |
| `and` | `[a: int] [b: int] -- [a & b: int]`  | bit `and`.                    |
| `not` | `[a: int] -- [~a: int]`              | bit `not`.                    |

#### Memory

| Name         | Signature                      | Description                                                                                    |
| ---          | ---                            | ---                                                                                            |
| `mem`        | `-- [mem: ptr]`                | pushes the address of the beginning of the memory where you can read and write onto the stack. |
| `!8`         | `[byte: int] [place: ptr] -- ` | store a given byte at the address on the stack.                                                |
| `@8`         | `[place: ptr] -- [byte: int]`  | load a byte from the address on the stack.                                                     |
| `!16`        | `[byte: int] [place: ptr] --`  | store an 2-byte word at the address on the stack.                                              |
| `@16`        | `[place: ptr] -- [byte: int]`  | load an 2-byte word from the address on the stack.                                             |
| `!32`        | `[byte: int] [place: ptr] --`  | store an 4-byte word at the address on the stack.                                              |
| `@32`        | `[place: ptr] -- [byte: int]`  | load an 4-byte word from the address on the stack.                                             |
| `!64`        | `[byte: int] [place: ptr] --`  | store an 8-byte word at the address on the stack.                                              |
| `@64`        | `[place: ptr] -- [byte: int]`  | load an 8-byte word from the address on the stack.                                             |
| `cast(int)`  | `[a: any] -- [a: int]`         | cast the element on top of the stack to `int`                                                  |
| `cast(bool)` | `[a: any] -- [a: bool]`        | cast the element on top of the stack to `bool`                                                 |
| `cast(ptr)`  | `[a: any] -- [a: ptr]`         | cast the element on top of the stack to `ptr`                                                  |

#### System

- `syscall<n>` - perform a syscall with n arguments where n is in range `[0..6]`. (`syscall1`, `syscall2`, etc)

```porth
syscall_number = pop()
<move syscall_number to the corresponding register>
for i in range(n):
    arg = pop()
    <move arg to i-th register according to the call convention>
<perform the syscall>
```

#### Misc

- `here (-- [len: int] [str: ptr])` - pushes a string `"<file-path>:<row>:<col>"` where `<file-path>` is the path to the file where `here` is located, `<row>` is the row on which `here` is located and `<col>` is the column from which `here` starts. It is useful for reporting developer errors:

```porth
include "std.porth"

here puts ": TODO: not implemented\n" puts 1 exit
```

- `argc (-- [argc: int])`
- `argv (-- [argv: ptr])`

### std.porth

TBD

<!-- TODO: Document Standard Library Properly -->

### Control Flow

#### if-condition

<!-- TODO: document if-conditions -->

```porth
<condition> if
  <body>
else <condition> if*
  <body>
else <condition> if*
  <body>
else
  <body>
end
```

#### while-loop

<!-- TODO: document while-loops properly -->

```porth
while <condition> do
   <body>
end
```

### Macros

Define a new word `write` that expands into a sequence of tokens `stdout SYS_write syscall3` during the compilation.

```porth
macro write
    stdout SYS_write syscall3
end
```

### Include

Include tokens of file `file.porth`

```porth
include "file.porth"
```

### Procedures

<!-- TODO: Document Procedures Properly -->

```porth
proc seq // n --
  while dup 0 > do
    dup print
    1 -
  end drop
end
```

### Constants

<!-- TODO: Document Constants Properly -->

```porth
const N 69 end
const M 420 end
const K M N / end
```

### Memory

<!-- TODO: Document Memory properly -->

#### Global Memory

```porth
include "std.porth"

const N 26 end
memory buffer N end

0 while dup N < do
  dup 'a' +
  over buffer +
  !8

  1 +
end drop

N buffer puts
```

#### Local Memory

```porth
include "std.porth"

proc fib // n --
  memory a sizeof(u64) end
  memory b sizeof(u64) end

  dup 1 > if
    dup 1 - fib a !64
    dup 2 - fib b !64
    a @64 b @64 +
  end
end
```

### offset/reset

<!-- TODO: Document offset/reset properly -->

#### Enums

```porth
include "std.porth"

const MON 1 offset end
const TUE 1 offset end
const WED 1 offset end
const THU 1 offset end
const FRI 1 offset end
const SAT 1 offset end
const SUN 1 offset end
const WEEK_DAYS reset end

"There is " puts WEEK_DAYS putd " days in a week\n" puts
```

#### Structs

```porth
include "std.porth"

const offsetof(Str.count) sizeof(u64) offset end
const offsetof(Str.data) sizeof(ptr) offset end
const sizeof(Str) reset end
```

### Type Checking

TBD

<!-- TODO: Document Type Checking process -->

#### Types of Porth

- `int` - 64 bit integer
- `bool` - boolean
- `ptr` - pointer

TBD
