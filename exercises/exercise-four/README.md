# Exercise Four

## tl;dr

Compile the program with AddressSanitizer (ASAN) and find the bug.

## Learning Objectives

- Use AddressSanitizer (ASAN) to find memory access issues that normally don't result in a fatal crash.

## About

Exercises two and three showed us show to find fatal crashes in program. What about finding faults that normally wouldn't lead to fatal crashes. Potentially out of bounds reads or writes that access valid memory locations? This is where [sanitizers][sanitizers] come in! This lesson will walk us through using AddressSanitizer (ASAN) to find issues related to memory accesses that we wouldn't be able to find without ASAN.

Exercise four looks at a small project called `mantohtml`. As the name suggests, it converts `man` pages to .html documents. The project is hosted on [GitHub][mantohtml-github] and available on the [snap][mantohtml-snap] package manager.

The project in this repository is a submodule. If you didn't already clone the submodules, make sure to do so with:

```shell
git submodule init
git submodule update --recursive
```

## Compilation

You can compile the program with the included [Makefile](./mantohtml/Makefile) in the `mantohtml` directory. If you're using Docker, skip to the [Docker](#docker) section.

```shell
# Navigate to the exercise-four directory if you haven't already.
$ cd exercise-four

# Compile the program.
$ make
# Should output something similar:
< Lot of output here. >
Compiling mantohtml.c...
afl-gcc-pass ++4.06a by <oliva@adacore.com>
[*] Inline instrumentation at ratio of 100% in non-hardened mode.
[+] Instrumented 503 locations (non-hardened mode, inline, ratio 100%).
[+] Done compiling mantohtml.
./mantohtml: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d6f8cdeb49d4ba0e13c0e6061720bcbe6b9409b7, for GNU/Linux 3.2.0, with debug_info, not stripped
```

## Docker

Alternatively, you can use the included Dockerfile to build the program. This is useful if you don't want to install the dependencies on your system.

```shell
# Navigate to the exercise-four directory if you haven't already.
$ cd exercise-four

# Build the Docker image.
$ docker build --tag exercise-four .
... < Lots of output here >
Successfully tagged exercise-four:latest

# Run the container. Mounting a volume to persist the output.
$ docker run --volume $(pwd)/output:/output --interactive --tty exercise-four:latest
```

## Usage

`mantohtml` takes a file as input and, without any other arguments, writes the resulting `man` page to stdout formatted as `html`. There is a sample test case provided in `mantohtml/mantohtml.1` (also linked to [./testsuite/mantohtml.1][testcase]). You can run the program with this test case like so:

```shell
# Assumes you're in the exercise-four directory.
$ ./mantohtml/mantohtml ./testsuite/mantohtml.1
<!DOCTYPE html>
<html>
  <head>
    <meta name="creator" content="mantohtml v2.0">
    <title>Documentation</title>
  </head>

... < Lots more output >
```

The executable does read some flags that can be passed in as arguments (like `--author` or `--chapter`). For the purposes of this course, they remain unexplored, but could also also be fuzzed. We'll focus exclusively on the input file.

[sanitizers]: https://github.com/google/sanitizers
[mantohtml-github]:https://github.com/michaelrsweet/mantohtml/
[mantohtml-snap]: https://snapcraft.io/mantohtml
[testcase]: ./testsuite/mantohtml.1
