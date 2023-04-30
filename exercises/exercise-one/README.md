# Exercise One

## tl;dr

Run the program and inspect the source code to find the artificial "bug".

## Compilation

Exercise one is compilable with the included Makefile. The Makefile compiles the target with debug symbols. In a terminal, you should run (exclude the $):

```shell
$ make

# Should yield something similar to following output (Linux on amd64).
cc -Og -ggdb -fno-omit-frame-pointer -fno-inline-functions -fno-stack-protector -o exercise-one exercise-one.c
--
exercise-one: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=45bbfda7da689398ed38d9524b242f0c900b159d, for GNU/Linux 3.2.0, with debug_info, not stripped
```

## Docker

Alternatively to compiling it on your host, you can build the referenced container with the following:

```shell
# Ensure that your current working directory is /exercises/exercise-one/
$ docker build --tag exercise-one .
... <lots of output here>
Successfully built c0156e6e4990
Successfully tagged exercise-one:latest

# Run the container
$ docker run --interactive --tty exercise-one
```

## Usage

The executable expects a file to be passed in as the first argument (`argv[1]`). Using the executable without input will warn you of this (again, don't type the $).

```shell
# Without a file, the executable prints and exits.
$ ./exercise-one
Usage: exercise-one <filename>

# With a file, the executable prints the contents of the file, and exits.
$ ./exercise-one input-one.txt
The contents of the file are: Hello world!
```

## Intent

### Learning Objectives

- Students understands what a crash is.
- Students understand how to compile an executable.
- Students can reason about the many different states of the program.
- Students can reason about the exploding problem space caused by the `strcmp`s.

The program has an artificial bug introduced with the command `abort` which raises the `SIGABRT` signal on the calling process. When this command is triggered, the signal handler will terminate the process. Usually, this is not desirable and simulates typical, unintentional, crashing behavior.

The program opens a file passed in as the first argument. The file contents are read in to a buffer on the stack. The program then prints the contents to `stdout`. Finally, the program checks the first three bytes of the program. If they are 'bug', then the program calls `abort`. This represents a specific test case that a fuzzer is capable of finding. We are not yet fuzzing in this exercise, but discussing the different paths a program could take.

This program, although simple, also represents a difficult problem for a fuzzer. We're essentially checking for magic bytes that have to appear at the beginning of the file's contents. This is difficult for fuzzers to pick up because the chance of encountering those specific bytes is very small. We'll test it out in the next exercise.
