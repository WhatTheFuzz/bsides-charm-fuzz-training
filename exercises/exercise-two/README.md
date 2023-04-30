# Exercise Two

## Compilation

Exercise two is compilable just like [exercise one](../exercise-one) (it's the
same source) with the included Makefile. The Makefile compiles the target with
the AFL clang fast compiler and debug symbols. In a terminal, you should run
(exclude the `$`):

```shell
$ make

# Should yield something similar to following output (Linux on amd64).
afl-clang-fast -Og -ggdb -fno-omit-frame-pointer -fno-inline-functions -fno-stack-protector -o exercise-two exercise-two.c
afl-cc++4.05a by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: LLVM-PCGUARD
SanitizerCoveragePCGUARD++4.05a
[+] Instrumented 9 locations with no collisions (non-hardened mode) of which are 0 handled and 0 unhandled selects.
--
exercise-two: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d72746fc6b7b80ca44be8cd5de6c752128120cca, for GNU/Linux 3.2.0, with debug_info, not stripped
```

## Docker

Alternatively to compiling it on your host, you can build the referenced
container with the following commands. This container is larger than exercise
one since it uses the [aflplusplus][docker-aflplusplus] container (3.07GB
:grimacing:).

```shell
# Ensure that your current working directory is /exercises/exercise-two/
$ docker build --tag exercise-two .
... <lots of output here>
Successfully built eacb16515dd6
Successfully tagged exercise-two:latest

# Run the container. This time we are mounting a volume to persist the output.
$ docker run --interactive --tty --volume $(pwd)/output:/output exercise-two
```

## Usage

Usage is the same as [exercise one](../exercise-one).

The executable expects a file to be passed in as the first argument (`argv[1]`).
Using the executable without input will warn you of this (again, don't type the
`$`).

```shell
# Without a file, the executable prints and exits.
$ ./exercise-two
Usage: exercise-two <filename>

# With a file, the executable prints the contents of the file, and exits.
$ ./exercise-two input-one.txt
The contents of the file are: Hello world!
```

## Fuzzing

### Starting the Fuzzer

The executable to start `afl` is `afl-fuzz`. To use it, we need just a few
simple options.

- `-i` is the **input** corpus. Sometimes called **seed corpus**. This is where
  our initial test cases come from.
- `-o` is the **output** directory where the fuzzer will write new, interesting
  test cases.

That gives us the line `afl-fuzz -i ./testsuite -o ./output`

What follows is the command to run the target executable and instructions on how
to pass it input. `afl-fuzz` supports two different kinda of input. That from
`stdin` and from a file. The latter is used more often. To tell `afl-fuzz` to
pass input as a file, use the `@@` command. This gives us the following line.

```shell
afl-fuzz -i ./testsuite -o ./output ./exercise-two @@
```

Not that if you're in a container, you may have to adjust the relative or
absolute paths to the folders and executable.

### RNG

There's one last flag to be aware of for this course. Though, you typically
won't need it. Test case generation is **not** deterministic. This means that no
two fuzzing jobs will generate the same test cases, even with the same seed/s.
We can alter this by providing the `-s` options which seeds the RNG with a
known number. On my machine (an old i7 from 2014...), I was able to yield a
crash on this exercise with the included seed within 10 seconds. Hopefully you
get similar results. :grinning:

### Output

We explain the terminal-based output in the slides. Wait until you see, in bold
red, `saved crashes: 1` and/or `total crashes: ` have a positive number. The
crashing test case is in the `./output/default/crashes/` folder.

[docker-aflplusplus]:https://hub.docker.com/r/aflplusplus/aflplusplus
