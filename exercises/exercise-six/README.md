# Exercise 5: Exploring Persistent Mode and Deferred Initialization with AFL++
This exercise serves as an introduction to AFL++'s persistent mode and deferred initialization features.

# Objectives
Utilize the provided src.c to gain a deeper understanding of AFL++'s deferred initialization and persistent mode options. You can find more information on both modes in the [AFL++ documentation](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md).

While experimenting with the code, remove the components responsible for persistent mode and deferred initialization one at a time. Observe and analyze the impact of these changes on fuzzing speeds.

# Overview
In this exercise, we will explore two key concepts in AFL++: [persistent mode](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md#4-persistent-mode) and [deferred initialization](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md#3-deferred-initialization). 

# Persistent Mode
Persistent mode enables the fuzzer to run the target program multiple times without restarting the program.

## Key Symbols
Take note of the following compiler-introduced symbols (introduced in afl-clang-fast and afl-clang-lto) that are essential for the implementation of persistent mode:

`__AFL_FUZZ_TESTCASE_BUF`: The buffer containing the testcase data

`__AFL_FUZZ_TESTCASE_LEN`: The length of the `__AFL_FUZZ_TESTCASE_BUF` buffer

`__AFL_FUZZ_INIT`: Sets up the `__afl_fuzz_ptr` and `__afl_fuzz_len` variables (which will be used for `__AFL_FUZZ_TESTCASE_BUF` and `__AFL_FUZZ_TESTCASE_LEN`, respectively)

`__AFL_LOOP`: This sets up the loop to run multiple times when the binary is executed through AFL++.

# Deferred Initialization
Deferred initialization allows AFL++ to fork the target program at a specific point in the program. This is particularly useful for programs with long startup times when you wish to fuzz a function called after the startup process.

## Key Symbols
`__AFL_INIT`: Specifies the location in the binary at which AFL++ will fork. This function is the hallmark of "deferred initialization." Normally, AFL++ forks right before the call to main, but with `__AFL_INIT`, you can designate a different location for forking.

# Results

## `no_defer_no_persist`
Run with: `afl-fuzz -i in -o out -- ./no_defer_no_persist @@`

Fuzzing speed: Approximately 3-4k execs/sec

## `only_fuzzbuf`
Run with: `afl-fuzz -i in -o out -- ./only_fuzzbuf`

Fuzzing speed: Approximately 7k execs/sec

## `persist_no_defer`
Run with: `afl-fuzz -i in -o out -- ./persist_no_defer`

Fuzzing speed: Approximately 45-47k execs/sec

## `persist_and_defer`
Run with: `afl-fuzz -i in -o out -- ./persist_and_defer`

Fuzzing speed: Approximately 45-47k execs/sec