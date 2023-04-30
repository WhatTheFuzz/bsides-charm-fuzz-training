# An Introduction to Fuzzing

## Description

Fuzzing is still one of the leading methods for finding vulnerabilities in
applications. And it doesn't have to be hard. This course gives both a
high-level overview on the theory of fuzz testing as well as concrete practical
exercises to apply essential concepts. Students will learn how to fuzz
real-world applications to uncover actual software vulnerabilities in
applications still shipped in 2023. The four exercises progressively showcase
the power of modern fuzzing solutions, to include corpus management,
dictionaries, fuzzing emulated targets, and coverage maps.

## Course Objectives

- Students conceptually understand the meaning of fuzz testing (fuzzing).
- Students understand the history of fuzzing.
- Students can instrument targets when source code is available with the AFL
  compilers.
- Students understand address sanitization.
- Students can fuzz an instrumented application.
- Students can generate a sample corpus as input for the fuzzer.
- Students can generate a dictionary as input for the fuzzer.
- Students can generate and understand coverage metrics.
- Students understand the different types of coverage metrics (ie. line, block,
  branch).
- Students understand different types of fuzzers and the benefits of each.

## Course Schedule

- Discussion the theory of fuzzing.
  - What is AFL++?
- Exercise One (Crashing Input)
  - What is a segmentation fault?
  - Manually passing in bad input.
- Exercise Two (Fuzzing with a Seed)
  - Fuzzing a contrived C application, host architecture.
  - Discuss instrumentation.
  - Selecting a good corpus.
  - Triage crashes.
  - Test case minimization.
- Exercise Three (Fuzzing with a Dictionary)
  - Fuzzing a real-world C application, host architecture.
  - Creating a dictionary.
  - Compare two fuzzing jobs, with and without a dictionary.
  - Collecting coverage results.
  - Repeat with address sanitization. What are the differences?
- Exercise Four (TODO)
  - Fuzzing a cross-architecture C application with QEMU mode.
  - Discuss implementation and downsides of native-host fuzzing.
- Exercise Five (TODO)
  - Fuzzing Python applications.
  - Compare differences to memory-unsafe and compiled languages.

Students might not complete every exercise. And that's OK! All of the exercises
are included as Docker containers on GitHub so students can always revisit
missed topics.

## Prerequisites

- An understanding of C and compilation.
- Working knowledge of git and how to clone repositories.
- An understanding of Docker is helpful, though not necessary, as all of the
  exercises are included as Docker containers.
- Without Docker, students are encouraged to
  [build AFL++ on their host][install] before the class.
- Instructors can troubleshoot issues on Linux and macOS, though Windows should
  work especially when using Docker.

## Instructors

### Sean Deaton

Sean is an alumnus of the United States Military Academy (B.S. 2017) and Georgia
Tech (M.S. 2021), where he studied Computer Science. After commissioning as a
Cyber Officer in the U.S. Army, Sean served as a developer with the 780th MI
BDE. He now works as a vulnerability researcher for Blue Star and Bogart
Associates, with particular interests in fuzzing, data flow analysis, and
decompilation theory.

When he’s not finding bugs or working on training material, he spends his time
at the dog park trying to burn off his corgi’s seemingly unlimited energy.

### Ryan O'Neal

Ryan O'Neal is a vulnerability researcher employed by the US Army. His research
focuses on static analysis, symbolic execution and fuzzing, and he draws upon
his experience as a web developer, cloud application developer and devops
engineer to create innovative solutions. His passion is discovering and
developing new techniques to address difficult questions in program security.

# Ideas

- Coverage map with Ghidra or Binary Ninja.
- Start with crasm, progress upwards to afl-qemu or afl-unicorn.
- ASAN
- Docker containers

## Exercises

### Exercise One

- Fuzzing an instrumented target (crasm). No dictionary. Have a starting corpus.

### Exercise Two

- Fuzzing an instrumented target (aspic) with a dictionary and a starting
corpus.
- Compare the speed at which test cases are generated with and without a
dictionary.
- Re-instrument with ASAN and see how many more crashes we get.

[install]:
https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/INSTALL.md
