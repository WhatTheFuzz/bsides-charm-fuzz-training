FROM aflplusplus/aflplusplus as COMPILE

RUN mkdir /exercise-six

COPY Makefile only_fuzzbuf.c no_defer_no_persist.c  persist_and_defer.c  persist_no_defer.c /exercise-six/

WORKDIR /exercise-six

RUN make

# prep the env for fuzzing
RUN mkdir /exercise-six/in && \
    mkdir /exercise-six/out

COPY testfuzz_in /exercise-six/in/testfuzz_in