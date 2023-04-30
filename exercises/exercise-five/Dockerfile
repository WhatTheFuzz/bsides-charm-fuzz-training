FROM aflplusplus/aflplusplus as COMPILE

# Copy the exercise file over.
COPY ./openssl /exercise-six/openssl/

# Change working directory to the exercise.
WORKDIR /exercise-six/

# Compile OpenSSL.
# We do this in the build process because I don't want students to have to recompile
# each time the harness changes.
RUN cd openssl/ && \
    AFL_USE_ASAN=1 CC=afl-gcc-fast CXX=afl-gcc++-fast ./Configure && \
    AFL_USE_ASAN=1 CC=afl-gcc-fast CXX=afl-gcc++-fast  make --jobs `nproc`

# Copy the harness and Makefile.
COPY ./harness.c /exercise-six/
COPY ./Makefile /exercise-six/
COPY ./testsuite /exercise-six/testsuite

# Compile the harness.
RUN make harness

# Add openssl to the library path.
ENV LD_LIBRARY_PATH=/exercise-six/openssl/

# Auto resume fuzzing
ENV AFL_AUTORESUME=1

# Fuzz the program.
CMD ["afl-fuzz", "-s", "1337", \
                 "-i", "/exercise-six/testsuite", \
                 "-o", "/output", \
                 "/exercise-six/harness", "@@" \
]
