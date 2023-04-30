FROM aflplusplus/aflplusplus as COMPILE

# Copy the exercise file over.
COPY . /exercise-four/.

# Change working directory to the exercise.
WORKDIR /exercise-four/

# Compile the exercise.
RUN make

# Auto resume fuzzing
ENV AFL_AUTORESUME=1

# Fuzz the program.
CMD ["afl-fuzz", "-s", "1337", \
                 "-i", "/exercise-four/testsuite", \
                 "-o", "/output", \
                 "/exercise-four/mantohtml/mantohtml", "@@" \
]
