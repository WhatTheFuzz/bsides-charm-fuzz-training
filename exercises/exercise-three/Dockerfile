FROM aflplusplus/aflplusplus as COMPILE

# Copy the exercise file over.
COPY . /exercise-three/.

# Change working directory to the exercise.
WORKDIR /exercise-three/

# Compile the exercise.
RUN make

# Syntax to run the target executable in Docker.
# I've commented it out becuase I want students to get comfortable with the
# syntax before including it as a the entrypoint command.

# The exercise calls for different experiements. The first one, we'll do without
# a dictionary.
# CMD ["afl-fuzz", "-s", "1337", \
#                  "-i", "/exercise-three/testsuite", \
#                  "-o", "/output", \
#                  "/exercise-three/crasm/src/crasm", "@@" \
# ]

# Now with the dictionary.
# Note the difference here is the addition of the dictionary file with -x
# CMD ["afl-fuzz", "-s", "1337", \
#                  "-i", "/exercise-three/testsuite", \
#                  "-o", "/output", \
#                  "-x", "/exercise-three/dictionary/dictionary.txt", \
#                  "/exercise-three/crasm/src/crasm", "@@" \
# ]
