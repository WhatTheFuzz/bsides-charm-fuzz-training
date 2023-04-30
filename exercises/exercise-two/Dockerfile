FROM aflplusplus/aflplusplus as COMPILE

# Copy the exercise file over.
COPY . /exercise-two/.

# Change working directory to the exercise.
WORKDIR /exercise-two/

# Compile the exercise.
RUN make

# Syntax to run the target executable in Docker.
# I've commented it out becuase I want students to get comfortable with the
# syntax before including it as a the entrypoint command.
# CMD ["afl-fuzz", "-s", "1337", "-i", "/exercise-two/testsuite", "-o", "/output", "/exercise-two/exercise-two", "@@"]
