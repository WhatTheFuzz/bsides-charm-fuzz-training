FROM ubuntu:22.04 as COMPILE

# Install everything necessary to compile the target.
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y \
    build-essential \
    clang \
    file

# Copy the exercise file over.
COPY . /exercise-one/.

# Change working directory to the exercise.
WORKDIR /exercise-one/

# Compile the exercise.
RUN make
