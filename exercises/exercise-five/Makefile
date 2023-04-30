CC = afl-gcc-fast
CXX = afl-g++-fast
CFLAGS = -O3 -fno-omit-frame-pointer -fno-inline-functions -fno-stack-protector
LDFLAGS = -L/exercise-six/openssl -l:libcrypto.so.3 -l:libcrypto.a
INCLUDE = -I/exercise-six/openssl/include

.DEFAULT_GOAL := harness

# What we'll actually use for fuzzing.
harness: harness.c
	AFL_USE_ASAN=1 $(CC) -o $@ $< $(CFLAGS) $(INCLUDE) $(LDFLAGS)

# Confirm that the vulnerability is present.
confirm-vulnerability: confirm-vulnerability.c
	AFL_USE_ASAN=1 $(CC) -o $@ $< $(CFLAGS) $(INCLUDE) $(LDFLAGS)

clean:
	rm -f harness
	rm -f confirm-vulnerability
