CC = afl-clang-fast
override CFLAGS += "-Og -ggdb -fno-omit-frame-pointer -fno-inline-functions -fno-stack-protector -z execstack"

.PHONY: exercise-three

exercise-three:
	cd ./crasm && \
	CC=$(CC) CFLAGS=$(CFLAGS) make && \
	echo "[+] Done compiling crasm." && \
	file ./src/crasm

clean:
	cd ./crasm && \
	git clean -xfd
