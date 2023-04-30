# TODO, add the evironment variable that will compile the program with ASAN.
ENABLE_ASAN = # TODO
# TODO, compile as a 32-bit binary.
32_BIT = # TODO
CC = afl-gcc-fast
CFLAGS = $(32_BIT) -Og -ggdb -fno-omit-frame-pointer -fno-inline-functions -fno-stack-protector -z execstack

.PHONY: exercise-four

exercise-four:
	cd ./mantohtml && \
	sed -i 's/^CC.*/CC\t=\t$(CC)/g' Makefile && \
	sed -i 's/^CFLAGS.*/CFLAGS\t=\t$(CFLAGS) \x27-DVERSION="2.0"\x27/g' Makefile && \
	sed -i 's/^TARGETS.*/TARGETS\t=\tmantohtml/g' Makefile && \
	sed -i 's/^LDFLAGS.*/LDFLAGS\t=\t$(32_BIT)/g' Makefile && \
	$(ENABLE_ASAN) make && \
	echo "[+] Done compiling mantohtml." && \
	file ./mantohtml

clean:
	cd ./mantohtml && \
	git clean -xfd
