CC = afl-clang-fast
override CFLAGS += -Og -ggdb -fno-omit-frame-pointer -fno-inline-functions -fno-stack-protector

exercise-two: exercise-two.c
	$(CC) $(CFLAGS) -o $@ $^
	@echo "--"
	@file $@

clean:
	rm -f exercise-two
	@echo "Cleaning out output directory."
	rm -rf ./output/default/