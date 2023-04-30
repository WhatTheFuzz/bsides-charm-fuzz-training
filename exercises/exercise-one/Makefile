override CFLAGS += -Og -ggdb -fno-omit-frame-pointer -fno-inline-functions -fno-stack-protector

exercise-one: exercise-one.c
	$(CC) $(CFLAGS) -o $@ $^
	@echo "--"
	@file $@

clean:
	rm -f exercise-one