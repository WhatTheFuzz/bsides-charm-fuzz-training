CC := afl-clang-lto
CFLAGS := -Og -ggdb
OBJ := only_fuzzbuf persist_and_defer persist_no_defer no_defer_no_persist
SRC := $(OBJ:=.c)
PREPROC := $(OBJ:=_preproc.c)

all: $(OBJ) $(PREPROC)

%: %.c
	$(CC) $(CFLAGS) $< -o $@

%_preproc.c: %.c
	$(CC) $(CFLAGS) -E $< -o $@