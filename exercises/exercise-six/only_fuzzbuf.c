#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

int main(int argc, char ** argv){
    char textbuf[30];
    pid_t pid = getpid();

    unsigned char *fuzzbuf= __AFL_FUZZ_TESTCASE_BUF;
    FILE *file = fopen("/tmp/output.txt", "a");
    sprintf(textbuf, "process %i\n", pid);
    fputs(textbuf, file);
    fputs(fuzzbuf, file);
    fputs("___input_end___\n", file);
    fclose(file);

    return 0;
}
