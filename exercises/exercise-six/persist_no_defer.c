#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

int main(int argc, char ** argv){
    int counter = 0;
    char textbuf[30];
    pid_t pid = getpid();

    unsigned char *fuzzbuf= __AFL_FUZZ_TESTCASE_BUF;
    FILE *file = fopen("/tmp/output.txt", "a");
    while(__AFL_LOOP(100)){
        sprintf(textbuf, "iteration %i in process %i\n", counter, pid);
        fputs(textbuf, file);
        fputs(fuzzbuf, file);
        fputs("___input_end___\n", file);
        counter++;
    }

    fputs("__END_AFL_LOOP__\n", file);
    fclose(file);

    return 0;
}
