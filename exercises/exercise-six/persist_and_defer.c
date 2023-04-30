#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

int main(int argc, char ** argv){
    FILE* ff = fopen("/tmp/output.txt", "a");
    pid_t pre_init_pid = getpid();
    char initial_write_buf[40];
    sprintf(initial_write_buf, "__HELLO__ from process %d\n", pre_init_pid);
    fputs(initial_write_buf, ff);
    fclose(ff);

    __AFL_INIT();
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
