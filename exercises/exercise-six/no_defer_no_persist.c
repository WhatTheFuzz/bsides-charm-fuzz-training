#include <stdio.h>  // sprintf
#include <stdlib.h>  // EXIT_FAILURE
#include <unistd.h> // getpid
#include <fcntl.h> // open

int main(int argc, char ** argv){
    char * fuzz_filename = argv[1];

    FILE *fd = fopen(argv[1], "r");
    /* Check if the file was opened successfully. */
    if (fd == NULL){
        fprintf(stderr, "Could not open file %s.\n", argv[1]);
        return EXIT_FAILURE;
    }

    fseek(fd, 0, SEEK_END);
    long size = ftell(fd);
    char fuzzbuf[size];

    fseek(fd, 0, SEEK_SET);

    /* Read data from the file. */
    if (fread(fuzzbuf, 1, size, fd) == 0) { 
        fprintf(stderr, "Could not read from file %s.\n", argv[1]);
        return EXIT_FAILURE;
    }

    /* Close the file. */
    if (fclose(fd) != 0) {
        fprintf(stderr, "Could not close file %s.\n", argv[1]);
        return EXIT_FAILURE;
    }

    int counter = 0;
    char textbuf[30];
    pid_t pid = getpid();

    FILE *file = fopen("/tmp/output.txt", "a");
    sprintf(textbuf, "in process %i\n", pid);
    fputs(textbuf, file);
    fputs(fuzzbuf, file);
    fputs("___input_end___\n", file);
    fclose(file);

    return 0;
}
