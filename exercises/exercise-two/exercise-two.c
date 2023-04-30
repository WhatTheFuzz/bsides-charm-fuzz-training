/* Exercise One.
**
** This program reads a file and checks the contents.
**
** Compile with clang or gcc like so:
** cc -o exercise-one exercise-one.c
**
** Usage:
** ./exercise-one <filename>
*/

#include <sys/types.h>  /* For open */
#include <sys/stat.h>   /* For open */
#include <fcntl.h>      /* For open */
#include <stdlib.h>     /* For abort */
#include <string.h>     /* For strcmp */
#include <unistd.h>     /* For read */
#include <stdio.h>      /* For fprintf */

#define BUFSIZE 64

int main(int argc, char ** argv) {

    /* Declare a file descriptor to read from. */
    int fd;
    /* Declare a buffer on the stack. We will read data to this buffer. */
    char buf[BUFSIZE];

    /* Check how many arguments are on the command line. */
    if (argc != 2){
        fprintf(stderr, "Usage: exercise-one <filename>\n");
        return EXIT_FAILURE;
    }

    /* Open the file. */
    fd = open(argv[1], O_RDONLY);
    /* Check if the file was opened successfully. */
    if (fd == -1){
        fprintf(stderr, "Could not open file %s.\n", argv[1]);
        return EXIT_FAILURE;
    }

    /* Read data from the file. */
    if (read(fd, buf, BUFSIZE-1) == -1) { /* Sus. */
        fprintf(stderr, "Could not read from file %s.\n", argv[1]);
        return EXIT_FAILURE;
    }

    /* Close the file. */
    if (close(fd) != 0) {
        fprintf(stderr, "Could not close file %s.\n", argv[1]);
        return EXIT_FAILURE;
    }

    printf("The contents of the file are: %s\n", buf);

    /* Check the contents of the file. */
    if (strncmp(buf, "b", sizeof(char)) == 0) {
        fprintf(stderr, "Hmm, how did you get here?\n");
        if (strncmp(buf+1, "u", sizeof(char)) == 0) {
            fprintf(stderr, "Something isn't right.\n");
            if (strncmp(buf+2, "g", sizeof(char)) == 0) {
                fprintf(stderr, "Found a bug.\n");
                abort();
            }
        }
    }
    return EXIT_SUCCESS;
}