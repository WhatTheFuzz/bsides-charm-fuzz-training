/* TODO: Modify the call to ossl_a2ulabel marked with the parameters TODO. 
** Your harness should fuzz the first parameter to the function. 
** A successful harness will compile and reach a crash < 1 minute
** with the provided test cases and ASAN enabled. */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* From punycode test. See link below.
** https://github.com/openssl/openssl/commit/a0af4a3c8b18c435a5a4afb28b3ad1a2730e6ea8#diff-83399d92c96bb1f4616b5c6f090053b95834cdbc7bb37bb0d835d1555f69e8ad
*/
#include <openssl/crypto.h>
#include <string.h>

#include "crypto/punycode.h"
#include "internal/nelem.h"

/* This is from crypto/punycode.c
** Why not the header? I dunno. */
#define LABEL_BUF_SIZE 512

__AFL_FUZZ_INIT();

int main(int argc, char ** argv){

    int fd;
    struct stat stat;
    int result;
    char *buf;


    /* Call the function we want to test. */
    char ulabel[256];
    size_t size = sizeof(ulabel) - 1;
    memset(ulabel, 0, sizeof(ulabel));
    /* TODO: Fill in the arguments of ossl_a2ulabel.
    ** Hint: You might find a great example at the verrrrryyyyy tail end of:
    ** openssl/crpyto/punycode.c */
    __AFL_INIT();
    buf = __AFL_FUZZ_TESTCASE_BUF; 
    while(__AFL_LOOP(10000)){
        result = ossl_a2ulabel(buf, ulabel, &size);
        printf("ossl_a2ulabel returned: %d\n", result);
    }


    /* Exit the program. */
    return result;
}
