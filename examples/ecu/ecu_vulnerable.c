/* Intentionally vulnerable standalone training fixture.
 * Run only in a controlled local sanitizer harness. */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char small_frame[8];
    strcpy(small_frame, argv[1]);  /* CWE-120 candidate: no bounds check */
    printf("%u\n", (unsigned)(unsigned char)small_frame[0]);
    return 0;
}
