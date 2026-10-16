/* Remediated standalone training fixture (same input contract). */
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char small_frame[8];
    size_t n = strlen(argv[1]);
    if (n >= sizeof small_frame) {
        fputs("frame length rejected\n", stderr);
        return 3;
    }
    memcpy(small_frame, argv[1], n + 1);
    printf("%u\n", (unsigned)(unsigned char)small_frame[0]);
    return 0;
}
