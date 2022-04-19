
/*
 * This example demonstrates how to implement ASCON-HASHA using
 * just the ASCON permutation API.
 *
 * This example is placed into the public domain.
 */

#include <ascon/permutation.h>
#include <ascon/hash.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    const unsigned char *data;
    size_t len, posn;

    /* Validate the command-line parameters */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s \"string\"\n", argv[0]);
        return 1;
    }
    data = (const unsigned char *)(argv[1]);
    len = strlen(argv[1]);

    /* Initialize the ASCON permutation state */
    ascon_state_t state;
    ascon_init(&state);

    /* Set the ASCON-HASHA initialization vector and permute for 12 rounds */
    static unsigned char const iv[8] = {
        0x00, 0x40, 0x0c, 0x04, 0x00, 0x00, 0x01, 0x00
    };
    ascon_add_bytes(&state, iv, 0, 8);
    ascon_permute12(&state);

    /* Absorb the data 8 bytes at a time.  Permute each block with 8 rounds */
    for (posn = 0; (posn + 8) <= len; posn += 8) {
        ascon_add_bytes(&state, data + posn, 0, 8);
        ascon_permute8(&state);
    }

    /* Absorb and pad the last block.  Use 12 permutation rounds when
     * transitioning from absorbing to squeezing. */
    static unsigned char const pad[1] = {0x80};
    ascon_add_bytes(&state, data + posn, 0, len - posn);
    ascon_add_bytes(&state, pad, len - posn, 1);
    ascon_permute12(&state);

    /* Squeeze out the 32-byte hash value, 8 bytes at a time */
    unsigned char hash[32];
    for (posn = 0; posn < 24; posn += 8) {
        ascon_extract_bytes(&state, hash + posn, 0, 8);
        ascon_permute8(&state);
    }
    ascon_extract_bytes(&state, hash + posn, 0, 8);

    /* Free the resources associated with the ASCON permutation state */
    ascon_free(&state);

    /* Print the final hash value */
    for (posn = 0; posn < 32; ++posn)
        printf("%02x", hash[posn]);
    printf("\n");

    /* Cross-check with the library's version of ASCON-HASHA */
    unsigned char hash2[32];
    ascon_hasha(hash2, data, len);
    if (memcmp(hash, hash2, 32) != 0) {
        printf("Hash value is incorrect!");
        return 1;
    }
    return 0;
}
