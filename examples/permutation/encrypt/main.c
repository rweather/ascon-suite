
/*
 * This example demonstrates how to implement a simple encryption scheme
 * by operating the ASCON permutation in a Cipher FeedBack (CFB) like mode.
 *
 *      encrypt "password" plaintext-file ciphertext-file
 *      encrypt -d "password" ciphertext-file plaintext-file2
 *
 * The input and output files will be the same size.
 *
 * Note: This isn't a very good way to do encryption.  No authentication is
 * provided so it is impossible to know if the contents are correct when the
 * file is decrypted.  If the wrong password is supplied, the ciphertext
 * will decrypt to garbage.  The password is also hashed in a very simple way
 * without any salting or repeated hashing steps.  Don't use this method for
 * real work - it is just an example.
 *
 * This example is placed into the public domain.
 */

#include <ascon/permutation.h>
#include <ascon/hash.h>
#include <ascon/utility.h>
#include <stdio.h>
#include <string.h>

/* Encrypts a block of data */
static void encrypt(ascon_state_t *state, unsigned char *c,
                    const unsigned char *m, int len)
{
    int posn;

    /* Process as many full 16 byte chunks as possible */
    for (posn = 0; (posn + 16) <= len; posn += 16) {
        ascon_add_bytes(state, m + posn, 0, 16);
        ascon_extract_bytes(state, c + posn, 0, 16);
        ascon_permute8(state);
    }

    /* Process the left-over short chunk */
    if (posn < len) {
        ascon_add_bytes(state, m + posn, 0, len - posn);
        ascon_extract_bytes(state, c + posn, 0, len - posn);
        ascon_permute8(state);
    }
}

/* Decrypts a block of data */
static void decrypt(ascon_state_t *state, unsigned char *m,
                    const unsigned char *c, int len)
{
    int posn;

    /* Process as many full 16 byte chunks as possible */
    for (posn = 0; (posn + 16) <= len; posn += 16) {
        ascon_extract_and_overwrite_bytes(state, c + posn, m + posn, 0, 16);
        ascon_permute8(state);
    }

    /* Process the left-over short chunk */
    if (posn < len) {
        ascon_extract_and_overwrite_bytes(state, c + posn, m + posn, 0, len - posn);
        ascon_permute8(state);
    }
}

int main(int argc, char *argv[])
{
    const char *progname = argv[0];
    unsigned char buffer[1024];
    unsigned char key[32];
    int encrypt_mode = 1;
    FILE *infile;
    FILE *outfile;
    int len;

    /* Validate the command-line parameters */
    if (argc >= 2 && !strcmp(argv[1], "-d")) {
        encrypt_mode = 0;
        ++argv;
        --argc;
    }
    if (argc < 4) {
        fprintf(stderr, "Usage: %s [-d] \"password\" input-file output-file\n", progname);
        return 1;
    }

    /* Open the input and output files */
    if ((infile = fopen(argv[2], "rb")) == NULL) {
        perror(argv[1]);
        return 1;
    }
    if ((outfile = fopen(argv[3], "wb")) == NULL) {
        perror(argv[2]);
        fclose(infile);
        return 1;
    }

    /* Hash the password argument to produce a 32-byte key value.  This is
     * actually a 16-byte key concatenated with a 16-byte nonce. */
    ascon_hash(key, (const unsigned char *)(argv[1]), strlen(argv[1]));

    /* Initialize the ASCON permutation state with the IV and key */
    static unsigned char const iv[8] = {
        0x80, 0x40, 0x0c, 0x08, 0xFF, 0xFF, 0xFF, 0xFF
    };
    ascon_state_t state;
    ascon_init(&state);
    ascon_overwrite_bytes(&state, iv, 0, 8);
    ascon_overwrite_bytes(&state, key, 8, 32);
    ascon_permute12(&state);

    /* Read the input block by block and encrypt or decrypt it */
    while ((len = fread(buffer, 1, sizeof(buffer), infile)) > 0) {
        /* Encrypt or decrypt the block */
        if (encrypt_mode)
            encrypt(&state, buffer, buffer, len);
        else
            decrypt(&state, buffer, buffer, len);

        /* Write the processed data to the output file */
        fwrite(buffer, 1, len, outfile);

        /* Break out if this is the last (short) block */
        if (len < (int)sizeof(buffer))
            break;
    }

    /* Clean up and exit */
    ascon_free(&state);
    ascon_clean(buffer, sizeof(buffer));
    ascon_clean(key, sizeof(key));
    fclose(infile);
    fclose(outfile);
    return 0;
}
