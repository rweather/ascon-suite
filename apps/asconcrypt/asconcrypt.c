/*
 * Copyright (C) 2022 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#if defined(HAVE_CONFIG_H)
#include <config.h>
#endif
#include <ascon/aead.h>
#include <ascon/pbkdf2.h>
#include <ascon/random.h>
#include <ascon/siv.h>
#include <ascon/utility.h>
#include <stdio.h>
#include <string.h>
#if defined(HAVE_GETOPT_H)
#include <getopt.h>
#endif
#if defined(HAVE_ISATTY)
#include <unistd.h>
#endif
#include "fileops.h"
#include "readpass.h"

#define ASCON_PBKDF2_ROUNDS 8192

#define ASCON_BUFSIZ        BUFSIZ
#define ASCON_PWSIZ         1024

#define ASCON_MAX_FILE_SIZE (1024ULL * 1024ULL * 1024ULL * 1024ULL)

#define MODE_DECRYPT        0
#define MODE_ENCRYPT        1
#define MODE_DETECT         2
#define MODE_GENERATE       3

static char full_password[ASCON_PWSIZ];
static char confirm_password[ASCON_PWSIZ];
static char temp_filename[ASCON_BUFSIZ];

static void usage(const char *progname);
static void password_error(const char *filename);
static int generate_password(const char *keyfile);
static int read_keyfile(const char *keyfile);
static int is_encrypted_filename(const char *filename);
static const char *strip_suffix(const char *filename);
static const char *add_suffix(const char *filename, const char *suffix);
static int encrypt_file(const char *infilename, const char *outfilename);
static int decrypt_file(const char *infilename, const char *outfilename);

int main(int argc, char *argv[])
{
    const char *progname = argv[0];
    int opt_mode = MODE_DETECT;
    const char *opt_password = NULL;
    const char *opt_keyfile = NULL;
    const char *opt_output = NULL;
    int opt, posn;
    int exit_val = 0;

#if defined(HAVE_GETOPT)
    /* Process the command-line options */
    while ((opt = getopt(argc, argv, "edp:k:o:g:")) != -1) {
        switch (opt) {
        case 'e': opt_mode = MODE_ENCRYPT; break;
        case 'd': opt_mode = MODE_DECRYPT; break;
        case 'p': opt_password = optarg; break;
        case 'k': opt_keyfile = optarg; break;
        case 'o': opt_output = optarg; break;

        case 'g':
            opt_mode = MODE_GENERATE;
            opt_keyfile = optarg;
            break;

        default:
            usage(progname);
            return 1;
        }
    }
#else
    /* Simple command-line parser for systems without getopt() */
    #define GET_OPTARG(var) \
        do { \
            (var) = NULL; \
            if (opts[0] == '\0') { \
                if ((optind + 1) < argc) { \
                    (var) = argv[optind + 1]; \
                    ++optind; \
                } else { \
                    error = 1; \
                } \
            } else { \
                (var) = opts; \
                opts = ""; \
            } \
        } while (0)
    int optind = 1;
    while (optind < argc && argv[optind][0] == '-' &&
           argv[optind][1] != '\0') {
        const char *opts = argv[optind] + 1;
        while ((opt = *opts++) != '\0') {
            int error = 0;
            switch (opt) {
            case 'e': opt_mode = MODE_ENCRYPT; break;
            case 'd': opt_mode = MODE_DECRYPT; break;
            case 'p': GET_OPTARG(opt_password); break;
            case 'k': GET_OPTARG(opt_keyfile); break;
            case 'o': GET_OPTARG(opt_output); break;

            case 'g':
                opt_mode = MODE_GENERATE;
                GET_OPTARG(opt_keyfile);
                break;

            default: error = 1; break;
            }
            if (error) {
                usage(progname);
                return 1;
            }
        }
        ++optind;
    }
#endif

    /* Validate the arguments */
    if ((opt_mode == MODE_GENERATE && optind < argc) ||
            (opt_mode != MODE_GENERATE && optind >= argc)) {
        usage(progname);
        return 1;
    }
    if (opt_mode != MODE_GENERATE) {
        if (opt_password && opt_keyfile) {
            fprintf(stderr, "%s: cannot specify both -p and -k\n", progname);
            return 1;
        }
        if (opt_output && optind < (argc - 1)) {
            fprintf(stderr, "%s: only one input file allowed with -o\n", progname);
            return 1;
        }
    }

    /* Handle password file generation */
    if (opt_mode == MODE_GENERATE) {
        if (!generate_password(opt_keyfile))
            return 1;
        return 0;
    }

    /* Auto-detect encrypt vs decrypt if necessary.  If standard input is
     * supplied, then we default to encrypting it.  It is necessary to
     * specify -d to decrypt standard input. */
    if (opt_mode == MODE_DETECT) {
        int mixture = 0;
        for (posn = optind; posn < argc; ++posn) {
            if (is_encrypted_filename(argv[posn])) {
                if (opt_mode == MODE_ENCRYPT)
                    mixture = 1;
                else
                    opt_mode = MODE_DECRYPT;
            } else {
                if (opt_mode == MODE_DECRYPT)
                    mixture = 1;
                else
                    opt_mode = MODE_ENCRYPT;
            }
        }
        if (mixture) {
            /* There is a mixture of file types, so bail out */
            fprintf(stderr,
                    "%s: cannot determine direction; specify -e or -d\n",
                    progname);
            return 1;
        }
    }

    /* Acquire the password, from the command-line, a key file,
     * or by prompting the user to enter it. */
    if (opt_password) {
        if (strlen(opt_password) >= sizeof(full_password)) {
            password_error(progname);
            return 1;
        }
        strncpy(full_password, opt_password, sizeof(full_password));
        full_password[sizeof(full_password) - 1] = '\0';
    } else if (opt_keyfile) {
        if (!read_keyfile(opt_keyfile)) {
            ascon_clean(full_password, sizeof(full_password));
            return 1;
        }
    } else {
        int have_password;

#if defined(HAVE_ISATTY)
        /* Must have a real tty for stdin and stdout to prompt for a password */
        if (!isatty(0) || !isatty(1)) {
            fprintf(stderr, "%s: cannot prompt for a password without a terminal\n",
                    progname);
            return 1;
        }
#endif

        /* If we are encrypting, ask for the password twice to confirm.
         * If we are decrypting, then only ask for the password once. */
        have_password = 0;
        if (opt_mode == MODE_DECRYPT) {
            have_password = read_password
                ("Password: ", full_password, sizeof(full_password));
        } else {
            have_password = read_password
                ("Password: ", full_password, sizeof(full_password));
            if (have_password) {
                have_password = read_password
                    ("Confirm Password: ", confirm_password,
                     sizeof(confirm_password));
                if (!have_password || strcmp(full_password, confirm_password) != 0) {
                    fprintf(stderr, "%s: passwords do not match\n", progname);
                    ascon_clean(full_password, sizeof(full_password));
                    ascon_clean(confirm_password, sizeof(confirm_password));
                    return 1;
                }
            }
        }
        if (!have_password) {
            /* We don't know how to prompt for passwords, so we require that
             * the user supply the -p or -k option on the command-line. */
            ascon_clean(full_password, sizeof(full_password));
            ascon_clean(confirm_password, sizeof(confirm_password));
            usage(progname);
            return 1;
        }
    }

    /* Encrypt or decrypt the supplied files */
    for (posn = optind; posn < argc; ++posn) {
        const char *filename;
        if (!strcmp(argv[posn], "-") && !opt_output) {
            /* If we are encrypting standard input and there is no output
             * filename given, default to writing to standard output. */
            opt_output = "-";
        }
        if (opt_mode == MODE_DECRYPT) {
            if (opt_output)
                filename = opt_output;
            else if (is_encrypted_filename(argv[posn]))
                filename = strip_suffix(argv[posn]);
            else
                filename = add_suffix(argv[posn], ".decrypted");
            if (!decrypt_file(argv[posn], filename))
                exit_val = 1;
        } else {
            if (opt_output)
                filename = opt_output;
            else
                filename = add_suffix(argv[posn], ".ascon");
            if (!encrypt_file(argv[posn], filename))
                exit_val = 1;
        }
        opt_output = NULL; /* Can only use the -o option once */
    }

    /* Clean up and exit */
    ascon_clean(full_password, sizeof(full_password));
    ascon_clean(confirm_password, sizeof(confirm_password));
    return exit_val;
}

/* Print usage information for the program */
static void usage(const char *progname)
{
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: %s [-e|-d] [-p PASSWORD | -k KEYFILE] [-o OUTPUT] INPUT ...\n", progname);
    fprintf(stderr, "   or: %s -g KEYFILE\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "-e              Encrypt the file(s)\n");
    fprintf(stderr, "-d              Decrypt the file(s)\n");
    fprintf(stderr, "-p PASSWORD     Provides the password on the command-line.\n");
    fprintf(stderr, "-k KEYFILE      Provides the password via a key file.\n");
    fprintf(stderr, "-o OUTPUT       Output file to write to.\n");
    fprintf(stderr, "-g KEYFILE      Generate a random password and write it to KEYFILE.\n");
    fprintf(stderr, "\n");
}

/* Print an error for a password that is too long */
static void password_error(const char *filename)
{
    fprintf(stderr, "%s: password is too long, maximum is %d bytes\n",
            filename, ASCON_PWSIZ - 1);
}

/* Number of characters to put in a generated password */
#define DEFAULT_PASSWORD_LENGTH 40

/* Generates a random password and writes it to keyfile */
static int generate_password(const char *keyfile)
{
    /* Uses the same ASCII encoding as https://www.aescrypt.com/ */
    static char const pw_chars[] =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ%$";
    unsigned char password[DEFAULT_PASSWORD_LENGTH];
    unsigned posn;
    SAFEFILE file;

    /* Try to open keyfile before we start */
    if (!safe_file_open_write(&file, keyfile))
        return 0;

    /* Generate random bytes for the password */
    if (!ascon_random(password, sizeof(password))) {
        fprintf(stderr, "FATAL: system random number generator does not appear to be working!\n");
        safe_file_delete(&file);
        ascon_clean(password, sizeof(password));
        return 0;
    }

    /* Reduce each byte to modulo 64 and convert into ASCII.  This will throw
     * away some of the bits, but any random bit is as good as any other. */
    for (posn = 0; posn < sizeof(password); ++posn)
        password[posn] = (unsigned char)pw_chars[password[posn] & 0x3F];

    /* Write the generated password to keyfile */
    safe_file_write(&file, password, sizeof(password));
    safe_file_write(&file, "\n", 1);
    safe_file_close(&file);

    /* Clean up and exit */
    ascon_clean(password, sizeof(password));
    return 1;
}

/* Reads the password from a key file */
static int read_keyfile(const char *keyfile)
{
    SAFEFILE file;
    int len, posn;

    /* Read the contents of the key file */
    if (!safe_file_open_read(&file, keyfile))
        return 0;
    len = safe_file_read(&file, full_password, sizeof(full_password));
    safe_file_close(&file);
    if (len < 0)
        return 0;

    /* Find the end of line marker for the first line of the file */
    posn = 0;
    while (posn < len && full_password[posn] != '\n' &&
           full_password[posn] != '\r') {
        if (full_password[posn] == '\0') {
            fprintf(stderr, "%s: password value contains a NUL\n", keyfile);
            return 0;
        }
        ++posn;
    }
    if (posn >= len && len >= (int)sizeof(full_password)) {
        /* Could not find an end of line marker; password is too long */
        password_error(keyfile);
        return 0;
    }
    full_password[posn] = '\0';
    return 1;
}

/* Determine if a filename appears to be for an encrypted file */
static int is_encrypted_filename(const char *filename)
{
    size_t len = strlen(filename);
    if (len >= 6)
        return !strncmp(filename + len - 6, ".ascon", 6);
    else
        return 1;
}

/* Strips the ".ascon" suffix from a filename */
static const char *strip_suffix(const char *filename)
{
    size_t len = strlen(filename) - 6;
    if (len >= sizeof(temp_filename))
        len = sizeof(temp_filename);
    memcpy(temp_filename, filename, len);
    temp_filename[len] = '\0';
    return temp_filename;
}

/* Adds a suffix to a filename */
static const char *add_suffix(const char *filename, const char *suffix)
{
    snprintf(temp_filename, sizeof(temp_filename), "%s%s", filename, suffix);
    return temp_filename;
}

/* Bytes to be written to the header portion of the file */
struct asconcrypt_header
{
    char magic[10];             /* "ASCONcrypt" */
    unsigned char version[2];   /* Version number */
    unsigned char salt[16];     /* Salt value */
};

/* Bytes to be written to the "SIV block" portion of the file */
struct asconcrypt_siv_block
{
    unsigned char key[20];      /* Key value for the payload */
    unsigned char nonce[16];    /* Nonce value for the payload */
    unsigned char tag[16];      /* Tag value to authenticate the block */
};

/* Header plus the "SIV block" */
struct asconcrypt_full_header
{
    struct asconcrypt_header header;
    struct asconcrypt_siv_block siv;
};

/* Encrypts a file */
static int encrypt_file(const char *infilename, const char *outfilename)
{
    struct asconcrypt_header header;
    struct asconcrypt_siv_block siv;
    struct asconcrypt_siv_block siv_copy;
    unsigned char kn[20 + 16];
    int exit_val = 0;
    size_t clen = 0;
    SAFEFILE input;
    SAFEFILE output;
    ascon80pq_state_t state;
    unsigned char data[ASCON_BUFSIZ];
    uint64_t size;
    int len;

    /* Open the input and output files.  If we can't do this then
     * there is nothing we can do - bail out. */
    if (!safe_file_open_read(&input, infilename)) {
        return 0;
    }
    if (!safe_file_open_write(&output, outfilename)) {
        safe_file_close(&input);
        return 0;
    }

    /* Format the header */
    memcpy(header.magic, "ASCONcrypt", 10);
    header.version[0] = 0;
    header.version[1] = 1;

    /* Allocate the salt, key, and nonce randomly */
    memset(&siv, 0, sizeof(siv));
    if (!ascon_random(header.salt, sizeof(header.salt)) ||
            !ascon_random(siv.key, sizeof(siv.key) + sizeof(siv.nonce))) {
        fprintf(stderr, "FATAL: system random number generator does not appear to be working!\n");
        goto cleanup;
    }
    siv_copy = siv;

    /* Run PBKDF2 to derive the key and nonce to use to encrypt the SIV block */
    ascon_pbkdf2(kn, sizeof(kn),
                 (const unsigned char *)full_password, strlen(full_password),
                 header.salt, sizeof(header.salt), ASCON_PBKDF2_ROUNDS);

    /* Encrypt the SIV block and generate the tag */
    ascon80pq_siv_encrypt
        (siv.key, &clen, siv.key, sizeof(siv.key) + sizeof(siv.nonce),
         (const unsigned char *)&header, sizeof(header), kn + 20, kn);

    /* Write the header and SIV block to the output file */
    exit_val = 1;
    if (!safe_file_write(&output, &header, sizeof(header)) ||
            !safe_file_write(&output, &siv, sizeof(siv))) {
        exit_val = 0;
    }

    /* Read the input file, encrypt it, and write to the output file */
    ascon80pq_aead_start
        (&state, (const unsigned char *)&siv, sizeof(siv),
         siv_copy.nonce, siv_copy.key);
    size = 0;
    while (exit_val) {
        len = safe_file_read(&input, data, sizeof(data));
        if (len < 0) {
            exit_val = 0;
        } else if (len == 0) {
            break;
        } else {
            size += (unsigned)len;
            if (size > ASCON_MAX_FILE_SIZE) {
                fprintf(stderr, "%s: maximum file size exceeded\n", infilename);
                exit_val = 0;
                break;
            }
            ascon80pq_aead_encrypt_block(&state, data, data, len);
            if (!safe_file_write(&output, data, len))
                exit_val = 0;
            if (len < (int)sizeof(data))
                break; /* Short last block - we're done */
        }
    }
    ascon80pq_aead_encrypt_finalize(&state, data);
    if (exit_val) {
        if (!safe_file_write(&output, data, ASCON80PQ_TAG_SIZE))
            exit_val = 0;
    }

cleanup:
    /* Clean up and exit */
    safe_file_close(&input);
    safe_file_close(&output);
    ascon_clean(&header, sizeof(header));
    ascon_clean(&siv, sizeof(siv));
    ascon_clean(&siv_copy, sizeof(siv_copy));
    ascon_clean(kn, sizeof(kn));
    ascon_clean(data, sizeof(data));
    if (!exit_val)
        safe_file_delete(&output);
    return exit_val;
}

/* Decrypt a file */
static int decrypt_file(const char *infilename, const char *outfilename)
{
    struct asconcrypt_full_header header;
    struct asconcrypt_siv_block siv_copy;
    unsigned char kn[20 + 16];
    int exit_val = 0;
    size_t mlen = 0;
    int bad_format;
    SAFEFILE input;
    SAFEFILE output;
    ascon80pq_state_t state;
    unsigned char data[ASCON_BUFSIZ];
    uint64_t size;
    int len;

    /* Open the input and output files.  If we can't do this then
     * there is nothing we can do - bail out. */
    if (!safe_file_open_read(&input, infilename)) {
        return 0;
    }
    if (!safe_file_open_write(&output, outfilename)) {
        safe_file_close(&input);
        return 0;
    }

    /* Read and validate the file's header */
    bad_format = 0;
    if (safe_file_read(&input, &header, sizeof(header)) != (int)sizeof(header)) {
        bad_format = 1;
    } else {
        if (memcmp(header.header.magic, "ASCONcrypt", 10) != 0 ||
                header.header.version[0] != 0 ||
                header.header.version[1] != 1) {
            bad_format = 1;
        }
    }
    if (bad_format) {
        fprintf(stderr, "%s: unrecognized encrypted file format\n",
                infilename);
        goto cleanup;
    }

    /* Run PBKDF2 to derive the key and nonce to use to decrypt the SIV block */
    ascon_pbkdf2(kn, sizeof(kn),
                 (const unsigned char *)full_password, strlen(full_password),
                 header.header.salt, sizeof(header.header.salt),
                 ASCON_PBKDF2_ROUNDS);

    /* Decrypt the SIV block and check the tag */
    siv_copy = header.siv;
    if (ascon80pq_siv_decrypt
            (header.siv.key, &mlen, header.siv.key, sizeof(header.siv),
             (const unsigned char *)&(header.header), sizeof(header.header),
             kn + 20, kn) != 0) {
        fprintf(stderr, "%s: password is incorrect\n", infilename);
        goto cleanup;
    }

    /* We need to decrypt everything except the last 16 bytes which is the
     * authentication tag.  Pre-read the first 16 bytes and then keep 16
     * bytes in the buffer for every block until we are done. */
    if (safe_file_read(&input, data, 16) != 16) {
        fprintf(stderr, "%s: encrypted data is truncated\n", infilename);
        goto cleanup;
    }

    /* Read the input file, decrypt it, and write to the output file */
    ascon80pq_aead_start
        (&state, (const unsigned char *)&siv_copy, sizeof(siv_copy),
         header.siv.nonce, header.siv.key);
    size = 0;
    exit_val = 1;
    while (exit_val) {
        len = safe_file_read(&input, data + 16, sizeof(data) - 16);
        if (len < 0) {
            exit_val = 0;
        } else if (len == 0) {
            break;
        } else {
            size += (unsigned)len;
            if (size > ASCON_MAX_FILE_SIZE) {
                fprintf(stderr, "%s: maximum file size exceeded\n", infilename);
                exit_val = 0;
                break;
            }
            ascon80pq_aead_decrypt_block(&state, data, data, len);
            if (!safe_file_write(&output, data, len))
                exit_val = 0;
            memmove(data, data + len, 16);
            if (len < (int)(sizeof(data) - 16))
                break; /* Short last block - we're done */
        }
    }
    if (ascon80pq_aead_decrypt_finalize(&state, data) != 0 && exit_val) {
        exit_val = 0;
        fprintf(stderr, "%s: file is corrupt and failed to decrypt\n",
                infilename);
        goto cleanup;
    }

cleanup:
    /* Clean up and exit */
    safe_file_close(&input);
    safe_file_close(&output);
    ascon_clean(&header, sizeof(header));
    ascon_clean(&siv_copy, sizeof(siv_copy));
    ascon_clean(kn, sizeof(kn));
    ascon_clean(data, sizeof(data));
    if (!exit_val)
        safe_file_delete(&output);
    return exit_val;
}
