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
#include <ascon/hash.h>
#include <stdio.h>
#include <string.h>
#if defined(HAVE_GETOPT_H)
#include <getopt.h>
#endif

#define ASCON_BUFSIZ    BUFSIZ
#define ASCON_LINESIZ   1024

#define ALG_ASCON_HASH  0
#define ALG_ASCON_HASHA 1

static void usage(const char *progname);
static int hash_file(const char *filename, int algorithm);
static int check_file(const char *filename, int algorithm);

int main(int argc, char *argv[])
{
    const char *progname = argv[0];
    int algorithm = ALG_ASCON_HASH;
    int check_mode = 0;
    int opt, index;
    int exit_val = 0;

#if defined(HAVE_GETOPT)
    /* Process the command-line options */
    while ((opt = getopt(argc, argv, "ac")) != -1) {
        switch (opt) {
        case 'a': algorithm = ALG_ASCON_HASHA; break;
        case 'c': check_mode = 1; break;
        default:
            usage(progname);
            return 1;
        }
    }
#else
    /* Simple command-line parser for systems without getopt() */
    int optind = 1;
    while (optind < argc && argv[optind][0] == '-' &&
           argv[optind][1] != '\0') {
        const char *opts = argv[optind] + 1;
        while ((opt = *opts++) != '\0') {
            switch (opt) {
            case 'a': algorithm = ALG_ASCON_HASHA; break;
            case 'c': check_mode = 1; break;
            default:
                usage(progname);
                return 1;
            }
        }
        ++optind;
    }
#endif

    /* Process all of the files on the command-line (stdin if no files) */
    if (optind < argc) {
        for (index = optind; index < argc; ++index) {
            if (check_mode) {
                if (!check_file(argv[index], algorithm))
                    exit_val = 1;
            } else {
                if (!hash_file(argv[index], algorithm))
                    exit_val = 1;
            }
        }
    } else if (check_mode) {
        if (!check_file("-", algorithm))
            exit_val = 1;
    } else {
        if (!hash_file("-", algorithm))
            exit_val = 1;
    }
    return exit_val;
}

/* Print usage information for the program */
static void usage(const char *progname)
{
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: %s [-a] [-c] FILE ...\n", progname);
    fprintf(stderr, "\n");
    fprintf(stderr, "-a  Selects ASCON-HASHA instead of ASCON-HASH.\n");
    fprintf(stderr, "-c  Read checksums from a file and checks them.\n");
    fprintf(stderr, "\n");
}

/* Hashes the contents of a file with ASCON-HASH */
static int ascon_hash_file
    (const char *filename, FILE *file, unsigned char hash[ASCON_HASH_SIZE])
{
    unsigned char buffer[ASCON_BUFSIZ];
    int len, ok;
    ascon_hash_state_t state;
    ascon_hash_init(&state);
    while ((len = fread(buffer, 1, ASCON_BUFSIZ, file)) == ASCON_BUFSIZ) {
        ascon_hash_update(&state, buffer, len);
    }
    ok = !ferror(file);
    if (!ok) {
        perror(filename);
    }
    if (len > 0) {
        ascon_hash_update(&state, buffer, len);
    }
    ascon_hash_finalize(&state, hash);
    ascon_hash_free(&state);
    return ok;
}

/* Hashes the contents of a file with ASCON-HASHA */
static int ascon_hasha_file
    (const char *filename, FILE *file, unsigned char hash[ASCON_HASH_SIZE])
{
    unsigned char buffer[ASCON_BUFSIZ];
    int len, ok;
    ascon_hasha_state_t state;
    ascon_hasha_init(&state);
    while ((len = fread(buffer, 1, ASCON_BUFSIZ, file)) == ASCON_BUFSIZ) {
        ascon_hasha_update(&state, buffer, len);
    }
    ok = !ferror(file);
    if (!ok) {
        perror(filename);
    }
    if (len > 0) {
        ascon_hasha_update(&state, buffer, len);
    }
    ascon_hasha_finalize(&state, hash);
    ascon_hasha_free(&state);
    return ok;
}

static int hash_file(const char *filename, int algorithm)
{
    unsigned char hash[ASCON_HASH_SIZE] = {0};
    FILE *file;
    int ok;

    /* Open the file to be hashed */
    if (!strcmp(filename, "-")) {
        file = stdin;
    } else if ((file = fopen(filename, "rb")) == NULL) {
        perror(filename);
        return 0;
    }

    /* Hash the contents of the file with the selected algorithm */
    if (algorithm == ALG_ASCON_HASHA)
        ok = ascon_hasha_file(filename, file, hash);
    else
        ok = ascon_hash_file(filename, file, hash);

    /* Close the file */
    if (strcmp(filename, "-") != 0) {
        fclose(file);
    }

    /* Print the hash value if no errors occurred */
    if (ok) {
        int posn;
        for (posn = 0; posn < ASCON_HASH_SIZE; ++posn)
            printf("%02x", hash[posn]);
        printf("  %s\n", filename);
    }
    return ok;
}

static int to_hex_digit(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    else if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    else if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    else
        return -1;
}

static int check_file(const char *filename, int algorithm)
{
    char line[ASCON_LINESIZ];
    size_t len, posn, hashlen;
    unsigned char hash[ASCON_HASH_SIZE] = {0};
    unsigned char hash2[ASCON_HASH_SIZE] = {0};
    const char *check_filename;
    FILE *file;
    FILE *file2;
    int ok = 1;
    int file_ok;
    int hex1, hex2;
    int found = 0;
    int format_errors = 0;
    int mismatch_errors = 0;
    int read_errors = 0;

    /* Open the file to be hashed */
    if (!strcmp(filename, "-")) {
        file = stdin;
    } else if ((file = fopen(filename, "r")) == NULL) {
        perror(filename);
        return 0;
    }

    /* Read checksums and filenames from the file */
    while (fgets(line, sizeof(line), file)) {
        /* LF and CR characters from from the end of the line */
        len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            --len;
        if (!len)
            continue; /* Ignore empty lines */
        line[len] = '\0';

        /* Parse the line into a hash value and a filename */
        hashlen = 0;
        posn = 0;
        while (posn < len && hashlen < ASCON_HASH_SIZE &&
               (hex1 = to_hex_digit(line[posn])) >= 0 &&
               (hex2 = to_hex_digit(line[posn + 1])) >= 0) {
            hash[hashlen++] = (unsigned char)(hex1 * 16 + hex2);
            posn += 2;
        }
        if (line[posn] != ' ' || hashlen != ASCON_HASH_SIZE) {
            /* Malformed input */
            ++format_errors;
            continue;
        }
        while (line[posn] == ' ') {
            ++posn;
        }
        if (line[posn] == '\0') {
            /* Missing filename - malformed input */
            ++format_errors;
            continue;
        }
        check_filename = line + posn;
        found = 1;

        /* Cannot check stdin if we are reading checksums from stdin */
        if (!strcmp(check_filename, "-") && !strcmp(filename, "-")) {
            ++format_errors;
            continue;
        }

        /* Compute the actual hash on the file */
        if (!strcmp(check_filename, "-")) {
            file2 = stdin;
        } else {
            file2 = fopen(check_filename, "rb");
        }
        if (!file2) {
            perror(check_filename);
            file_ok = 0;
        } else if (algorithm == ALG_ASCON_HASHA) {
            file_ok = ascon_hasha_file(check_filename, file2, hash2);
        } else {
            file_ok = ascon_hash_file(check_filename, file2, hash2);
        }
        if (file2 && strcmp(check_filename, "-") != 0) {
            fclose(file2);
        }

        /* Did the hashes match? */
        printf("%s: ", check_filename);
        if (file_ok && !memcmp(hash, hash2, ASCON_HASH_SIZE)) {
            printf("OK\n");
        } else if (file_ok) {
            printf("FAILED\n");
            ++mismatch_errors;
        } else {
            printf("FAILED open or read\n");
            ++read_errors;
        }
    }

    /* Report overall results */
    if (!found) {
        fprintf(stderr, "%s: no properly formatted checksum lines found\n",
                filename);
        ok = 0;
    }
    if (format_errors != 0) {
        fprintf(stderr, "WARNING: %d line%s improperly formatted\n",
                format_errors,
                (format_errors > 1 ? "s are" : " is"));
        ok = 0;
    }
    if (mismatch_errors != 0) {
        fprintf(stderr, "WARNING: %d computed checksum%s did not match\n",
                mismatch_errors,
                (mismatch_errors > 1 ? "s" : ""));
        ok = 0;
    }
    if (read_errors != 0) {
        fprintf(stderr, "WARNING: %d listed file%s could not be read\n",
                read_errors,
                (read_errors > 1 ? "s" : ""));
        ok = 0;
    }

    /* Close the checksum file */
    if (strcmp(filename, "-") != 0) {
        fclose(file);
    }
    return ok;
}
