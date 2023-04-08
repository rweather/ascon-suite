//! [snippet_key]
    ascon_state_t state;
    ascon_init(&state);
    static unsigned char const iv[8] = {
        0x80, 0x40, 0x0c, 0x06, 0xFF, 0xFF, 0xFF, 0xFF
    };
    ascon_overwrite_bytes(&state, iv, 0, 8);
    ascon_overwrite_bytes(&state, key, 8, 16);
    ascon_overwrite_bytes(&state, nonce, 24, 16);
    ascon_permute12(&state);
//! [snippet_key]

//! [snippet_zero]
    unsigned char data[8];
    ascon_extract_bytes(&state, data, 0, 8);
    ascon_add_bytes(&state, data, 0, 8);
    ascon_clean(data, sizeof(data));
//! [snippet_zero]

//! [snippet_zero2]
    ascon_overwrite_with_zeroes(&state, 0, 8);
//! [snippet_zero2]

//! [snippet_encrypt_ofb]
void ofb_encrypt(ascon_state_t *state, unsigned char *c, const unsigned char *m, int len)
{
    int posn;
    for (posn = 0; (posn + 16) <= len; posn += 16) {
        ascon_extract_and_add_bytes(state, m + posn, c + posn, 0, 16);
        ascon_permute8(state);
    }
    if (posn < len) {
        ascon_extract_and_add_bytes(state, m + posn, c + posn, 0, len - posn);
    }
}
//! [snippet_encrypt_ofb]

//! [snippet_encrypt_cfb]
void cfb_encrypt(ascon_state_t *state, unsigned char *c, const unsigned char *m, int len)
{
    int posn;
    for (posn = 0; (posn + 16) <= len; posn += 16) {
        ascon_add_bytes(state, m + posn, 0, 16);
        ascon_extract_bytes(state, c + posn, 0, 16);
        ascon_permute8(state);
    }
    if (posn < len) {
        ascon_add_bytes(state, m + posn, 0, len - posn);
        ascon_extract_bytes(state, c + posn, 0, len - posn);
    }
}
//! [snippet_encrypt_cfb]

//! [snippet_decrypt_cfb]
void cfb_decrypt(ascon_state_t *state, unsigned char *m, const unsigned char *c, int len)
{
    int posn;
    for (posn = 0; (posn + 16) <= len; posn += 16) {
        ascon_extract_and_add_bytes(state, m + posn, c + posn, 0, 16);
        ascon_overwrite_bytes(state, c + posn, 0, 16);
        ascon_permute8(state);
    }
    if (posn < len) {
        ascon_extract_and_add_bytes(state, m + posn, c + posn, 0, len - posn);
        ascon_overwrite_bytes(state, c + posn, 0, len - posn);
    }
}
//! [snippet_decrypt_cfb]

//! [snippet_decrypt_cfb2]
void cfb_decrypt(ascon_state_t *state, unsigned char *m, const unsigned char *c, int len)
{
    int posn;
    for (posn = 0; (posn + 16) <= len; posn += 16) {
        ascon_extract_and_overwrite_bytes(state, c + posn, m + posn, 0, 16);
        ascon_permute8(state);
    }
    if (posn < len) {
        ascon_extract_and_overwrite_bytes(state, c + posn, m + posn, 0, len - posn);
    }
}
//! [snippet_decrypt_cfb2]

//! [snippet_encrypt_cfb_auth]
void cfb_auth_encrypt(ascon_state_t *state, unsigned char *c, const unsigned char *m, int len, unsigned char tag[16])
{
    static unsigned char const pad[1] = {0x80};
    int posn;
    for (posn = 0; (posn + 16) <= len; posn += 16) {
        ascon_add_bytes(state, m + posn, 0, 16);
        ascon_extract_bytes(state, c + posn, 0, 16);
        ascon_permute8(state);
    }
    if (posn < len) {
        ascon_add_bytes(state, m + posn, 0, len - posn);
        ascon_extract_bytes(state, c + posn, 0, len - posn);
    }
    ascon_add_bytes(state, pad, len - posn, 1); /* padding */
    ascon_permute12(state);
    ascon_extract_bytes(state, tag, 24, 16); /* extract the tag */
}
//! [snippet_encrypt_cfb_auth]
