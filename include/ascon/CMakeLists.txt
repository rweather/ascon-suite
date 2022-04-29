
list(APPEND ASCON_HEADERS
    aead.h
    aead-masked.h
    hash.h
    hkdf.h
    hmac.h
    isap.h
    kmac.h
    masking.h
    pbkdf2.h
    permutation.h
    random.h
    siv.h
    utility.h
    xof.h
)

install(FILES ${ASCON_HEADERS} DESTINATION include/ascon)
