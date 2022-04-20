
list(APPEND ASCON_HEADERS
    aead.h
    hash.h
    hmac.h
    isap.h
    kmac.h
    permutation.h
    siv.h
    utility.h
    xof.h
)

install(FILES ${ASCON_HEADERS} DESTINATION include/ascon)
