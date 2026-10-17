/* gzclose.c -- zlib gzclose() function
 * Copyright (C) 2004, 2010 Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h
 */

#include "gzguts.h"

/* gzclose() is in a separate file so that it is linked in only if it is used.
   That way the other gzclose functions can be used instead to avoid linking in
   unneeded compression or decompression routines. */
int ZEXPORT gzclose(gzFile file) {
#ifndef NO_GZCOMPRESS
    gz_statep state;

    if (file == NULL)
        return Z_STREAM_ERROR;
    state = (gz_statep)file;

    return state->mode == GZ_READ ? gzclose_r(file) : gzclose_w(file);
#else
    return gzclose_r(file);
#endif
}

/* -- see zlib.h -- */
void ZEXPORT gz_hash_init(gzFile file) {
    gz_statep state;

    if (file == NULL)
        return;
    state = (gz_statep)file;

    mbedtls_sha256_init(&(state->strm.sha256_context));
    if (mbedtls_sha256_starts(&(state->strm.sha256_context), 0) != 0)
        /* leaves the state Z_SHA256_STATE_UNINITIALIZED */
        mbedtls_sha256_free(&(state->strm.sha256_context));
    else
        state->strm.sha256_ret = Z_SHA256_STATE_ACTIVE;
}

/* -- see zlib.h -- */
int ZEXPORT gzclose_hash(gzFile file, unsigned char hashBuf[32],
                         z_off64_t *compressedSize) {
#ifndef NO_GZCOMPRESS
    gz_statep state;

    if (file == NULL)
        return Z_STREAM_ERROR;
    state = (gz_statep)file;

    return state->mode == GZ_READ ? gzclose_r(file) :
                                    gzclose_hash_w(file, hashBuf, compressedSize);
#else
    return gzclose_r(file);
#endif
}
