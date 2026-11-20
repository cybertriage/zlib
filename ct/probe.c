/*
 * Probe for the Cyber Triage build of zlib. ct/ci.py builds it against
 * zlibstat.lib and an Mbed TLS release, with each toolset and C runtime that
 * Cyber Triage links zlibstat.lib with, and runs it.
 *
 * Usage: probe <directory>
 *
 * Writes files in <directory> the way the collector does (gzopen_w,
 * gz_hash_init, gzwrite, gzoffset, gzclose_hash) and checks that each hash is
 * the SHA-256 of the file as written and that the size is the file's size. It
 * prints "<hash> <size> <file>" for each, so ct/ci.py can recompute the hash
 * independently. It also exercises the rest of the zlib API the collector uses.
 * It exits 0 only if every check passes.
 */
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "zlib.h"
#include "mbedtls/sha256.h"

static int failures = 0;

static void check(int ok, const char *what)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) {
        failures++;
    }
}

/* Reads a whole file into memory. Returns NULL on failure. */
static unsigned char *read_file(const wchar_t *path, size_t *size)
{
    FILE *file = _wfopen(path, L"rb");
    unsigned char *data;
    long length;

    if (file == NULL) {
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    length = ftell(file);
    fseek(file, 0, SEEK_SET);
    data = (unsigned char *) malloc(length > 0 ? (size_t) length : 1);
    if (data != NULL && fread(data, 1, (size_t) length, file) != (size_t) length) {
        free(data);
        data = NULL;
    }
    fclose(file);
    *size = (size_t) length;
    return data;
}

static void print_hex(const unsigned char *bytes, size_t length)
{
    size_t i;
    for (i = 0; i < length; i++) {
        printf("%02x", bytes[i]);
    }
}

/* Deterministic JSON-like text that compresses about as well as a collection. */
static unsigned char *make_data(size_t length)
{
    unsigned char *data = (unsigned char *) malloc(length);
    size_t i;
    unsigned int seed = 12345;

    for (i = 0; data != NULL && i < length; i++) {
        seed = seed * 1103515245u + 12345u;
        data[i] = (i % 64 == 63) ? '\n' : (unsigned char) ("{\"path\":\"C:\\\\Windows\\\\\"}0123456789abcdef"[(seed >> 16) % 40]);
    }
    return data;
}

/*
 * Writes data in chunks to path, opened with mode, hashing from the start the
 * way the collector does, and checks gzclose_hash's results against the file.
 */
static void write_and_check(const wchar_t *path, const char *mode, const unsigned char *data,
                            size_t length, size_t chunk, const char *what)
{
    gzFile file;
    unsigned char hash[32];
    unsigned char expected[32];
    unsigned char *written;
    size_t written_size = 0;
    size_t offset;
    z_off64_t compressed_size = -1;
    int ok = 1;
    char label[160];

    file = gzopen_w(path, mode);
    if (file == NULL) {
        check(0, what);
        return;
    }
    gz_hash_init(file);
    for (offset = 0; offset < length; offset += chunk) {
        unsigned put = (unsigned) (length - offset < chunk ? length - offset : chunk);
        /* The collector checks gzoffset before each write to split its output. */
        ok &= gzoffset(file) >= 0;
        ok &= gzwrite(file, data + offset, put) == (int) put;
    }
    ok &= gzclose_hash(file, hash, &compressed_size) == Z_OK;

    written = read_file(path, &written_size);
    ok &= written != NULL;
    if (written != NULL) {
        ok &= mbedtls_sha256(written, written_size, expected, 0) == 0;
        ok &= memcmp(hash, expected, sizeof(hash)) == 0;
        ok &= compressed_size == (z_off64_t) written_size;
        free(written);
    }
    print_hex(hash, sizeof(hash));
    printf(" %lld %ls\n", (long long) compressed_size, path);
    snprintf(label, sizeof(label), "%s: hash is the SHA-256 of the file, size is its size", what);
    check(ok, label);
}

/* Reads a gzip file back and compares it with data. */
static void read_and_check(const wchar_t *path, const unsigned char *data, size_t length, const char *what)
{
    gzFile file = gzopen_w(path, "rb");
    unsigned char *buffer = (unsigned char *) malloc(length + 1);
    int got = -1;

    if (file != NULL && buffer != NULL) {
        got = gzread(file, buffer, (unsigned) length + 1);
        gzclose(file);
    }
    check(got == (int) length && memcmp(buffer, data, length) == 0, what);
    free(buffer);
}

static void probe_gz(const wchar_t *directory)
{
    const size_t length = 3 * 1024 * 1024 + 17;
    unsigned char *data = make_data(length);
    wchar_t path[1024];
    gzFile file;
    unsigned char hash[32];
    unsigned char zeros[32];
    z_off64_t size = -1;

    if (data == NULL) {
        check(0, "allocate test data");
        return;
    }
    memset(zeros, 0, sizeof(zeros));

    swprintf(path, 1024, L"%ls\\compressed.json.gz", directory);
    write_and_check(path, "wb", data, length, 64 * 1024 + 3, "compressed, 64 KiB writes");
    read_and_check(path, data, length, "compressed file reads back");

    swprintf(path, 1024, L"%ls\\small-writes.json.gz", directory);
    write_and_check(path, "wb", data, 200000, 37, "compressed, small writes");

    swprintf(path, 1024, L"%ls\\transparent.json", directory);
    write_and_check(path, "wbT", data, length, 100000, "transparent (T) write");

    swprintf(path, 1024, L"%ls\\empty.json.gz", directory);
    write_and_check(path, "wb", data, 0, 1, "empty file");

    /* gzclose_hash without gz_hash_init reports zeros but still the size. */
    swprintf(path, 1024, L"%ls\\unhashed.json.gz", directory);
    file = gzopen_w(path, "wb");
    gzwrite(file, data, 1000);
    check(gzclose_hash(file, hash, &size) == Z_OK && memcmp(hash, zeros, 32) == 0 && size > 0,
          "without gz_hash_init: zero hash, real size");

    /* gzclose after gz_hash_init frees the hash, as the collector's error path does. */
    swprintf(path, 1024, L"%ls\\error-path.json.gz", directory);
    file = gzopen_w(path, "wb");
    gz_hash_init(file);
    gzwrite(file, data, 1000);
    check(gzclose(file) == Z_OK, "gzclose after gz_hash_init");

    free(data);
}

/* The rest of the zlib API the collector uses. */
static void probe_api(void)
{
    static const unsigned char text[] = "Cyber Triage zlib probe. Cyber Triage zlib probe. Cyber Triage zlib probe.";
    unsigned char compressed[256];
    unsigned char restored[256];
    uLongf compressed_length = sizeof(compressed);
    uLongf restored_length = sizeof(restored);
    z_stream stream;
    int ret;

    printf("zlib %s, sizeof(z_off_t) %u, sizeof(z_stream) %u\n", zlibVersion(),
           (unsigned) sizeof(z_off_t), (unsigned) sizeof(z_stream));
    check(strcmp(zlibVersion(), ZLIB_VERSION) == 0, "zlibVersion matches zlib.h");

    ret = compress(compressed, &compressed_length, text, sizeof(text));
    check(ret == Z_OK, "compress");
    ret = uncompress(restored, &restored_length, compressed, compressed_length);
    check(ret == Z_OK && restored_length == sizeof(text) && memcmp(restored, text, sizeof(text)) == 0,
          "uncompress restores compress");

    memset(&stream, 0, sizeof(stream));
    ret = deflateInit(&stream, Z_DEFAULT_COMPRESSION);
    check(ret == Z_OK, "deflateInit");
    stream.next_in = (Bytef *) text;
    stream.avail_in = sizeof(text);
    stream.next_out = compressed;
    stream.avail_out = sizeof(compressed);
    ret = deflate(&stream, Z_FINISH);
    check(ret == Z_STREAM_END, "deflate");
    check(deflateEnd(&stream) == Z_OK, "deflateEnd");

    /* EwfSegmentWriter: adler32 started from 1, over "abc". */
    check(adler32(1, (const Bytef *) "abc", 3) == 0x024d0127UL, "adler32");
    check(crc32(0, (const Bytef *) "abc", 3) == 0x352441c2UL, "crc32");
}

int main(int argc, char **argv)
{
    wchar_t directory[512];

    if (argc != 2) {
        fprintf(stderr, "usage: probe <directory>\n");
        return 2;
    }
    swprintf(directory, 512, L"%hs", argv[1]);
    printf("built with _MSC_FULL_VER %d\n", _MSC_FULL_VER);

    probe_api();
    probe_gz(directory);

    printf("%d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
