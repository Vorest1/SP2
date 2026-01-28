// host_emul.c — Host application for BAR2 file-backed PCIe device (Lab2 Variant 8)
//
// Builds a file "bar2.bin" and treats it as BAR2 memory:
//  0x00 u64 storage_base (RO) = 0
//  0x08 u64 storage_size (RO)
//  0x10 u32 status       (RO) READY/ERROR
//  0x14 u32 block_size   (RO)
//  0x100 data region     (RW)
//
// Commands:
//   r <lba> <blocks>
//   w <lba> <hexbytes>        (length must be multiple of block_size)
//   fill <lba> <blocks> <bytehex>
//   q

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

enum { BAR2_SIZE = 2 * 1024 * 1024 };
enum { DATA_OFFSET = 0x100 };

enum { REG_STORAGE_BASE = 0x00 };
enum { REG_STORAGE_SIZE = 0x08 };
enum { REG_STATUS       = 0x10 };
enum { REG_BLOCK_SIZE   = 0x14 };

enum { STATUS_READY = 1u << 0 };
enum { STATUS_ERROR = 1u << 1 };

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static bool parse_u64(const char *s, uint64_t *out) {
    if (!s || !*s) return false;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0') return false;
    *out = (uint64_t)v;
    return true;
}

static bool parse_u32(const char *s, uint32_t *out) {
    uint64_t v;
    if (!parse_u64(s, &v)) return false;
    if (v > 0xffffffffULL) return false;
    *out = (uint32_t)v;
    return true;
}

static bool hex_nibble(char c, uint8_t *n) {
    if (c >= '0' && c <= '9') { *n = (uint8_t)(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { *n = (uint8_t)(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { *n = (uint8_t)(c - 'A' + 10); return true; }
    return false;
}

// Parse hex string with optional spaces: "aa bbcc 01" -> bytes
static uint8_t *parse_hexbytes(const char *s, size_t *out_len) {
    *out_len = 0;
    if (!s) return NULL;

    // collect only hex chars
    size_t n = strlen(s);
    char *tmp = (char*)malloc(n + 1);
    if (!tmp) return NULL;

    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if ((c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F')) {
            tmp[k++] = c;
        }
    }
    tmp[k] = '\0';

    if (k == 0 || (k % 2) != 0) { free(tmp); return NULL; }

    size_t blen = k / 2;
    uint8_t *buf = (uint8_t*)malloc(blen);
    if (!buf) { free(tmp); return NULL; }

    for (size_t i = 0; i < blen; i++) {
        uint8_t hi, lo;
        if (!hex_nibble(tmp[2*i], &hi) || !hex_nibble(tmp[2*i+1], &lo)) {
            free(tmp); free(buf); return NULL;
        }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }

    free(tmp);
    *out_len = blen;
    return buf;
}

static void store_u64_le(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

static void store_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void hexdump_line(const uint8_t *p, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", p[i]);
        if (i + 1 != len) printf(" ");
    }
    printf("\n");
}

int main(int argc, char **argv) {
    const char *file = "bar2.bin";
    uint64_t storage_size = 1024 * 1024;
    uint32_t block_size = 512;

    // args: --file X --storage-size N --block-size N
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--file") && i + 1 < argc) {
            file = argv[++i];
        } else if (!strcmp(argv[i], "--storage-size") && i + 1 < argc) {
            if (!parse_u64(argv[++i], &storage_size)) {
                fprintf(stderr, "Bad --storage-size\n");
                return 2;
            }
        } else if (!strcmp(argv[i], "--block-size") && i + 1 < argc) {
            if (!parse_u32(argv[++i], &block_size)) {
                fprintf(stderr, "Bad --block-size\n");
                return 2;
            }
        } else {
            fprintf(stderr, "Usage: %s [--file bar2.bin] [--storage-size N] [--block-size N]\n", argv[0]);
            return 2;
        }
    }

    if (block_size == 0 || storage_size == 0 || (storage_size % block_size) != 0) {
        fprintf(stderr, "ERROR: storage_size must be >0 and multiple of block_size\n");
        return 2;
    }
    if (DATA_OFFSET + storage_size > BAR2_SIZE) {
        fprintf(stderr, "ERROR: DATA_OFFSET + storage_size exceeds BAR2_SIZE\n");
        return 2;
    }

    int fd = open(file, O_RDWR | O_CREAT, 0644);
    if (fd < 0) die("open");

    // ensure exact size
    if (ftruncate(fd, BAR2_SIZE) != 0) die("ftruncate");

    uint8_t *m = (uint8_t*)mmap(NULL, BAR2_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) die("mmap");

    // init registers
    store_u64_le(m + REG_STORAGE_BASE, 0);
    store_u64_le(m + REG_STORAGE_SIZE, storage_size);
    store_u32_le(m + REG_STATUS, STATUS_READY);
    store_u32_le(m + REG_BLOCK_SIZE, block_size);

    printf("bar2.bin initialized: file=%s storage_size=%" PRIu64 " block_size=%u\n",
           file, storage_size, block_size);
    printf("commands:\n");
    printf("  r <lba> <blocks>\n");
    printf("  w <lba> <hexbytes>\n");
    printf("  fill <lba> <blocks> <bytehex>\n");
    printf("  q\n");

    char *line = NULL;
    size_t cap = 0;

    while (true) {
        printf("> ");
        fflush(stdout);
        ssize_t nread = getline(&line, &cap, stdin);
        if (nread <= 0) break;

        // trim newline
        while (nread > 0 && (line[nread-1] == '\n' || line[nread-1] == '\r')) line[--nread] = 0;
        if (nread == 0) continue;

        // tokenize
        char *save = NULL;
        char *cmd = strtok_r(line, " \t", &save);
        if (!cmd) continue;

        if (!strcmp(cmd, "q")) break;

        if (!strcmp(cmd, "r")) {
            char *s_lba = strtok_r(NULL, " \t", &save);
            char *s_blocks = strtok_r(NULL, " \t", &save);
            uint64_t lba, blocks;
            if (!s_lba || !s_blocks || !parse_u64(s_lba, &lba) || !parse_u64(s_blocks, &blocks)) {
                printf("ERR: r <lba> <blocks>\n");
                continue;
            }
            uint64_t len = blocks * (uint64_t)block_size;
            uint64_t off = DATA_OFFSET + lba * (uint64_t)block_size;
            if (off + len > BAR2_SIZE) {
                printf("ERR: out of range\n");
                continue;
            }
            hexdump_line(m + off, (size_t)len);
        }
        else if (!strcmp(cmd, "w")) {
            char *s_lba = strtok_r(NULL, " \t", &save);
            char *rest = save; // remainder is hex string (may include spaces)
            uint64_t lba;
            if (!s_lba || !parse_u64(s_lba, &lba) || !rest) {
                printf("ERR: w <lba> <hexbytes>\n");
                continue;
            }

            size_t blen = 0;
            uint8_t *buf = parse_hexbytes(rest, &blen);
            if (!buf) {
                printf("ERR: invalid hex bytes\n");
                continue;
            }
            if ((blen % block_size) != 0) {
                printf("ERR: data length (%zu) must be multiple of block_size (%u)\n", blen, block_size);
                free(buf);
                continue;
            }

            uint64_t off = DATA_OFFSET + lba * (uint64_t)block_size;
            if (off + blen > BAR2_SIZE) {
                printf("ERR: out of range\n");
                free(buf);
                continue;
            }
            memcpy(m + off, buf, blen);
            free(buf);
            printf("OK: wrote %zu bytes at LBA %" PRIu64 "\n", blen, lba);
        }
        else if (!strcmp(cmd, "fill")) {
            char *s_lba = strtok_r(NULL, " \t", &save);
            char *s_blocks = strtok_r(NULL, " \t", &save);
            char *s_byte = strtok_r(NULL, " \t", &save);
            uint64_t lba, blocks;
            uint32_t bytev;
            if (!s_lba || !s_blocks || !s_byte ||
                !parse_u64(s_lba, &lba) || !parse_u64(s_blocks, &blocks) || !parse_u32(s_byte, &bytev)) {
                printf("ERR: fill <lba> <blocks> <bytehex>\n");
                continue;
            }
            uint8_t b = (uint8_t)(bytev & 0xff);
            uint64_t len = blocks * (uint64_t)block_size;
            uint64_t off = DATA_OFFSET + lba * (uint64_t)block_size;
            if (off + len > BAR2_SIZE) {
                printf("ERR: out of range\n");
                continue;
            }
            memset(m + off, b, (size_t)len);
            printf("OK: filled %" PRIu64 " blocks with 0x%02x at LBA %" PRIu64 "\n", blocks, b, lba);
        }
        else {
            printf("ERR: unknown command\n");
        }
    }

    free(line);
    msync(m, BAR2_SIZE, MS_SYNC);
    munmap(m, BAR2_SIZE);
    close(fd);
    return 0;
}
