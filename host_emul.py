#!/usr/bin/env python3
import mmap
import os
import struct
import argparse

BAR2_SIZE = 2 * 1024 * 1024   # 2 MiB file-backed BAR2
DATA_OFFSET = 0x100

REG_STORAGE_BASE = 0x00
REG_STORAGE_SIZE = 0x08
REG_STATUS       = 0x10
REG_BLOCK_SIZE   = 0x14

STATUS_READY = 1 << 0
STATUS_ERROR = 1 << 1

def u64_pack(x): return struct.pack("<Q", x)
def u32_pack(x): return struct.pack("<I", x)

def ensure_file(path, size):
    fd = os.open(path, os.O_RDWR | os.O_CREAT)
    st = os.fstat(fd)
    if st.st_size != size:
        os.ftruncate(fd, size)
    return fd

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="bar2.bin")
    ap.add_argument("--storage-size", type=int, default=1024*1024, help="bytes, must be multiple of block_size")
    ap.add_argument("--block-size", type=int, default=512, help="bytes (512/4096 etc.)")
    args = ap.parse_args()

    if args.block_size <= 0:
        raise SystemExit("block_size must be > 0")
    if args.storage_size <= 0:
        raise SystemExit("storage_size must be > 0")
    if args.storage_size % args.block_size != 0:
        raise SystemExit("storage_size must be multiple of block_size")

    fd = ensure_file(args.file, BAR2_SIZE)
    with mmap.mmap(fd, BAR2_SIZE, access=mmap.ACCESS_WRITE) as m:
        # init registers
        m[REG_STORAGE_BASE:REG_STORAGE_BASE+8] = u64_pack(0)
        m[REG_STORAGE_SIZE:REG_STORAGE_SIZE+8] = u64_pack(args.storage_size)
        m[REG_STATUS:REG_STATUS+4] = u32_pack(STATUS_READY)
        m[REG_BLOCK_SIZE:REG_BLOCK_SIZE+4] = u32_pack(args.block_size)

        print("bar2.bin initialized")
        print(f"storage_size={args.storage_size} block_size={args.block_size}")
        print("commands:")
        print("  r <lba> <blocks>         # read blocks")
        print("  w <lba> <hexbytes>       # write raw bytes (length must be blocks*bs)")
        print("  fill <lba> <blocks> <bytehex>  # fill blocks with one byte")
        print("  q")

        while True:
            try:
                line = input("> ").strip()
            except EOFError:
                break
            if not line:
                continue
            if line == "q":
                break

            parts = line.split()
            cmd = parts[0]

            if cmd == "r" and len(parts) == 3:
                lba = int(parts[1], 0)
                blocks = int(parts[2], 0)
                ln = blocks * args.block_size
                off = DATA_OFFSET + lba * args.block_size
                data = m[off:off+ln]
                print(data.hex(" "))

            elif cmd == "w" and len(parts) >= 3:
                lba = int(parts[1], 0)
                hexbytes = "".join(parts[2:])
                data = bytes.fromhex(hexbytes)
                if len(data) % args.block_size != 0:
                    print("ERR: data length must be multiple of block_size")
                    continue
                off = DATA_OFFSET + lba * args.block_size
                m[off:off+len(data)] = data
                print(f"wrote {len(data)} bytes at LBA {lba}")

            elif cmd == "fill" and len(parts) == 4:
                lba = int(parts[1], 0)
                blocks = int(parts[2], 0)
                b = int(parts[3], 16) & 0xFF
                ln = blocks * args.block_size
                off = DATA_OFFSET + lba * args.block_size
                m[off:off+ln] = bytes([b]) * ln
                print(f"filled {blocks} blocks with 0x{b:02x} at LBA {lba}")

            else:
                print("bad command")

if __name__ == "__main__":
    main()
