#!/usr/bin/env python3
"""
Build a minimal valid single-file .torrent for an existing file.

Usage: make_test_torrent.py <data-file> <out.torrent> [piece_length]

Writes a torrent with no real announce URL (just a placeholder); used for
local self-tests where peers are dialed directly via --peer.
"""
import hashlib
import sys
from pathlib import Path


def bencode(obj):
    if isinstance(obj, int):
        return f"i{obj}e".encode()
    if isinstance(obj, bytes):
        return f"{len(obj)}:".encode() + obj
    if isinstance(obj, str):
        return bencode(obj.encode())
    if isinstance(obj, list):
        return b"l" + b"".join(bencode(x) for x in obj) + b"e"
    if isinstance(obj, dict):
        out = b"d"
        for k in sorted(obj.keys()):
            out += bencode(k if isinstance(k, bytes) else k.encode())
            out += bencode(obj[k])
        return out + b"e"
    raise TypeError(type(obj))


def main():
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    piece_len = int(sys.argv[3]) if len(sys.argv) > 3 else 16384
    data = src.read_bytes()
    pieces = b""
    for off in range(0, len(data), piece_len):
        chunk = data[off:off + piece_len]
        pieces += hashlib.sha1(chunk).digest()
    info = {
        "name": src.name,
        "piece length": piece_len,
        "pieces": pieces,
        "length": len(data),
    }
    torrent = {
        "announce": "http://localhost:0/announce",
        "info": info,
    }
    dst.write_bytes(bencode(torrent))
    print(f"Wrote {dst} ({dst.stat().st_size} bytes)")
    info_bytes = bencode(info)
    print(f"info_hash: {hashlib.sha1(info_bytes).hexdigest()}")


if __name__ == "__main__":
    main()
