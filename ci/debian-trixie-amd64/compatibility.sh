#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import ctypes
import socket

library = ctypes.CDLL("libcares.so.2")
parse_address = library.ares_inet_pton
parse_address.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p]
parse_address.restype = ctypes.c_int

for family, address in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
    expected = socket.inet_pton(family, address)
    result = ctypes.create_string_buffer(len(expected))
    if parse_address(family, address.encode("ascii"), result) != 1 or result.raw != expected:
        raise SystemExit(f"Unexpected c-ares address conversion for {address}")
PY
