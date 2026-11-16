#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PYTHON'
import ctypes

library = ctypes.CDLL("libcares.so.2")
library.ares_library_init.argtypes = [ctypes.c_int]
library.ares_library_init.restype = ctypes.c_int
library.ares_init.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
library.ares_init.restype = ctypes.c_int
library.ares_destroy.argtypes = [ctypes.c_void_p]
library.ares_destroy.restype = None
library.ares_library_cleanup.argtypes = []
library.ares_library_cleanup.restype = None

status = library.ares_library_init(0)
if status:
    raise SystemExit(f"ares_library_init failed with status {status}")
try:
    channel = ctypes.c_void_p()
    status = library.ares_init(ctypes.byref(channel))
    if status or not channel:
        raise SystemExit(f"ares_init failed with status {status}")
    library.ares_destroy(channel)
finally:
    library.ares_library_cleanup()
PYTHON
