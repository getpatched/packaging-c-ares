#!/usr/bin/env bash
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
cat > smoke.c <<'C'
#include <ares.h>

int main(void) {
    ares_channel channel;
    if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS)
        return 1;
    int result = ares_init(&channel);
    if (result == ARES_SUCCESS)
        ares_destroy(channel);
    ares_library_cleanup();
    return result == ARES_SUCCESS ? 0 : 1;
}
C
gcc smoke.c -o smoke -lcares
./smoke
