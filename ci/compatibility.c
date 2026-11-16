#include <arpa/inet.h>
#include <sys/select.h>
#include <ares.h>
#include <assert.h>
#include <netdb.h>
#include <string.h>

static void resolved(void *data, int status, int timeouts, struct hostent *host) {
    int *calls = data;
    struct in_addr expected;

    assert(status == ARES_SUCCESS && timeouts == 0);
    assert(host && host->h_addrtype == AF_INET);
    assert(host->h_length == (int)sizeof(expected) && host->h_addr_list[0]);
    assert(inet_pton(AF_INET, "127.0.0.1", &expected) == 1);
    assert(memcmp(host->h_addr_list[0], &expected, sizeof(expected)) == 0);
    ++*calls;
}

int main(void) {
    ares_channel channel;
    int calls = 0;

    assert(ares_library_init(ARES_LIB_INIT_ALL) == ARES_SUCCESS);
    assert(ares_init(&channel) == ARES_SUCCESS);
    ares_gethostbyname(channel, "127.0.0.1", AF_INET, resolved, &calls);
    assert(calls == 1);
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
}
