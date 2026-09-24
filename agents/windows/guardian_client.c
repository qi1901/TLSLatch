#include "guardian_runtime.h"
#include "guardian.h"
enum { G_HOLD = 1, G_RELEASE = 2, G_TRIP = 3, G_DONE = 4 };
typedef struct {
    uint32_t operation, reserved;
    uint64_t handle;
} Message;
typedef struct {
    uint64_t worker_handle;
    HANDLE handle;
} Reference;
static HANDLE request_pipe, reply_pipe;
static CRITICAL_SECTION ipc_lock;
static volatile LONG tripped;
static char endpoint[64];
static unsigned short endpoint_port;

bool guard_worker_init(int argc, char **argv, const char *ip, unsigned short port) {
    const char *rx = NULL, *tx = NULL;
    for (int i = 1; i + 1 < argc; i++) {
        if (!strcmp(argv[i], "--guard-rx"))
            rx = argv[i + 1];
        if (!strcmp(argv[i], "--guard-tx"))
            tx = argv[i + 1];
    }
    if (!rx || !tx)
        return false;
    reply_pipe = (HANDLE)(uintptr_t)_strtoui64(rx, NULL, 10);
    request_pipe = (HANDLE)(uintptr_t)_strtoui64(tx, NULL, 10);
    strcpy_s(endpoint, sizeof(endpoint), ip);
    endpoint_port = port;
    InitializeCriticalSection(&ipc_lock);
    return true;
}
static bool command(uint32_t operation, HANDLE h) {
    Message message = {operation, 0, (uint64_t)(uintptr_t)h};
    uint32_t ack = 0;
    EnterCriticalSection(&ipc_lock);
    bool ok = io(request_pipe, &message, sizeof(message), true) &&
              io(reply_pipe, &ack, sizeof(ack), false) && ack == 1;
    LeaveCriticalSection(&ipc_lock);
    return ok;
}
bool guard_is_tripped(void) {
    return InterlockedCompareExchange(&tripped, 0, 0) != 0;
}
void guard_trip(void) {
    InterlockedExchange(&tripped, 1);
    if (!command(G_TRIP, NULL))
        quarantine(endpoint, endpoint_port);
}
bool guard_hold(HANDLE h) {
    if (!guard_is_tripped() && command(G_HOLD, h))
        return true;
    guard_trip();
    return false;
}
bool guard_release(HANDLE h) {
    if (command(G_RELEASE, h))
        return true;
    guard_trip();
    return false;
}
bool guard_done(void) {
    return !guard_is_tripped() && command(G_DONE, NULL);
}
