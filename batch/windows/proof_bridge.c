#include <stdint.h>
int csv_verify_init(void);
int csv_verify_binding(const unsigned char *, const unsigned char *);
static int ready;
__declspec(dllexport) int tcpra_bridge_init(int reporter) {
    if (reporter)
        return 0;
    ready = csv_verify_init();
    return ready;
}
__declspec(dllexport) int tcpra_bridge_verify(const uint8_t *report, const uint8_t *binding) {
    return ready && csv_verify_binding(report, binding);
}
__declspec(dllexport) void tcpra_bridge_close(void) {
    ready = 0;
}
