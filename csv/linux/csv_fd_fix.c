#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static FILE *(*real_fopen)(const char *, const char *);
static int (*real_fclose)(FILE *);
static int (*real_report)(void *, int, void *, int);
static pthread_once_t once = PTHREAD_ONCE_INIT;
static _Thread_local FILE *owned;
static _Thread_local int in_report;
static _Thread_local int opened, closed;
static void init(void) {
    void *p = dlsym(RTLD_NEXT, "fopen");
    memcpy(&real_fopen, &p, sizeof p);
    p = dlsym(RTLD_NEXT, "fclose");
    memcpy(&real_fclose, &p, sizeof p);
    p = dlsym(RTLD_NEXT, "vmmcall_get_attestation_report");
    memcpy(&real_report, &p, sizeof p);
    if (!real_fopen || !real_fclose || !real_report)
        abort();
}
FILE *fopen(const char *path, const char *mode) {
    pthread_once(&once, init);
    FILE *f = real_fopen(path, mode);
    if (f && in_report && strcmp(path, "/proc/self/pagemap") == 0) {
        if (owned)
            abort();
        owned = f;
        opened++;
    }
    return f;
}
int fclose(FILE *f) {
    pthread_once(&once, init);
    if (f == owned) {
        owned = NULL;
        closed++;
    }
    return real_fclose(f);
}
int vmmcall_get_attestation_report(void *key, int key_len, void *report, int report_len) {
    pthread_once(&once, init);
    if (in_report || owned)
        abort();
    in_report = 1;
    opened = closed = 0;
    int rc = real_report(key, key_len, report, report_len);
    if (owned) {
        FILE *f = owned;
        owned = NULL;
        closed++;
        if (real_fclose(f) != 0 && rc == 0)
            rc = -1;
    }
    in_report = 0;

    if (rc == 0 && (opened != 1 || closed != 1))
        return -1;
    return rc;
}
