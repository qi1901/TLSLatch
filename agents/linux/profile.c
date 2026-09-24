#define _GNU_SOURCE
#include "profile.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>
#include <inttypes.h>
#define LIMIT 32768
struct record {
    const char *op;
    unsigned port;
    int ok;
    struct prof_stamp start, end;
};
static struct record rows[LIMIT];
static atomic_uint count;
static const char *path;
struct prof_stamp prof_start(void) {
    if (!path)
        return (struct prof_stamp){0};
    struct timespec t, c;
    struct rusage r;
    clock_gettime(CLOCK_MONOTONIC, &t);
    getrusage(RUSAGE_THREAD, &r);
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c);
    return (struct prof_stamp){
        (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec,
        (uint64_t)r.ru_utime.tv_sec * 1000000000 + (uint64_t)r.ru_utime.tv_usec * 1000,
        (uint64_t)r.ru_stime.tv_sec * 1000000000 + (uint64_t)r.ru_stime.tv_usec * 1000,
        (uint64_t)c.tv_sec * 1000000000 + c.tv_nsec};
}
void prof_end(const char *op, unsigned port, int ok, struct prof_stamp start) {
    if (!path)
        return;
    struct prof_stamp end = prof_start();
    unsigned i = atomic_fetch_add(&count, 1);
    if (i < LIMIT)
        rows[i] = (struct record){op, port, ok, start, end};
}
static void flush_profile(void) {
    if (!path)
        return;
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("profile output");
        return;
    }
    fputs("operation,client_port,ok,start_ns,end_ns,wall_ns,user_ns,system_ns,thread_cpu_ns\n", f);
    unsigned n = atomic_load(&count);
    if (n > LIMIT) {
        fputs("OVERFLOW,0,0,0,0,0,0,0\n", f);
        n = LIMIT;
    }
    for (unsigned i = 0; i < n; i++) {
        struct record *r = &rows[i];
        fprintf(
            f, "%s,%u,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
            r->op, r->port, r->ok, r->start.wall, r->end.wall, r->end.wall - r->start.wall,
            r->end.user - r->start.user, r->end.system - r->start.system,
            r->end.cpu - r->start.cpu);
    }
    fclose(f);
}
__attribute__((constructor)) static void init_profile(void) {
    path = getenv("TCPRA_PROFILE");
    if (path) {
        atexit(flush_profile);
        for (int i = 0; i < 100; i++) {
            struct prof_stamp t = prof_start();
            prof_end("empty_probe", 0, 1, t);
        }
    }
}
