#ifndef TLSLATCH_GUARDIAN_H
#define TLSLATCH_GUARDIAN_H
#include <windows.h>
#include <stdbool.h>
bool guard_worker_init(int argc, char **argv, const char *ip, unsigned short port);
int guard_parent(const char *ip, unsigned short port, const char *output);
bool guard_hold(HANDLE handle);
bool guard_release(HANDLE handle);
void guard_trip(void);
bool guard_is_tripped(void);
bool guard_done(void);
#endif
