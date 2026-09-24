#ifndef SCALE_PROFILE_H
#define SCALE_PROFILE_H
#include <stdint.h>
struct prof_stamp {
    uint64_t wall, user, system, cpu;
};
struct prof_stamp prof_start(void);
void prof_end(const char *operation, unsigned port, int ok, struct prof_stamp start);
#endif
