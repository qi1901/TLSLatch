#ifndef TCPRA_UNIFIED_CSV_ATTESTATION_H
#define TCPRA_UNIFIED_CSV_ATTESTATION_H

#include <pthread.h>
#include <stdint.h>

#include "ra_protocol_early.h"

typedef int (*tcpra_get_report_fn)(void *, int, void *, int);
typedef int (*tcpra_sm2_verify_fn)(void *, int, void *, int, void *, int, void *, int);

struct tcpra_csv_context {
    void *handle;
    tcpra_get_report_fn get_report;
    tcpra_sm2_verify_fn sm2_verify;
    uint8_t trusted_pek[64];
    uint8_t trusted_measurement[32];
    pthread_mutex_t library_mutex;
    int reporter;
};

int tcpra_csv_context_open(struct tcpra_csv_context *context, int reporter);
void tcpra_csv_context_close(struct tcpra_csv_context *context);
int tcpra_csv_verify_report(struct tcpra_csv_context *context, const uint8_t report[RA_REPORT_SIZE],
                            const uint8_t expected[RA_KEY_SIZE]);
int tcpra_csv_generate_report(struct tcpra_csv_context *context, const uint8_t key[RA_KEY_SIZE],
                              uint8_t report[RA_REPORT_SIZE]);

#endif
