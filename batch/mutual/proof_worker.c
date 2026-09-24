#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "csv_attestation.h"

int main(int argc, char **argv) {
    struct tcpra_csv_context context;
    int reporter = argc == 2 && strcmp(argv[1], "generate") == 0;
    if (argc != 2 || (!reporter && strcmp(argv[1], "verify") != 0))
        return 2;
    if (!tcpra_csv_context_open(&context, reporter))
        return 2;
    if (fputc(1, stdout) == EOF || fflush(stdout))
        return 3;
    int op, result = 0;
    uint8_t key[64], report[2548];
    while ((op = fgetc(stdin)) != EOF && op != 'Q') {
        if (fread(key, 1, sizeof key, stdin) != sizeof key) {
            result = 3;
            break;
        }
        int ok;
        if (op == 'G' && reporter) {
            ok = tcpra_csv_generate_report(&context, key, report);
        } else if (op == 'V') {
            if (fread(report, 1, sizeof report, stdin) != sizeof report) {
                result = 3;
                break;
            }
            ok = tcpra_csv_verify_report(&context, report, key);
        } else {
            result = 2;
            break;
        }
        if (fputc(ok ? 1 : 0, stdout) == EOF ||
            (ok && op == 'G' && fwrite(report, 1, sizeof report, stdout) != sizeof report) ||
            fflush(stdout)) {
            result = 3;
            break;
        }
    }
    tcpra_csv_context_close(&context);
    return result;
}
