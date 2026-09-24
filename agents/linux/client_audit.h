#include <inttypes.h>
#include <sys/stat.h>
#include <openssl/evp.h>
struct audit_item {
    uint8_t ch[64], sh[64];
    uint64_t mono, utc;
};
struct client_audit {
    FILE *observations, *records;
    struct audit_item *items;
    size_t count, consumed, capacity;
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    pthread_t worker;
    int reporting, stop, started;
    atomic_int failed;
    const char *epoch, *directory;
    struct tcpra_csv_context *csv;
};
static void audit_hex(const uint8_t *key, char out[129]) {
    for (int i = 0; i < 64; i++)
        snprintf(out + 2 * i, 3, "%02x", key[i]);
}
static void audit_be(uint8_t out[8], uint64_t v) {
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t)(v >> (56 - i * 8));
}
static void *audit_report_worker(void *opaque) {
    struct client_audit *a = opaque;
    for (;;) {
        pthread_mutex_lock(&a->mutex);
        while (a->consumed == a->count && !a->stop)
            pthread_cond_wait(&a->changed, &a->mutex);
        if (a->consumed == a->count && a->stop) {
            pthread_mutex_unlock(&a->mutex);
            break;
        }
        size_t index = a->consumed++;
        struct audit_item item = a->items[index];
        pthread_mutex_unlock(&a->mutex);
        uint64_t seq = index + 1, start = tcpra_now_ns();
        uint8_t key[64], be[8], report[RA_REPORT_SIZE];
        unsigned n = 0;
        EVP_MD_CTX *md = EVP_MD_CTX_new();
        int ok = md && EVP_DigestInit_ex(md, EVP_sha512(), NULL) == 1 &&
                 EVP_DigestUpdate(md, "tcp-level-ra/audit-client/v1",
                                  sizeof("tcp-level-ra/audit-client/v1") - 1) == 1 &&
                 EVP_DigestUpdate(md, a->epoch, strlen(a->epoch)) == 1;
        audit_be(be, seq);
        ok = ok && EVP_DigestUpdate(md, be, 8) == 1 && EVP_DigestUpdate(md, item.ch, 64) == 1 &&
             EVP_DigestUpdate(md, item.sh, 64) == 1;
        audit_be(be, item.mono);
        ok = ok && EVP_DigestUpdate(md, be, 8) == 1 && EVP_DigestFinal_ex(md, key, &n) == 1 &&
             n == 64;
        EVP_MD_CTX_free(md);
        ok = ok && tcpra_csv_generate_report(a->csv, key, report);
        if (ok) {
            char path[1024];
            snprintf(path, sizeof(path), "%s/reports/%" PRIu64 ".bin", a->directory, seq);
            FILE *f = fopen(path, "wb");
            if (!f)
                ok = 0;
            else {
                ok = fwrite(report, 1, sizeof(report), f) == sizeof(report);
                if (fclose(f))
                    ok = 0;
            }
        }
        uint64_t done = tcpra_now_ns();
        char ch[129], sh[129];
        audit_hex(item.ch, ch);
        audit_hex(item.sh, sh);

        fprintf(a->records,
                "%" PRIu64 ",%s,%s,%" PRIu64 ",%" PRIu64 ",%d,%" PRIu64 ",%" PRIu64 "\n", seq, sh,
                ch, item.mono, item.utc, ok, done - start, done);
        fflush(a->records);
        if (!ok)
            a->failed = 1;
    }
    return NULL;
}
static int client_audit_open(struct client_audit *a, const char *output, size_t capacity,
                             const char *epoch, const char *directory,
                             struct tcpra_csv_context *csv) {
    atomic_init(&a->failed, 0);
    a->capacity = capacity;
    a->csv = csv;
    a->epoch = epoch;
    a->directory = directory;
    a->reporting = directory != NULL;
    a->items = calloc(capacity, sizeof(*a->items));
    a->observations = fopen(output, "w");
    if (!a->items || !a->observations)
        return 0;
    fprintf(a->observations, "session,lookup_key,local_serverhello_key,t_ch_ns,t_sh_ns\n");
    pthread_mutex_init(&a->mutex, NULL);
    pthread_cond_init(&a->changed, NULL);
    if (a->reporting) {
        size_t len = epoch ? strlen(epoch) : 0;
        if (len < 7 || strcmp(epoch + len - 7, "-client"))
            return 0;
        char path[1024];
        mkdir(directory, 0700);
        snprintf(path, sizeof(path), "%s/reports", directory);
        mkdir(path, 0700);
        snprintf(path, sizeof(path), "%s/epoch", directory);
        FILE *f = fopen(path, "w");
        if (!f)
            return 0;
        fprintf(f, "%s\n", epoch);
        fclose(f);
        snprintf(path, sizeof(path), "%s/records.csv", directory);
        a->records = fopen(path, "w");
        if (!a->records)
            return 0;
        fprintf(a->records, "seq,ch_key,sh_key,t_srv_mono_ns,t_srv_utc_ns,report_ok,report_gen_ns,"
                            "t_report_done_ns\n");
        if (pthread_create(&a->worker, NULL, audit_report_worker, a))
            return 0;
        a->started = 1;
    }
    return 1;
}
static void client_audit_record(struct client_audit *a, struct gate_flow *gate) {
    pthread_mutex_lock(&a->mutex);
    if (a->count >= a->capacity) {
        a->failed = 1;
        pthread_mutex_unlock(&a->mutex);
        return;
    }
    struct audit_item *item = &a->items[a->count];
    memcpy(item->ch, gate->lookup_key, 64);
    memcpy(item->sh, gate->report_key, 64);
    item->mono = gate->state_ns;
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    item->utc = (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
    char ch[129], sh[129];
    audit_hex(item->ch, ch);
    audit_hex(item->sh, sh);
    fprintf(a->observations, "%zu,%s,%s,%" PRIu64 ",%" PRIu64 "\n", a->count + 1, ch, sh,
            item->mono, tcpra_now_ns());
    fflush(a->observations);
    a->count++;
    pthread_cond_signal(&a->changed);
    pthread_mutex_unlock(&a->mutex);
}
static void client_audit_close(struct client_audit *a) {
    pthread_mutex_lock(&a->mutex);
    a->stop = 1;
    pthread_cond_signal(&a->changed);
    pthread_mutex_unlock(&a->mutex);
    if (a->started)
        pthread_join(a->worker, NULL);
    if (a->records)
        fclose(a->records);
    if (a->observations)
        fclose(a->observations);
    free(a->items);
    pthread_cond_destroy(&a->changed);
    pthread_mutex_destroy(&a->mutex);
}
