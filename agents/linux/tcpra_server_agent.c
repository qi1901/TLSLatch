#define _GNU_SOURCE
#include "profile.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "csv_attestation.h"
#include "linux_safety.h"
#include "pcap_observer.h"
#include "tls_parse.h"
#include "wire_io.h"

#define SERVER_CACHE_CAPACITY 8192u
#define SERVER_LOOKUP_CAPACITY 16384u
#define SERVER_JOB_CAPACITY 8192u
#define SERVER_CONTROL_CAPACITY 1024u

enum tcpra_mode { MODE_NIRA = 1, MODE_NIRAK = 2, MODE_DEFERRED = 3 };

struct server_cache_entry {
    uint8_t occupancy;
    uint8_t has_lookup_key;
    uint8_t lookup_observed;
    uint8_t request_received;
    uint8_t has_report_key;
    uint8_t ready;
    uint8_t delivered;
    uint8_t admitted;
    struct flow_key flow;
    uint64_t socket_cookie;
    uint8_t lookup_key[RA_KEY_SIZE];
    uint8_t report_key[RA_KEY_SIZE];
    uint8_t attestation_key[RA_KEY_SIZE];
    uint8_t report[RA_REPORT_SIZE];
    uint64_t request_nonce;
    uint64_t observed_ns;
    uint64_t lookup_observed_ns;
    uint64_t report_start_ns;
    uint64_t report_done_ns;
    uint64_t request_ns;
    uint64_t response_ns;
    uint64_t verdict_ns;

    uint64_t d_seq;
    uint64_t d_t_srv;
    uint64_t d_t_utc;
};

struct report_job {
    size_t slot;
    struct flow_key flow;
    uint8_t report_key[RA_KEY_SIZE];
};

struct lookup_index_entry {
    uint8_t occupancy;
    uint8_t reserved[7];
    size_t cache_slot;
    uint8_t lookup_key[RA_KEY_SIZE];
};

struct completed_record {
    int session;
    int admitted;
    int client_report_verified;
    struct flow_key flow;
    uint64_t observed_ns;
    uint64_t report_start_ns;
    uint64_t report_done_ns;
    uint64_t request_ns;
    uint64_t response_ns;
    uint64_t verdict_ns;
};

struct server_counters {
    unsigned long long copied_packets;
    unsigned long long copied_bytes;
    unsigned long long client_hellos;
    unsigned long long server_hellos;
    unsigned long long duplicate_keys;
    unsigned long long report_failures;
    unsigned long long client_reports_verified;
    unsigned long long client_report_failures;
    unsigned long long report_queue_full;
    unsigned long long cache_full;
    unsigned long long map_deletes;
    unsigned long long map_delete_misses;
    unsigned long long enobufs;
};

struct server_agent {
    enum tcpra_mode mode;
    const char *server_ip;
    uint16_t main_port;
    uint16_t ra_port;
    uint16_t queue_number;
    int expected_sessions;
    int mutual_ra;
    const char *csv_path;
    const char *ready_file;
    const char *flow_bpf_object;
    const char *pin_directory;

    int deferred;
    const char *epoch_arg;
    const char *dlog_arg;
    char epoch[128];
    char dlog_dir[512];
    FILE *d_records;
    FILE *d_index;
    uint64_t d_seq;
    long d_reports_ok;
    long d_reports_fail;
    struct tcpra_csv_context reporter;
    struct tcpra_pcap_observer *pcap;

    pthread_mutex_t cache_mutex;
    pthread_cond_t cache_changed;
    struct server_cache_entry cache[SERVER_CACHE_CAPACITY];
    struct lookup_index_entry lookup_index[SERVER_LOOKUP_CAPACITY];
    int completed_sessions;
    struct completed_record *records;

    pthread_mutex_t job_mutex;
    pthread_cond_t job_available;
    struct report_job jobs[SERVER_JOB_CAPACITY];
    size_t job_head, job_tail, job_count;
    pthread_t report_thread;
    int report_thread_started;

    int listener;
    pthread_t accept_thread;
    int accept_thread_started;
    pthread_mutex_t control_mutex;
    pthread_cond_t controls_stopped;
    int control_fds[SERVER_CONTROL_CAPACITY];
    size_t active_controls;

    struct server_counters counters;
    atomic_int stopping;
};

struct control_argument {
    struct server_agent *agent;
    int fd;
    size_t slot;
};

static volatile sig_atomic_t signal_stop;

static void log_protocol_key(const char *event, const uint8_t key[RA_KEY_SIZE]) {
    fprintf(stderr, "tcpra_protocol event=%s key=", event);
    for (size_t index = 0; index < RA_KEY_SIZE; index++)
        fprintf(stderr, "%02x", key[index]);
    fputc('\n', stderr);
}

static void on_signal(int signal_number) {
    (void)signal_number;
    signal_stop = 1;
}

static int same_flow(const struct flow_key *left, const struct flow_key *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

static int same_route(const struct flow_key *left, const struct flow_key *right) {
    return left->client_ip == right->client_ip && left->server_ip == right->server_ip &&
           left->client_port == right->client_port && left->server_port == right->server_port;
}

static size_t route_hash(const struct flow_key *flow) {
    uint64_t value = flow->client_ip;
    value ^= ((uint64_t)flow->client_port << 32) | flow->server_port;
    value ^= value >> 33;
    value *= 0xff51afd7ed558ccdull;
    value ^= value >> 33;
    return (size_t)value & (SERVER_CACHE_CAPACITY - 1u);
}

static size_t cache_new_slot(struct server_agent *agent, const struct flow_key *flow) {
    size_t first_tombstone = SERVER_CACHE_CAPACITY;
    size_t start = route_hash(flow);
    for (size_t offset = 0; offset < SERVER_CACHE_CAPACITY; offset++) {
        size_t index = (start + offset) & (SERVER_CACHE_CAPACITY - 1u);
        struct server_cache_entry *entry = &agent->cache[index];
        if (entry->occupancy == 2 && first_tombstone == SERVER_CACHE_CAPACITY)
            first_tombstone = index;
        if (entry->occupancy == 0)
            return first_tombstone == SERVER_CACHE_CAPACITY ? index : first_tombstone;
    }
    return first_tombstone;
}

static size_t lookup_hash(const uint8_t lookup_key[RA_KEY_SIZE]) {
    uint64_t value = 1469598103934665603ull;
    for (size_t index = 0; index < RA_KEY_SIZE; index++) {
        value ^= lookup_key[index];
        value *= 1099511628211ull;
    }
    return (size_t)value & (SERVER_LOOKUP_CAPACITY - 1u);
}

static struct lookup_index_entry *find_lookup_index(struct server_agent *agent,
                                                    const uint8_t lookup_key[RA_KEY_SIZE]) {
    size_t start = lookup_hash(lookup_key);
    for (size_t offset = 0; offset < SERVER_LOOKUP_CAPACITY; offset++) {
        struct lookup_index_entry *index =
            &agent->lookup_index[(start + offset) & (SERVER_LOOKUP_CAPACITY - 1u)];
        if (index->occupancy == 0)
            break;
        if (index->occupancy == 1 && memcmp(index->lookup_key, lookup_key, RA_KEY_SIZE) == 0)
            return index;
    }
    return NULL;
}

static struct server_cache_entry *find_lookup_entry(struct server_agent *agent,
                                                    const uint8_t lookup_key[RA_KEY_SIZE]) {
    struct lookup_index_entry *index = find_lookup_index(agent, lookup_key);
    if (!index || index->cache_slot >= SERVER_CACHE_CAPACITY)
        return NULL;
    struct server_cache_entry *entry = &agent->cache[index->cache_slot];
    if (entry->occupancy != 1 || !entry->has_lookup_key ||
        memcmp(entry->lookup_key, lookup_key, RA_KEY_SIZE) != 0)
        return NULL;
    return entry;
}

static int insert_lookup_index(struct server_agent *agent, const uint8_t lookup_key[RA_KEY_SIZE],
                               size_t cache_slot) {
    size_t first_tombstone = SERVER_LOOKUP_CAPACITY;
    size_t start = lookup_hash(lookup_key);
    for (size_t offset = 0; offset < SERVER_LOOKUP_CAPACITY; offset++) {
        size_t slot = (start + offset) & (SERVER_LOOKUP_CAPACITY - 1u);
        struct lookup_index_entry *index = &agent->lookup_index[slot];
        if (index->occupancy == 1 && memcmp(index->lookup_key, lookup_key, RA_KEY_SIZE) == 0)
            return index->cache_slot == cache_slot;
        if (index->occupancy == 2 && first_tombstone == SERVER_LOOKUP_CAPACITY)
            first_tombstone = slot;
        if (index->occupancy == 0) {
            if (first_tombstone != SERVER_LOOKUP_CAPACITY)
                index = &agent->lookup_index[first_tombstone];
            memset(index, 0, sizeof(*index));
            index->occupancy = 1;
            index->cache_slot = cache_slot;
            memcpy(index->lookup_key, lookup_key, RA_KEY_SIZE);
            return 1;
        }
    }
    if (first_tombstone == SERVER_LOOKUP_CAPACITY)
        return 0;
    struct lookup_index_entry *index = &agent->lookup_index[first_tombstone];
    memset(index, 0, sizeof(*index));
    index->occupancy = 1;
    index->cache_slot = cache_slot;
    memcpy(index->lookup_key, lookup_key, RA_KEY_SIZE);
    return 1;
}

static void delete_lookup_index(struct server_agent *agent, const uint8_t lookup_key[RA_KEY_SIZE]) {
    struct lookup_index_entry *index = find_lookup_index(agent, lookup_key);
    if (!index)
        return;
    memset(index, 0, sizeof(*index));
    index->occupancy = 2;
}

static struct server_cache_entry *find_newest_report_orphan(struct server_agent *agent,
                                                            const struct flow_key *wanted,
                                                            uint64_t cookie) {
    struct server_cache_entry *result = NULL;
    size_t start = route_hash(wanted);
    for (size_t offset = 0; offset < SERVER_CACHE_CAPACITY; offset++) {
        struct server_cache_entry *entry =
            &agent->cache[(start + offset) & (SERVER_CACHE_CAPACITY - 1u)];
        if (entry->occupancy == 0)
            break;
        if (entry->occupancy == 1 && entry->socket_cookie == cookie && !entry->has_lookup_key &&
            entry->has_report_key && same_route(&entry->flow, wanted) &&
            (!result || entry->observed_ns > result->observed_ns))
            result = entry;
    }
    return result;
}

static struct server_cache_entry *find_newest_lookup_placeholder(struct server_agent *agent,
                                                                 const struct flow_key *flow,
                                                                 uint64_t cookie) {
    struct server_cache_entry *result = NULL;
    size_t start = route_hash(flow);
    for (size_t offset = 0; offset < SERVER_CACHE_CAPACITY; offset++) {
        struct server_cache_entry *entry =
            &agent->cache[(start + offset) & (SERVER_CACHE_CAPACITY - 1u)];
        if (entry->occupancy == 0)
            break;
        if (entry->occupancy == 1 && entry->socket_cookie == cookie && entry->has_lookup_key &&
            entry->lookup_observed && !entry->has_report_key && same_route(&entry->flow, flow) &&
            (!result || entry->lookup_observed_ns > result->lookup_observed_ns))
            result = entry;
    }
    return result;
}

static int observe_lookup_key(struct server_agent *agent, const struct flow_key *flow,
                              const uint8_t lookup_key[RA_KEY_SIZE], uint64_t observed_ns,
                              uint64_t cookie) {
    pthread_mutex_lock(&agent->cache_mutex);
    struct server_cache_entry *entry = find_lookup_entry(agent, lookup_key);
    if (entry && entry->lookup_observed) {
        int same = same_flow(&entry->flow, flow) && entry->socket_cookie == cookie;
        if (!same)
            agent->counters.duplicate_keys++;
        pthread_mutex_unlock(&agent->cache_mutex);
        return same;
    }
    if (!entry)
        entry = find_newest_report_orphan(agent, flow, cookie);
    if (!entry) {
        size_t slot = cache_new_slot(agent, flow);
        if (slot == SERVER_CACHE_CAPACITY) {
            agent->counters.cache_full++;
            pthread_mutex_unlock(&agent->cache_mutex);
            return 0;
        }
        entry = &agent->cache[slot];
        memset(entry, 0, sizeof(*entry));
        entry->occupancy = 1;
    }
    entry->flow = *flow;
    entry->socket_cookie = cookie;
    entry->has_lookup_key = 1;
    entry->lookup_observed = 1;
    memcpy(entry->lookup_key, lookup_key, RA_KEY_SIZE);
    entry->lookup_observed_ns = observed_ns;
    size_t slot = (size_t)(entry - agent->cache);
    if (!insert_lookup_index(agent, lookup_key, slot)) {
        memset(entry, 0, sizeof(*entry));
        entry->occupancy = 2;
        agent->counters.cache_full++;
        pthread_mutex_unlock(&agent->cache_mutex);
        return 0;
    }
    agent->counters.client_hellos++;
    log_protocol_key("client_hello", lookup_key);
    pthread_cond_broadcast(&agent->cache_changed);
    pthread_mutex_unlock(&agent->cache_mutex);
    return 1;
}

static struct server_cache_entry *find_report_generation(struct server_agent *agent,
                                                         const struct flow_key *flow,
                                                         const uint8_t report_key[RA_KEY_SIZE],
                                                         uint64_t cookie) {
    size_t start = route_hash(flow);
    for (size_t offset = 0; offset < SERVER_CACHE_CAPACITY; offset++) {
        struct server_cache_entry *entry =
            &agent->cache[(start + offset) & (SERVER_CACHE_CAPACITY - 1u)];
        if (entry->occupancy == 0)
            break;
        if (entry->occupancy == 1 && entry->socket_cookie == cookie && entry->has_report_key &&
            same_route(&entry->flow, flow) &&
            memcmp(entry->report_key, report_key, RA_KEY_SIZE) == 0)
            return entry;
    }
    return NULL;
}

static int enqueue_report(struct server_agent *agent, const struct report_job *job) {
    int ok = 0;
    pthread_mutex_lock(&agent->job_mutex);
    if (agent->job_count < SERVER_JOB_CAPACITY && !atomic_load(&agent->stopping)) {
        agent->jobs[agent->job_tail] = *job;
        agent->job_tail = (agent->job_tail + 1u) & (SERVER_JOB_CAPACITY - 1u);
        agent->job_count++;
        ok = 1;
        pthread_cond_signal(&agent->job_available);
    }
    pthread_mutex_unlock(&agent->job_mutex);
    return ok;
}

static void d_store_be64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint64_t d_utc_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void d_key_hex(const uint8_t key[RA_KEY_SIZE], char out[2 * RA_KEY_SIZE + 1]) {
    for (size_t i = 0; i < RA_KEY_SIZE; i++)
        snprintf(out + 2 * i, 3, "%02x", key[i]);
}

static int d_audit_user_data(const char *epoch, uint64_t seq, const uint8_t sh[RA_KEY_SIZE],
                             uint64_t t_mono, uint8_t out[RA_KEY_SIZE]) {
    static const char label[] = "tcp-level-ra/audit/v1";
    uint8_t be[8];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int n = 0;
    int ok = ctx != NULL && EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, label, sizeof(label) - 1) == 1 &&
             EVP_DigestUpdate(ctx, epoch, strlen(epoch)) == 1 && (d_store_be64(be, seq), 1) &&
             EVP_DigestUpdate(ctx, be, sizeof(be)) == 1 &&
             EVP_DigestUpdate(ctx, sh, RA_KEY_SIZE) == 1 && (d_store_be64(be, t_mono), 1) &&
             EVP_DigestUpdate(ctx, be, sizeof(be)) == 1 && EVP_DigestFinal_ex(ctx, out, &n) == 1 &&
             n == RA_KEY_SIZE;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static void d_write_record(struct server_agent *agent, struct server_cache_entry *entry, int ok,
                           uint64_t t_done) {
    if (!agent->deferred || !agent->d_records || !agent->d_index)
        return;
    char sh_hex[2 * RA_KEY_SIZE + 1];
    d_key_hex(entry->report_key, sh_hex);

    char ch_hex[2 * RA_KEY_SIZE + 1];
    ch_hex[0] = '\0';
    if (entry->has_lookup_key)
        d_key_hex(entry->lookup_key, ch_hex);
    fprintf(agent->d_records,
            "%" PRIu64 ",%s,%s,%" PRIu64 ",%" PRIu64 ",%d,%" PRIu64 ",%" PRIu64 "\n", entry->d_seq,
            ch_hex, sh_hex, entry->d_t_srv, entry->d_t_utc, ok, t_done - entry->report_start_ns,
            t_done);
    if (ok)
        fprintf(agent->d_index, "%" PRIu64 ",%s,%s,reports/%" PRIu64 ".bin\n", entry->d_seq, ch_hex,
                sh_hex, entry->d_seq);
    fflush(agent->d_records);
    fflush(agent->d_index);
    if (ok)
        agent->d_reports_ok++;
    else
        agent->d_reports_fail++;
}

static int schedule_report_locked(struct server_agent *agent, struct server_cache_entry *entry,
                                  size_t slot) {
    if (entry->report_start_ns || !entry->has_report_key ||
        (agent->mutual_ra && !entry->request_received))
        return 1;
    if (agent->deferred) {

        entry->d_seq = ++agent->d_seq;
        entry->d_t_srv = entry->observed_ns;
        entry->d_t_utc = d_utc_ns();
        if (!d_audit_user_data(agent->epoch, entry->d_seq, entry->report_key, entry->d_t_srv,
                               entry->attestation_key))
            return 0;
    } else if (agent->mutual_ra) {
        uint8_t client_report_key[RA_KEY_SIZE];
        if (!tcpra_early_client_report_key(entry->lookup_key, entry->request_nonce,
                                           client_report_key) ||
            !tcpra_early_server_report_key(entry->report_key, client_report_key,
                                           entry->attestation_key))
            return 0;
    } else {
        memcpy(entry->attestation_key, entry->report_key, RA_KEY_SIZE);
    }
    struct report_job job = {
        .slot = slot,
        .flow = entry->flow,
    };
    memcpy(job.report_key, entry->attestation_key, RA_KEY_SIZE);
    entry->report_start_ns = tcpra_now_ns();
    if (!enqueue_report(agent, &job)) {
        agent->counters.report_queue_full++;
        entry->report_done_ns = tcpra_now_ns();
        return 0;
    }
    return 1;
}

static int observe_report_key(struct server_agent *agent, const struct flow_key *flow,
                              const uint8_t report_key[RA_KEY_SIZE], uint64_t observed_ns,
                              uint64_t cookie) {
    pthread_mutex_lock(&agent->cache_mutex);
    struct server_cache_entry *entry = find_report_generation(agent, flow, report_key, cookie);
    if (entry) {
        agent->counters.duplicate_keys++;
        pthread_mutex_unlock(&agent->cache_mutex);
        return 1;
    }
    entry = find_newest_lookup_placeholder(agent, flow, cookie);
    size_t slot;
    if (entry) {
        slot = (size_t)(entry - agent->cache);

        entry->flow = *flow;
    } else {
        slot = cache_new_slot(agent, flow);
        if (slot == SERVER_CACHE_CAPACITY) {
            agent->counters.cache_full++;
            pthread_mutex_unlock(&agent->cache_mutex);
            return 0;
        }
        entry = &agent->cache[slot];
        memset(entry, 0, sizeof(*entry));
        entry->occupancy = 1;
        entry->flow = *flow;
    }
    entry->has_report_key = 1;
    entry->socket_cookie = cookie;
    memcpy(entry->report_key, report_key, RA_KEY_SIZE);
    entry->observed_ns = observed_ns;
    int scheduled = schedule_report_locked(agent, entry, slot);
    pthread_cond_broadcast(&agent->cache_changed);
    pthread_mutex_unlock(&agent->cache_mutex);
    return scheduled;
}

static void *report_worker_main(void *opaque) {
    struct server_agent *agent = opaque;
    for (;;) {
        pthread_mutex_lock(&agent->job_mutex);
        while (!agent->job_count && !atomic_load(&agent->stopping))
            pthread_cond_wait(&agent->job_available, &agent->job_mutex);
        if (!agent->job_count && atomic_load(&agent->stopping)) {
            pthread_mutex_unlock(&agent->job_mutex);
            break;
        }
        struct report_job job = agent->jobs[agent->job_head];
        agent->job_head = (agent->job_head + 1u) & (SERVER_JOB_CAPACITY - 1u);
        agent->job_count--;
        pthread_mutex_unlock(&agent->job_mutex);

        uint8_t report[RA_REPORT_SIZE];
        struct prof_stamp service_start = prof_start();
        int ok = tcpra_csv_generate_report(&agent->reporter, job.report_key, report);
        prof_end("report_service", job.flow.client_port, ok, service_start);
        uint64_t finished = tcpra_now_ns();
        pthread_mutex_lock(&agent->cache_mutex);
        struct server_cache_entry *entry = &agent->cache[job.slot];
        if (entry->occupancy == 1 && same_flow(&entry->flow, &job.flow) &&
            memcmp(entry->attestation_key, job.report_key, RA_KEY_SIZE) == 0) {
            if (ok) {
                memcpy(entry->report, report, RA_REPORT_SIZE);
                entry->ready = 1;
            } else {
                agent->counters.report_failures++;
            }
            entry->report_done_ns = finished;
            if (agent->deferred) {
                if (ok) {
                    char path[600];
                    snprintf(path, sizeof(path), "%s/reports/%" PRIu64 ".bin", agent->dlog_dir,
                             entry->d_seq);
                    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (fd < 0) {
                        ok = 0;
                    } else {
                        ssize_t written = write(fd, report, RA_REPORT_SIZE);
                        if (fsync(fd) != 0 || written != RA_REPORT_SIZE)
                            ok = 0;
                        close(fd);
                    }
                }
                d_write_record(agent, entry, ok, finished);
            }
            pthread_cond_broadcast(&agent->cache_changed);
        }
        pthread_mutex_unlock(&agent->cache_mutex);
    }
    return NULL;
}

static int register_request(struct server_agent *agent, const struct ra_request *request) {
    uint64_t started = tcpra_now_ns();
    int status = RA_NOT_FOUND;
    pthread_mutex_lock(&agent->cache_mutex);
    for (;;) {
        struct server_cache_entry *entry = find_lookup_entry(agent, request->lookup_key);
        if (entry && entry->lookup_observed && !entry->request_received) {
            uint64_t current_cookie;
            if (tcpra_now_ns() - entry->lookup_observed_ns >= RA_WINDOW_NS ||
                !tcpra_socket_cookie(&entry->flow, 1, &current_cookie) ||
                current_cookie != entry->socket_cookie) {
                status = RA_BAD_BINDING;
                break;
            }
            entry->request_received = 1;
            entry->request_ns = started;
            entry->request_nonce = request->client_nonce;
            size_t slot = (size_t)(entry - agent->cache);
            status = schedule_report_locked(agent, entry, slot) ? RA_OK : RA_INTERNAL;
            pthread_cond_broadcast(&agent->cache_changed);
            break;
        }
        if (entry && entry->request_received) {
            status = RA_BAD_BINDING;
            break;
        }
        if (atomic_load(&agent->stopping) || tcpra_now_ns() - started >= RA_WINDOW_NS)
            break;
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_nsec += 5 * 1000 * 1000;
        if (deadline.tv_nsec >= 1000000000l) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000l;
        }
        pthread_cond_timedwait(&agent->cache_changed, &agent->cache_mutex, &deadline);
    }
    pthread_mutex_unlock(&agent->cache_mutex);
    return status;
}

static int wait_for_report(struct server_agent *agent, const struct ra_request *request,
                           struct server_cache_entry *snapshot) {
    uint64_t started = tcpra_now_ns();
    int status = RA_NOT_FOUND;
    pthread_mutex_lock(&agent->cache_mutex);
    for (;;) {
        struct server_cache_entry *entry = find_lookup_entry(agent, request->lookup_key);
        if (entry && entry->request_received && entry->ready && !entry->delivered) {
            uint64_t current_cookie;
            if (entry->request_nonce != request->client_nonce ||
                tcpra_now_ns() - entry->lookup_observed_ns >= RA_WINDOW_NS ||
                !tcpra_socket_cookie(&entry->flow, 1, &current_cookie) ||
                current_cookie != entry->socket_cookie) {
                status = RA_BAD_BINDING;
                break;
            }
            entry->delivered = 1;
            *snapshot = *entry;
            status = RA_OK;
            break;
        }
        if (entry && entry->report_done_ns && !entry->ready) {
            status = RA_INTERNAL;
            break;
        }
        if (atomic_load(&agent->stopping) || tcpra_now_ns() - started >= RA_WINDOW_NS) {
            status = RA_NOT_FOUND;
            break;
        }
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_nsec += 5 * 1000 * 1000;
        if (deadline.tv_nsec >= 1000000000l) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000l;
        }
        pthread_cond_timedwait(&agent->cache_changed, &agent->cache_mutex, &deadline);
    }
    pthread_mutex_unlock(&agent->cache_mutex);
    return status;
}

static void mark_response_sent(struct server_agent *agent, const struct ra_request *request) {
    pthread_mutex_lock(&agent->cache_mutex);
    struct server_cache_entry *entry = find_lookup_entry(agent, request->lookup_key);
    if (entry && entry->delivered)
        entry->response_ns = tcpra_now_ns();
    pthread_mutex_unlock(&agent->cache_mutex);
}

static void record_verdict(struct server_agent *agent, const struct ra_request *request,
                           const struct ra_verdict *verdict, int client_report_verified) {
    pthread_mutex_lock(&agent->cache_mutex);
    struct server_cache_entry *entry = find_lookup_entry(agent, request->lookup_key);
    if (!entry || !entry->delivered ||
        memcmp(entry->lookup_key, verdict->lookup_key, RA_KEY_SIZE) != 0 ||
        agent->completed_sessions >= agent->expected_sessions) {
        pthread_mutex_unlock(&agent->cache_mutex);
        return;
    }

    entry->admitted = ntohl(verdict->verified) == 1;
    entry->verdict_ns = tcpra_now_ns();
    struct completed_record *record = &agent->records[agent->completed_sessions];
    record->session = agent->completed_sessions + 1;
    record->admitted = entry->admitted;
    record->client_report_verified = client_report_verified;
    record->flow = entry->flow;
    record->observed_ns = entry->observed_ns;
    record->report_start_ns = entry->report_start_ns;
    record->report_done_ns = entry->report_done_ns;
    record->request_ns = entry->request_ns;
    record->response_ns = entry->response_ns;
    record->verdict_ns = entry->verdict_ns;
    agent->completed_sessions++;
    delete_lookup_index(agent, entry->lookup_key);
    memset(entry, 0, sizeof(*entry));
    entry->occupancy = 2;
    pthread_cond_broadcast(&agent->cache_changed);
    pthread_mutex_unlock(&agent->cache_mutex);
}

static void remove_control(struct server_agent *agent, size_t slot) {
    pthread_mutex_lock(&agent->control_mutex);
    agent->control_fds[slot] = -1;
    if (agent->active_controls)
        agent->active_controls--;
    pthread_cond_broadcast(&agent->controls_stopped);
    pthread_mutex_unlock(&agent->control_mutex);
}

static int receive_early_client_report(int fd, const struct ra_request *request,
                                       uint8_t client_report[RA_REPORT_SIZE]) {
    if (ntohs(request->version) != RA_MRA_VERSION)
        return 0;
    return tcpra_read_all(fd, client_report, RA_REPORT_SIZE);
}

static int verify_early_client_report(struct server_agent *agent, const struct ra_request *request,
                                      const uint8_t client_report[RA_REPORT_SIZE]) {
    uint8_t expected[RA_KEY_SIZE];
    int verified =
        tcpra_early_client_report_key(request->lookup_key, request->client_nonce, expected) &&
        tcpra_csv_verify_report(&agent->reporter, client_report, expected);
    if (verified)
        agent->counters.client_reports_verified++;
    else
        agent->counters.client_report_failures++;

    return verified;
}

static void *control_worker_main(void *opaque) {
    struct control_argument *argument = opaque;
    struct server_agent *agent = argument->agent;
    int fd = argument->fd;
    size_t slot = argument->slot;
    free(argument);
    while (!atomic_load(&agent->stopping)) {
        struct ra_request request;
        if (!tcpra_read_all(fd, &request, sizeof(request)) || ntohl(request.magic) != RA_MAGIC ||
            !((ntohs(request.type) == RA_REQUEST && ntohs(request.version) == RA_VERSION) ||
              (ntohs(request.type) == RA_MUTUAL_REQUEST &&
               ntohs(request.version) == RA_MRA_VERSION)))
            break;
        int mutual = ntohs(request.type) == RA_MUTUAL_REQUEST;
        if (mutual != agent->mutual_ra)
            break;
        log_protocol_key("request", request.lookup_key);
        int status = register_request(agent, &request);
        if (status != RA_OK) {
            struct ra_response failed = {
                .magic = htonl(RA_MAGIC),
                .version = request.version,
                .type = htons(RA_RESPONSE),
                .status = htonl((uint32_t)status),
            };
            tcpra_write_all(fd, &failed, sizeof(failed));
            break;
        }
        uint8_t client_report[RA_REPORT_SIZE];
        if (mutual && !receive_early_client_report(fd, &request, client_report))
            break;
        struct server_cache_entry snapshot;
        memset(&snapshot, 0, sizeof(snapshot));
        status = wait_for_report(agent, &request, &snapshot);
        int client_report_verified = !mutual;
        if (status == RA_OK && mutual) {
            client_report_verified = verify_early_client_report(agent, &request, client_report);
            if (!client_report_verified)
                status = RA_CLIENT_REPORT_INVALID;
        }
        struct ra_response response = {
            .magic = htonl(RA_MAGIC),
            .version = request.version,
            .type = htons(RA_RESPONSE),
            .status = htonl((uint32_t)status),
        };
        if (status == RA_OK) {
            response.report_len = htonl(RA_REPORT_SIZE);
            response.generated_ns = tcpra_network_u64(snapshot.report_done_ns);
            memcpy(response.report_key, snapshot.attestation_key, RA_KEY_SIZE);
        }
        int sent = status == RA_OK ? tcpra_write_pair(fd, &response, sizeof(response),
                                                      snapshot.report, RA_REPORT_SIZE)
                                   : tcpra_write_all(fd, &response, sizeof(response));
        if (!sent || status != RA_OK)
            break;
        mark_response_sent(agent, &request);
        struct ra_verdict verdict;
        if (!tcpra_read_all(fd, &verdict, sizeof(verdict)) || ntohl(verdict.magic) != RA_MAGIC ||
            verdict.version != request.version || ntohs(verdict.type) != RA_VERDICT ||
            verdict.client_nonce != request.client_nonce ||
            memcmp(verdict.lookup_key, request.lookup_key, RA_KEY_SIZE) != 0)
            break;
        record_verdict(agent, &request, &verdict, client_report_verified);
    }
    shutdown(fd, SHUT_RDWR);
    close(fd);
    remove_control(agent, slot);
    return NULL;
}

static int reserve_control_slot(struct server_agent *agent, int fd, size_t *slot) {
    int ok = 0;
    pthread_mutex_lock(&agent->control_mutex);
    for (size_t index = 0; index < SERVER_CONTROL_CAPACITY; index++) {
        if (agent->control_fds[index] < 0) {
            agent->control_fds[index] = fd;
            agent->active_controls++;
            *slot = index;
            ok = 1;
            break;
        }
    }
    pthread_mutex_unlock(&agent->control_mutex);
    return ok;
}

static void *accept_worker_main(void *opaque) {
    struct server_agent *agent = opaque;
    while (!atomic_load(&agent->stopping)) {
        int fd = accept4(agent->listener, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        int enabled = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
        size_t slot;
        if (!reserve_control_slot(agent, fd, &slot)) {
            close(fd);
            continue;
        }
        struct control_argument *argument = malloc(sizeof(*argument));
        if (!argument) {
            close(fd);
            remove_control(agent, slot);
            continue;
        }
        *argument = (struct control_argument){
            .agent = agent,
            .fd = fd,
            .slot = slot,
        };
        pthread_t thread;
        if (pthread_create(&thread, NULL, control_worker_main, argument) == 0) {
            pthread_detach(thread);
        } else {
            free(argument);
            close(fd);
            remove_control(agent, slot);
        }
    }
    return NULL;
}

static void stop_control_threads(struct server_agent *agent) {
    atomic_store(&agent->stopping, 1);
    if (agent->listener >= 0) {
        shutdown(agent->listener, SHUT_RDWR);
        close(agent->listener);
        agent->listener = -1;
    }
    if (agent->accept_thread_started)
        pthread_join(agent->accept_thread, NULL);
    pthread_mutex_lock(&agent->control_mutex);
    for (size_t index = 0; index < SERVER_CONTROL_CAPACITY; index++) {
        if (agent->control_fds[index] >= 0)
            shutdown(agent->control_fds[index], SHUT_RDWR);
    }
    while (agent->active_controls)
        pthread_cond_wait(&agent->controls_stopped, &agent->control_mutex);
    pthread_mutex_unlock(&agent->control_mutex);
}

static int server_key_from_pcap_impl(void *opaque, const struct flow_key *flow, uint16_t group_id,
                                     const uint8_t *public_key, size_t public_key_length,
                                     uint64_t observed_ns, uint64_t cookie) {
    struct server_agent *agent = opaque;
    uint8_t report_key[RA_KEY_SIZE];
    if (!tcpra_report_key_from_public(group_id, public_key, public_key_length, report_key))
        return 0;
    int observed = observe_report_key(agent, flow, report_key, observed_ns, cookie);
    if (observed) {
        agent->counters.server_hellos++;
    }
    return observed;
}
static int server_key_from_pcap(void *opaque, const struct flow_key *flow, uint16_t group_id,
                                const uint8_t *public_key, size_t public_key_length,
                                uint64_t observed_ns, uint64_t cookie) {
    struct prof_stamp t = prof_start();
    int ok = server_key_from_pcap_impl(opaque, flow, group_id, public_key, public_key_length,
                                       observed_ns, cookie);
    prof_end("server_key_from_pcap", flow->client_port, ok, t);
    return ok;
}

static int server_lookup_from_pcap_impl(void *opaque, const struct flow_key *flow,
                                        const uint8_t lookup_key[RA_KEY_SIZE], uint64_t observed_ns,
                                        uint64_t cookie) {
    return observe_lookup_key((struct server_agent *)opaque, flow, lookup_key, observed_ns, cookie);
}
static int server_lookup_from_pcap(void *opaque, const struct flow_key *flow,
                                   const uint8_t lookup_key[RA_KEY_SIZE], uint64_t observed_ns,
                                   uint64_t cookie) {
    struct prof_stamp t = prof_start();
    int ok = server_lookup_from_pcap_impl(opaque, flow, lookup_key, observed_ns, cookie);
    prof_end("server_lookup_from_pcap", flow->client_port, ok, t);
    return ok;
}

static int write_ready_file(const char *path) {
    if (!path)
        return 1;
    FILE *file = fopen(path, "w");
    if (!file)
        return 0;
    fprintf(file, "%ld\n", (long)getpid());
    return fclose(file) == 0;
}

static int write_results(struct server_agent *agent) {
    FILE *output = fopen(agent->csv_path, "w");
    if (!output)
        return 0;
    fputs("session,mode,verified,client_port,server_port,observed_ns,report_start_ns,report_done_"
          "ns,request_ns,response_ns,verdict_ns,report_generation_ns,request_to_response_ns,total_"
          "control_ns,mutual_ra,client_report_verified\n",
          output);
    for (int index = 0; index < agent->completed_sessions; index++) {
        const struct completed_record *record = &agent->records[index];
        fprintf(output, "%d,%s,%d,%u,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%d,%d\n",
                record->session,
                agent->mutual_ra ? "nfqset-mra" : (agent->mode == MODE_NIRA ? "nira" : "nirak"),
                record->admitted, record->flow.client_port, record->flow.server_port,
                (unsigned long long)record->observed_ns,
                (unsigned long long)record->report_start_ns,
                (unsigned long long)record->report_done_ns, (unsigned long long)record->request_ns,
                (unsigned long long)record->response_ns, (unsigned long long)record->verdict_ns,
                (unsigned long long)(record->report_done_ns >= record->report_start_ns
                                         ? record->report_done_ns - record->report_start_ns
                                         : 0),
                (unsigned long long)(record->response_ns >= record->request_ns
                                         ? record->response_ns - record->request_ns
                                         : 0),
                (unsigned long long)(record->verdict_ns >= record->request_ns
                                         ? record->verdict_ns - record->request_ns
                                         : 0),
                agent->mutual_ra, record->client_report_verified);
    }
    return fclose(output) == 0;
}

static enum tcpra_mode parse_mode(const char *text) {
    if (text && strcmp(text, "nira") == 0)
        return MODE_NIRA;
    if (text && strcmp(text, "nirak") == 0)
        return MODE_NIRAK;
    if (text && strcmp(text, "deferred") == 0)
        return MODE_DEFERRED;
    return 0;
}

static int parse_unsigned(const char *text, unsigned long maximum, unsigned long *value) {
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(text, &end, 10);
    if (errno || !text || !*text || !end || *end || parsed > maximum)
        return 0;
    *value = parsed;
    return 1;
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage: %s --mode nira|nirak --server-ip IP --ra-port PORT "
            "--main-port PORT --expected N --csv PATH [--queue N] "
            "[--flow-bpf OBJ --pin-dir DIR] "
            "[--ready-file PATH] [--mutual-ra] "
            "deferred: --mode deferred --epoch ID --dlog DIR\n",
            program);
}

int main(int argc, char **argv) {
    struct server_agent *agent_storage = calloc(1, sizeof(*agent_storage));
    if (!agent_storage)
        return 2;
#define agent (*agent_storage)

    if (!freopen("/dev/null", "w", stdout)) {
        free(agent_storage);
        return 2;
    }
    agent.listener = -1;
    for (size_t index = 0; index < SERVER_CONTROL_CAPACITY; index++)
        agent.control_fds[index] = -1;
    static const struct option options[] = {
        {"mode", required_argument, NULL, 'M'},
        {"server-ip", required_argument, NULL, 'a'},
        {"ra-port", required_argument, NULL, 'r'},
        {"main-port", required_argument, NULL, 'p'},
        {"queue", required_argument, NULL, 'q'},
        {"expected", required_argument, NULL, 'n'},
        {"csv", required_argument, NULL, 'o'},
        {"flow-bpf", required_argument, NULL, 'b'},
        {"pin-dir", required_argument, NULL, 'd'},
        {"ready-file", required_argument, NULL, 'R'},
        {"mutual-ra", no_argument, NULL, 'u'},
        {"epoch", required_argument, NULL, 'e'},
        {"dlog", required_argument, NULL, 'g'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    int option;
    while ((option = getopt_long(argc, argv, "M:a:r:p:q:n:o:b:d:R:e:g:uh", options, NULL)) != -1) {
        unsigned long value = 0;
        switch (option) {
        case 'M':
            agent.mode = parse_mode(optarg);
            break;
        case 'a':
            agent.server_ip = optarg;
            break;
        case 'r':
            if (!parse_unsigned(optarg, UINT16_MAX, &value))
                return 2;
            agent.ra_port = (uint16_t)value;
            break;
        case 'p':
            if (!parse_unsigned(optarg, UINT16_MAX, &value))
                return 2;
            agent.main_port = (uint16_t)value;
            break;
        case 'q':
            if (!parse_unsigned(optarg, UINT16_MAX, &value))
                return 2;
            agent.queue_number = (uint16_t)value;
            break;
        case 'n':
            if (!parse_unsigned(optarg, 1000000, &value))
                return 2;
            agent.expected_sessions = (int)value;
            break;
        case 'o':
            agent.csv_path = optarg;
            break;
        case 'b':
            agent.flow_bpf_object = optarg;
            break;
        case 'd':
            agent.pin_directory = optarg;
            break;
        case 'R':
            agent.ready_file = optarg;
            break;
        case 'e':
            agent.epoch_arg = optarg;
            break;
        case 'g':
            agent.dlog_arg = optarg;
            break;
        case 'u':
            agent.mutual_ra = 1;
            break;
        case 'h':
            usage(argv[0]);
            free(agent_storage);
            return 0;
        default:
            usage(argv[0]);
            return 2;
        }
    }
    agent.deferred = agent.mode == MODE_DEFERRED;
    if (optind != argc || !agent.mode || !agent.server_ip || (!agent.ra_port && !agent.deferred) ||
        !agent.main_port || !agent.expected_sessions || !agent.csv_path ||
        ((agent.flow_bpf_object == NULL) != (agent.pin_directory == NULL)) ||
        (agent.deferred && (agent.mutual_ra || !agent.epoch_arg || !agent.dlog_arg))) {
        usage(argv[0]);
        return 2;
    }
    pthread_mutex_init(&agent.cache_mutex, NULL);
    pthread_cond_init(&agent.cache_changed, NULL);
    pthread_mutex_init(&agent.job_mutex, NULL);
    pthread_cond_init(&agent.job_available, NULL);
    pthread_mutex_init(&agent.control_mutex, NULL);
    pthread_cond_init(&agent.controls_stopped, NULL);
    agent.records = calloc((size_t)agent.expected_sessions, sizeof(*agent.records));
    if (!agent.records || !tcpra_csv_context_open(&agent.reporter, 1))
        goto fail;
    if ((agent.mode != MODE_NIRA && agent.mode != MODE_DEFERRED) || agent.flow_bpf_object ||
        agent.pin_directory)
        goto fail;
    if (agent.deferred) {
        if (strlen(agent.epoch_arg) >= sizeof(agent.epoch) ||
            strlen(agent.dlog_arg) >= sizeof(agent.dlog_dir))
            goto fail;
        strncpy(agent.epoch, agent.epoch_arg, sizeof(agent.epoch) - 1);
        strncpy(agent.dlog_dir, agent.dlog_arg, sizeof(agent.dlog_dir) - 1);
        mkdir(agent.dlog_dir, 0755);
        char sub[600];
        snprintf(sub, sizeof(sub), "%s/reports", agent.dlog_dir);
        mkdir(sub, 0755);
        snprintf(sub, sizeof(sub), "%s/records.csv", agent.dlog_dir);
        agent.d_records = fopen(sub, "w");
        snprintf(sub, sizeof(sub), "%s/index.csv", agent.dlog_dir);
        agent.d_index = fopen(sub, "w");
        snprintf(sub, sizeof(sub), "%s/epoch", agent.dlog_dir);
        FILE *epoch_file = fopen(sub, "w");
        if (!agent.d_records || !agent.d_index) {
            goto fail;
        }
        if (epoch_file) {
            fprintf(epoch_file, "%s\n", agent.epoch);
            fclose(epoch_file);
        }
        fprintf(agent.d_records, "seq,ch_key,sh_key,t_srv_mono_ns,t_srv_utc_ns,report_ok,"
                                 "report_gen_ns,t_report_done_ns\n");
        fprintf(agent.d_index, "seq,ch_key,sh_key,report_file\n");
    }
    if (!(agent.pcap =
              tcpra_pcap_observer_open(agent.server_ip, agent.main_port, server_lookup_from_pcap,
                                       server_key_from_pcap, &agent))) {
        goto fail;
    }
    if (!agent.deferred) {
        agent.listener = tcpra_listen_tcp(agent.ra_port, 128);
        if (agent.listener < 0)
            goto fail;
    }
    if (pthread_create(&agent.report_thread, NULL, report_worker_main, &agent) != 0)
        goto fail;
    agent.report_thread_started = 1;
    if (!agent.deferred) {
        if (pthread_create(&agent.accept_thread, NULL, accept_worker_main, &agent) != 0)
            goto fail;
        agent.accept_thread_started = 1;
    }
    if (!write_ready_file(agent.ready_file))
        goto fail;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    fprintf(stderr, "tcpra_server_agent_ready mode=%s pid=%ld ra_port=%u\n",
            agent.mutual_ra ? "nfqset-mra"
                            : (agent.mode == MODE_NIRA       ? "nira"
                               : agent.mode == MODE_DEFERRED ? "deferred"
                                                             : "nirak"),
            (long)getpid(), agent.ra_port);
    while (!signal_stop) {
        int polled = tcpra_pcap_observer_poll(agent.pcap, 100);
        if (polled < 0 && polled != -EINTR)
            break;
    }

    stop_control_threads(&agent);
    atomic_store(&agent.stopping, 1);
    pthread_mutex_lock(&agent.job_mutex);
    pthread_cond_broadcast(&agent.job_available);
    pthread_mutex_unlock(&agent.job_mutex);
    pthread_mutex_lock(&agent.cache_mutex);
    pthread_cond_broadcast(&agent.cache_changed);
    pthread_mutex_unlock(&agent.cache_mutex);
    if (agent.report_thread_started)
        pthread_join(agent.report_thread, NULL);
    int all_admitted = 1;
    if (!agent.deferred)
        for (int index = 0; index < agent.completed_sessions; index++)
            if (!agent.records[index].admitted)
                all_admitted = 0;
    int complete =
        agent.deferred
            ? (agent.d_seq == (uint64_t)agent.expected_sessions &&
               agent.d_reports_ok == agent.expected_sessions &&
               agent.counters.server_hellos == (unsigned long long)agent.expected_sessions &&
               agent.counters.report_failures == 0)
            : (agent.completed_sessions == agent.expected_sessions && all_admitted &&
               agent.counters.client_hellos == (unsigned long long)agent.expected_sessions &&
               agent.counters.server_hellos == (unsigned long long)agent.expected_sessions &&
               (!agent.mutual_ra || agent.counters.client_reports_verified ==
                                        (unsigned long long)agent.expected_sessions) &&
               agent.counters.client_report_failures == 0 && agent.counters.report_failures == 0 &&
               agent.counters.enobufs == 0);
    write_results(&agent);
    unsigned long long pcap_received = 0, pcap_dropped = 0;
    unsigned long long ch_split = 0, ch_reassembled = 0;
    tcpra_pcap_observer_counters(agent.pcap, &agent.counters.copied_packets,
                                 &agent.counters.copied_bytes, &pcap_received, &pcap_dropped,
                                 &ch_split, &ch_reassembled);
    if (pcap_dropped)
        complete = 0;
    if (agent.deferred) {
        if (agent.d_records) {
            fflush(agent.d_records);
            fsync(fileno(agent.d_records));
            fclose(agent.d_records);
            agent.d_records = NULL;
        }
        if (agent.d_index) {
            fflush(agent.d_index);
            fsync(fileno(agent.d_index));
            fclose(agent.d_index);
            agent.d_index = NULL;
        }
        fprintf(stderr, "D_SUMMARY records=%llu reports_ok=%ld reports_fail=%ld\n",
                (unsigned long long)agent.d_seq, agent.d_reports_ok, agent.d_reports_fail);
    }
    fprintf(stderr,
            "completed=%d copied_packets=%llu copied_bytes=%llu "
            "client_hellos=%llu server_hellos=%llu reports_failed=%llu map_deletes=%llu "
            "client_reports_verified=%llu client_report_failures=%llu "
            "map_delete_misses=%llu enobufs=%llu "
            "pcap_received=%llu pcap_dropped=%llu ch_split=%llu ch_reassembled=%llu\n",
            agent.completed_sessions, agent.counters.copied_packets, agent.counters.copied_bytes,
            agent.counters.client_hellos, agent.counters.server_hellos,
            agent.counters.report_failures, agent.counters.map_deletes,
            agent.counters.client_reports_verified, agent.counters.client_report_failures,
            agent.counters.map_delete_misses, agent.counters.enobufs, pcap_received, pcap_dropped,
            ch_split, ch_reassembled);
    if (agent.ready_file)
        unlink(agent.ready_file);
    tcpra_pcap_observer_close(agent.pcap);
    tcpra_csv_context_close(&agent.reporter);
    free(agent.records);
    pthread_cond_destroy(&agent.controls_stopped);
    pthread_mutex_destroy(&agent.control_mutex);
    pthread_cond_destroy(&agent.job_available);
    pthread_mutex_destroy(&agent.job_mutex);
    pthread_cond_destroy(&agent.cache_changed);
    pthread_mutex_destroy(&agent.cache_mutex);
    free(agent_storage);
    return complete ? 0 : 3;

fail:
    fprintf(stderr, "tcpra_server_agent initialization failed: %s\n", strerror(errno));
    signal_stop = 1;
    atomic_store(&agent.stopping, 1);
    if (agent.listener >= 0) {
        shutdown(agent.listener, SHUT_RDWR);
        close(agent.listener);
    }
    pthread_mutex_lock(&agent.job_mutex);
    pthread_cond_broadcast(&agent.job_available);
    pthread_mutex_unlock(&agent.job_mutex);
    if (agent.accept_thread_started)
        pthread_join(agent.accept_thread, NULL);
    if (agent.report_thread_started)
        pthread_join(agent.report_thread, NULL);
    if (agent.ready_file)
        unlink(agent.ready_file);
    tcpra_pcap_observer_close(agent.pcap);
    tcpra_csv_context_close(&agent.reporter);
    free(agent.records);
    pthread_cond_destroy(&agent.controls_stopped);
    pthread_mutex_destroy(&agent.control_mutex);
    pthread_cond_destroy(&agent.job_available);
    pthread_mutex_destroy(&agent.job_mutex);
    pthread_cond_destroy(&agent.cache_changed);
    pthread_mutex_destroy(&agent.cache_mutex);
    free(agent_storage);
    return 2;
#undef agent
}
