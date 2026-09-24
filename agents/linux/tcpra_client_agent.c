#define _GNU_SOURCE
#include "profile.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "csv_attestation.h"
#include "flow_selector.h"
#include "packet_view.h"
#include "tls_parse.h"
#include "wire_io.h"
#include "linux_safety.h"

#define CLIENT_FLOW_CAPACITY 8192u
#define CLIENT_JOB_CAPACITY 8192u
#define CLIENT_DECISION_CAPACITY 8192u
#define MAX_HELD_PACKETS 512u
#define RECEIVE_BUFFER_SIZE (1u << 20)
#define DEFAULT_TIMEOUT_MS 30000u
#define DEFAULT_WORKERS 1u

#ifndef TCPRA_DYNAMIC_MODE_NAME
#define TCPRA_DYNAMIC_MODE_NAME "nirak"
#endif
#ifndef TCPRA_MUTUAL_MODE_NAME
#define TCPRA_MUTUAL_MODE_NAME "nirak-mra"
#endif
#ifndef TCPRA_SELECTOR_CLOSE_CLEANUP
#define TCPRA_SELECTOR_CLOSE_CLEANUP 0
#endif

enum tcpra_mode { MODE_NIRA = 1, MODE_NIRAK = 2 };
enum gate_state {
    GATE_HANDSHAKE = 1,
    GATE_SERVER_HELLO = 2,
    GATE_ADMITTED = 3,
    GATE_DENIED = 4,
};

struct client_agent;

struct client_session {
    struct client_agent *agent;
    struct client_session *next;
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    struct flow_key flow;
    uint8_t lookup_key[RA_KEY_SIZE];
    uint8_t local_report_key[RA_KEY_SIZE];
    uint8_t response_report_key[RA_KEY_SIZE];
    uint8_t client_report_key[RA_KEY_SIZE];
    int id;
    int has_server_hello;
    int decision_applied;
    int gate_allowed;
    int finalized;
    int cancelled;
    int response_status;
    int key_match;
    int report_verify;
    int client_report_generated;
    int client_report_accepted;
    int remote_verdict_sent;
    int control_worker;
    int control_reused;
    int success;
    uint32_t report_length;
    uint64_t request_id;
    uint64_t clienthello_observed_ns;
    uint64_t request_start_ns;
    uint64_t request_sent_ns;
    uint64_t response_header_ns;
    uint64_t response_done_ns;
    uint64_t serverhello_observed_ns;
    uint64_t verify_start_ns;
    uint64_t verify_done_ns;
    uint64_t decision_queued_ns;
    uint64_t local_decision_ns;
    uint64_t remote_verdict_ns;
    uint64_t finished_ns;
    uint64_t selector_delete_ns;
    uint64_t client_report_generation_ns;
    uint64_t early_report_send_ns;
};

struct client_worker {
    struct client_agent *agent;
    pthread_t thread;
    int index;
    int fd;
    int started;
    unsigned uses;
};

struct gate_flow {
    uint8_t occupancy;
    uint8_t client_hello_seen;
    uint8_t server_hello_seen;
    uint8_t reserved;
    enum gate_state state;
    struct flow_key key;
    uint8_t lookup_key[RA_KEY_SIZE];
    uint8_t report_key[RA_KEY_SIZE];
    uint64_t state_ns;
    uint64_t deadline_ns;
    uint64_t socket_cookie;
    uint32_t held_ids[MAX_HELD_PACKETS];
    size_t held_count;
};

#include "client_audit.h"

struct client_counters {
    unsigned long long copied_packets;
    unsigned long long copied_bytes;
    unsigned long long accepted_packets;
    unsigned long long dropped_packets;
    unsigned long long held_packets;
    unsigned long long released_packets;
    unsigned long long client_hellos;
    unsigned long long server_hellos;
    unsigned long long decisions_allowed;
    unsigned long long decisions_denied;
    unsigned long long decision_mismatches;
    unsigned long long timeouts;
    unsigned long long flow_map_deletes;
    unsigned long long flow_map_delete_misses;
    unsigned long long close_cleanup_deletes;
    unsigned long long close_cleanup_delete_misses;
    unsigned long long flow_generation_resets;
    unsigned long long flow_table_full;
    unsigned long long held_table_full;
    unsigned long long job_queue_full;
    unsigned long long enobufs;
};

struct client_agent {
    int audit_only;
    const char *audit_epoch, *audit_directory;
    struct client_audit audit;
    int endpoint_quarantined;
    enum tcpra_mode mode;
    const char *server_host;
    uint16_t main_port;
    uint16_t ra_port;
    uint16_t queue_number;
    int expected_sessions;
    int mutual_ra;
    uint32_t timeout_ms;
    uint64_t timeout_ns;
    const char *csv_path;
    const char *ready_file;
    const char *flow_bpf_object;
    const char *pin_directory;
    struct sockaddr_in ra_server;
    struct tcpra_csv_context verifier;
    struct tcpra_flow_selector *selector;

    pthread_mutex_t session_mutex;
    pthread_cond_t progress;
    struct client_session *sessions;
    int started_sessions;
    int completed_sessions;
    int verified_sessions;
    int failed_sessions;

    pthread_mutex_t job_mutex;
    pthread_cond_t job_available;
    struct client_session *jobs[CLIENT_JOB_CAPACITY];
    size_t job_head, job_tail, job_count;
    struct client_worker *workers;
    size_t worker_count;

    pthread_mutex_t decision_mutex;
    struct client_session *decisions[CLIENT_DECISION_CAPACITY];
    size_t decision_head, decision_tail, decision_count;
    int decision_event_fd;

    struct gate_flow flows[CLIENT_FLOW_CAPACITY];
    struct client_counters counters;
    struct nfq_handle *nfq_handle;
    struct nfq_q_handle *nfq_queue;
    int nfq_fd;
    uint8_t *nfq_buffer;
    uint64_t last_expiry_scan_ns;
    atomic_int stopping;
};

static volatile sig_atomic_t signal_stop;

static void on_signal(int signal_number) {
    (void)signal_number;
    signal_stop = 1;
}

static int same_flow(const struct flow_key *left, const struct flow_key *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

static size_t flow_hash(const struct flow_key *flow) {
    uint64_t value = flow->client_ip ^ ((uint64_t)flow->server_ip << 1);
    value ^= ((uint64_t)flow->client_port << 32) | flow->server_port;
    value ^= value >> 33;
    value *= 0xff51afd7ed558ccdull;
    value ^= value >> 33;
    return (size_t)value & (CLIENT_FLOW_CAPACITY - 1u);
}

static struct gate_flow *gate_flow_find(struct client_agent *agent, const struct flow_key *key) {
    size_t start = flow_hash(key);
    for (size_t offset = 0; offset < CLIENT_FLOW_CAPACITY; offset++) {
        struct gate_flow *flow = &agent->flows[(start + offset) & (CLIENT_FLOW_CAPACITY - 1u)];
        if (flow->occupancy == 0)
            return NULL;
        if (flow->occupancy == 1 && same_flow(&flow->key, key))
            return flow;
    }
    return NULL;
}

static struct gate_flow *gate_flow_slot(struct client_agent *agent, const struct flow_key *key) {
    size_t first_tombstone = CLIENT_FLOW_CAPACITY;
    size_t start = flow_hash(key);
    for (size_t offset = 0; offset < CLIENT_FLOW_CAPACITY; offset++) {
        size_t index = (start + offset) & (CLIENT_FLOW_CAPACITY - 1u);
        struct gate_flow *flow = &agent->flows[index];
        if (flow->occupancy == 1 && same_flow(&flow->key, key))
            return flow;
        if (flow->occupancy == 2 && first_tombstone == CLIENT_FLOW_CAPACITY)
            first_tombstone = index;
        if (flow->occupancy == 0)
            return &agent->flows[first_tombstone == CLIENT_FLOW_CAPACITY ? index : first_tombstone];
    }
    return first_tombstone == CLIENT_FLOW_CAPACITY ? NULL : &agent->flows[first_tombstone];
}

static int resolve_server(const char *host, uint16_t port, struct sockaddr_in *server) {
    char service[16];
    snprintf(service, sizeof(service), "%u", port);
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    };
    struct addrinfo *addresses = NULL;
    if (getaddrinfo(host, service, &hints, &addresses) != 0)
        return 0;
    int ok = addresses && addresses->ai_addrlen == sizeof(*server);
    if (ok)
        memcpy(server, addresses->ai_addr, sizeof(*server));
    freeaddrinfo(addresses);
    return ok;
}

static int control_connect(const struct client_agent *agent) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int enabled = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
    struct timeval timeout = {
        .tv_sec = (time_t)(agent->timeout_ms / 1000u),
        .tv_usec = (suseconds_t)((agent->timeout_ms % 1000u) * 1000u),
    };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (connect(fd, (const struct sockaddr *)&agent->ra_server, sizeof(agent->ra_server)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static struct client_session *find_generation(struct client_agent *agent,
                                              const struct flow_key *flow,
                                              const uint8_t lookup_key[RA_KEY_SIZE]) {
    for (struct client_session *session = agent->sessions; session; session = session->next) {
        if (!session->finalized && same_flow(&session->flow, flow) &&
            memcmp(session->lookup_key, lookup_key, RA_KEY_SIZE) == 0)
            return session;
    }
    return NULL;
}

static struct client_session *create_session(struct client_agent *agent,
                                             const struct flow_key *flow,
                                             const uint8_t lookup_key[RA_KEY_SIZE],
                                             uint64_t observed_ns) {
    if (agent->started_sessions >= agent->expected_sessions)
        return NULL;
    struct client_session *session = calloc(1, sizeof(*session));
    if (!session)
        return NULL;
    session->agent = agent;
    session->flow = *flow;
    memcpy(session->lookup_key, lookup_key, RA_KEY_SIZE);
    session->id = ++agent->started_sessions;
    session->response_status = -1;
    session->clienthello_observed_ns = observed_ns;
    pthread_mutex_init(&session->mutex, NULL);
    pthread_cond_init(&session->changed, NULL);
    session->next = agent->sessions;
    agent->sessions = session;
    return session;
}

static int enqueue_job(struct client_agent *agent, struct client_session *session) {
    int ok = 0;
    pthread_mutex_lock(&agent->job_mutex);
    if (agent->job_count < CLIENT_JOB_CAPACITY && !atomic_load(&agent->stopping)) {
        agent->jobs[agent->job_tail] = session;
        agent->job_tail = (agent->job_tail + 1u) & (CLIENT_JOB_CAPACITY - 1u);
        agent->job_count++;
        ok = 1;
        pthread_cond_signal(&agent->job_available);
    }
    pthread_mutex_unlock(&agent->job_mutex);
    return ok;
}

static struct client_session *dequeue_job(struct client_agent *agent) {
    pthread_mutex_lock(&agent->job_mutex);
    while (!agent->job_count && !atomic_load(&agent->stopping))
        pthread_cond_wait(&agent->job_available, &agent->job_mutex);
    struct client_session *session = NULL;
    if (agent->job_count) {
        session = agent->jobs[agent->job_head];
        agent->job_head = (agent->job_head + 1u) & (CLIENT_JOB_CAPACITY - 1u);
        agent->job_count--;
    }
    pthread_mutex_unlock(&agent->job_mutex);
    return session;
}

static int enqueue_decision(struct client_agent *agent, struct client_session *session) {
    int ok = 0;
    pthread_mutex_lock(&agent->decision_mutex);
    if (agent->decision_count < CLIENT_DECISION_CAPACITY) {
        agent->decisions[agent->decision_tail] = session;
        agent->decision_tail = (agent->decision_tail + 1u) & (CLIENT_DECISION_CAPACITY - 1u);
        agent->decision_count++;
        ok = 1;
    }
    pthread_mutex_unlock(&agent->decision_mutex);
    if (ok) {
        uint64_t one = 1;
        if (write(agent->decision_event_fd, &one, sizeof(one)) != (ssize_t)sizeof(one))
            ok = 0;
    }
    return ok;
}

static struct client_session *dequeue_decision(struct client_agent *agent) {
    pthread_mutex_lock(&agent->decision_mutex);
    struct client_session *session = NULL;
    if (agent->decision_count) {
        session = agent->decisions[agent->decision_head];
        agent->decision_head = (agent->decision_head + 1u) & (CLIENT_DECISION_CAPACITY - 1u);
        agent->decision_count--;
    }
    pthread_mutex_unlock(&agent->decision_mutex);
    return session;
}

static void deadline_after_ms(struct timespec *deadline, uint32_t timeout_ms) {
    clock_gettime(CLOCK_REALTIME, deadline);
    deadline->tv_sec += (time_t)(timeout_ms / 1000u);
    deadline->tv_nsec += (long)(timeout_ms % 1000u) * 1000000l;
    if (deadline->tv_nsec >= 1000000000l) {
        deadline->tv_sec++;
        deadline->tv_nsec -= 1000000000l;
    }
}

static int wait_for_server_hello(struct client_session *session) {
    struct timespec deadline;
    deadline_after_ms(&deadline, session->agent->timeout_ms);
    pthread_mutex_lock(&session->mutex);
    while (!session->has_server_hello && !session->cancelled &&
           !atomic_load(&session->agent->stopping)) {
        int result = pthread_cond_timedwait(&session->changed, &session->mutex, &deadline);
        if (result == ETIMEDOUT)
            break;
    }
    int ready = session->has_server_hello;
    pthread_mutex_unlock(&session->mutex);
    return ready;
}

static int wait_for_gate(struct client_session *session) {
    struct timespec deadline;
    deadline_after_ms(&deadline, session->agent->timeout_ms);
    pthread_mutex_lock(&session->mutex);
    while (!session->decision_applied && !session->cancelled &&
           !atomic_load(&session->agent->stopping)) {
        int result = pthread_cond_timedwait(&session->changed, &session->mutex, &deadline);
        if (result == ETIMEDOUT)
            break;
    }
    int applied = session->decision_applied;
    pthread_mutex_unlock(&session->mutex);
    return applied;
}

static void finish_session(struct client_session *session) {
    struct client_agent *agent = session->agent;
    session->finished_ns = tcpra_now_ns();
    session->success = session->gate_allowed && session->remote_verdict_sent;
    pthread_mutex_lock(&agent->session_mutex);
    session->finalized = 1;
    agent->completed_sessions++;
    if (session->gate_allowed)
        agent->verified_sessions++;
    if (!session->success)
        agent->failed_sessions++;
    pthread_cond_broadcast(&agent->progress);
    pthread_mutex_unlock(&agent->session_mutex);
}

static int reconnect_worker(struct client_worker *worker) {
    if (worker->fd >= 0)
        close(worker->fd);
    worker->fd = control_connect(worker->agent);
    return worker->fd >= 0;
}

static int send_early_client_report(struct client_worker *worker, struct client_session *session,
                                    const struct ra_request *request) {
    struct client_agent *agent = worker->agent;
    uint8_t client_report[RA_REPORT_SIZE];
    if (!tcpra_early_client_report_key(session->lookup_key, request->client_nonce,
                                       session->client_report_key))
        return 0;
    uint64_t generated_started = tcpra_now_ns();
    session->client_report_generated =
        tcpra_csv_generate_report(&agent->verifier, session->client_report_key, client_report);
    session->client_report_generation_ns = tcpra_now_ns() - generated_started;
    if (!session->client_report_generated)
        return 0;
#ifdef TCPRA_TEST_CORRUPT_EARLY_REPORT
    client_report[0] ^= 0x01;
#endif

    uint64_t send_started = tcpra_now_ns();
    int sent = tcpra_write_all(worker->fd, client_report, sizeof(client_report));
    session->early_report_send_ns = tcpra_now_ns() - send_started;
    return sent;
}

static void run_control_job(struct client_worker *worker, struct client_session *session) {
    struct client_agent *agent = worker->agent;
    uint8_t report[RA_REPORT_SIZE] = {0};
    session->control_worker = worker->index;
    session->control_reused = worker->uses > 0;
    worker->uses++;
    if (worker->fd < 0 && !reconnect_worker(worker)) {
        enqueue_decision(agent, session);
        wait_for_gate(session);
        finish_session(session);
        return;
    }

    session->request_start_ns = tcpra_now_ns();
    session->request_id = session->request_start_ns ^ ((uint64_t)(uintptr_t)session << 17);
    struct ra_request request = {
        .magic = htonl(RA_MAGIC),
        .version = htons(agent->mutual_ra ? RA_MRA_VERSION : RA_VERSION),
        .type = htons(agent->mutual_ra ? RA_MUTUAL_REQUEST : RA_REQUEST),
        .client_nonce = tcpra_network_u64(session->request_id),
    };
    memcpy(request.lookup_key, session->lookup_key, RA_KEY_SIZE);
    int request_ok = tcpra_write_all(worker->fd, &request, sizeof(request));
    session->request_sent_ns = tcpra_now_ns();
    if (request_ok && agent->mutual_ra)
        request_ok = send_early_client_report(worker, session, &request);
    struct ra_response response;
    memset(&response, 0, sizeof(response));
    int response_ok = request_ok && tcpra_read_all(worker->fd, &response, sizeof(response));
    session->response_header_ns = tcpra_now_ns();
    if (response_ok && ntohl(response.magic) == RA_MAGIC &&
        ntohs(response.version) == (agent->mutual_ra ? RA_MRA_VERSION : RA_VERSION) &&
        ntohs(response.type) == RA_RESPONSE) {
        session->response_status = (int)ntohl(response.status);
        session->report_length = ntohl(response.report_len);
        memcpy(session->response_report_key, response.report_key, RA_KEY_SIZE);
    } else {
        response_ok = 0;
    }
    int full_response = response_ok && session->response_status == RA_OK &&
                        session->report_length == RA_REPORT_SIZE &&
                        tcpra_read_all(worker->fd, report, sizeof(report));
    if (agent->mutual_ra)
        session->client_report_accepted = full_response && session->client_report_generated;
    session->response_done_ns = tcpra_now_ns();

    int has_server_hello = full_response && wait_for_server_hello(session);
    if (has_server_hello) {
        uint8_t expected_report_key[RA_KEY_SIZE];
        int expected_ok = 1;
        if (agent->mutual_ra)
            expected_ok = tcpra_early_server_report_key(
                session->local_report_key, session->client_report_key, expected_report_key);
        else
            memcpy(expected_report_key, session->local_report_key, RA_KEY_SIZE);
        pthread_mutex_lock(&session->mutex);
        session->key_match = expected_ok && memcmp(session->response_report_key,
                                                   expected_report_key, RA_KEY_SIZE) == 0;
        pthread_mutex_unlock(&session->mutex);
        if (session->key_match) {
            session->verify_start_ns = tcpra_now_ns();
            session->report_verify =
                tcpra_csv_verify_report(&agent->verifier, report, expected_report_key);
            session->verify_done_ns = tcpra_now_ns();
        }
    }
    if (!session->verify_start_ns) {
        session->verify_start_ns = tcpra_now_ns();
        session->verify_done_ns = session->verify_start_ns;
    }
    int mutual_ok = !agent->mutual_ra || session->client_report_accepted;
    session->decision_queued_ns = tcpra_now_ns();
    if (!enqueue_decision(agent, session) || !wait_for_gate(session)) {
        session->gate_allowed = 0;
    }

    struct ra_verdict verdict = {
        .magic = htonl(RA_MAGIC),
        .version = request.version,
        .type = htons(RA_VERDICT),
        .verified = htonl(session->gate_allowed ? 1u : 0u),
        .client_nonce = request.client_nonce,
    };
    memcpy(verdict.lookup_key, request.lookup_key, RA_KEY_SIZE);
    if (full_response && mutual_ok)
        session->remote_verdict_sent = tcpra_write_all(worker->fd, &verdict, sizeof(verdict));
    session->remote_verdict_ns = tcpra_now_ns();
    if (!full_response || !session->remote_verdict_sent)
        reconnect_worker(worker);
    finish_session(session);
}

static void *control_worker_main(void *opaque) {
    struct client_worker *worker = opaque;
    while (!atomic_load(&worker->agent->stopping)) {
        struct client_session *session = dequeue_job(worker->agent);
        if (!session)
            continue;
        run_control_job(worker, session);
    }
    return NULL;
}

static int client_observe_hello(struct client_agent *agent, const struct flow_key *flow,
                                const uint8_t lookup_key[RA_KEY_SIZE], uint64_t observed_ns) {
    pthread_mutex_lock(&agent->session_mutex);
    struct client_session *session = find_generation(agent, flow, lookup_key);
    if (session) {
        pthread_mutex_unlock(&agent->session_mutex);
        return 1;
    }
    session = create_session(agent, flow, lookup_key, observed_ns);
    pthread_mutex_unlock(&agent->session_mutex);
    if (!session || !enqueue_job(agent, session)) {
        agent->counters.job_queue_full++;
        return 0;
    }
    return 1;
}

static void client_observe_server_key(struct client_agent *agent, const struct flow_key *flow,
                                      const uint8_t lookup_key[RA_KEY_SIZE],
                                      const uint8_t report_key[RA_KEY_SIZE], uint64_t observed_ns) {
    pthread_mutex_lock(&agent->session_mutex);
    struct client_session *session = find_generation(agent, flow, lookup_key);
    if (session) {
        pthread_mutex_lock(&session->mutex);
        if (!session->has_server_hello) {
            memcpy(session->local_report_key, report_key, RA_KEY_SIZE);
            session->serverhello_observed_ns = observed_ns;
            session->has_server_hello = 1;
            pthread_cond_broadcast(&session->changed);
        }
        pthread_mutex_unlock(&session->mutex);
    }
    pthread_mutex_unlock(&agent->session_mutex);
}

static void finish_held(struct client_agent *agent, struct gate_flow *flow, uint32_t verdict) {
    for (size_t index = 0; index < flow->held_count; index++) {

        if (nfq_set_verdict2(agent->nfq_queue, flow->held_ids[index], verdict,
                             verdict == NF_ACCEPT ? 0x544c0001u : 0, 0, NULL) < 0)
            continue;
        if (verdict == NF_ACCEPT) {
            agent->counters.released_packets++;
            agent->counters.accepted_packets++;
        } else {
            agent->counters.dropped_packets++;
        }
    }
    flow->held_count = 0;
}

static void drop_all_held(struct client_agent *agent) {
    for (size_t index = 0; index < CLIENT_FLOW_CAPACITY; index++) {
        struct gate_flow *gate = &agent->flows[index];
        if (gate->occupancy == 1 && gate->held_count)
            finish_held(agent, gate, NF_DROP);
    }
}

static void reset_gate_flow(struct client_agent *agent, struct gate_flow *gate,
                            const struct flow_key *key) {
    if (gate->occupancy == 1 && gate->held_count)
        finish_held(agent, gate, NF_DROP);
    memset(gate, 0, sizeof(*gate));
    gate->occupancy = 1;
    gate->key = *key;
    gate->state_ns = tcpra_now_ns();
    gate->deadline_ns = gate->state_ns + agent->timeout_ns;
    gate->state = GATE_HANDSHAKE;
}

enum packet_action { ACTION_DROP = -1, ACTION_ACCEPT = 0, ACTION_HOLD = 1, ACTION_AUTHORIZE = 2 };

static void quarantine_endpoint(struct client_agent *agent) {
    if (agent->endpoint_quarantined)
        return;
    agent->endpoint_quarantined = 1;
    fprintf(stderr, "TLSLATCH_QUARANTINED target=%s:%u\n", agent->server_host,
            (unsigned)agent->main_port);
    fflush(stderr);
    if (!tcpra_quarantine(agent->server_host, agent->main_port))
        fprintf(stderr, "FATAL: endpoint quarantine failed; pending packets remain blocked\n");
}

static enum packet_action handle_client_packet(struct client_agent *agent,
                                               const struct tcpra_ipv4_tcp_view *view,
                                               uint32_t packet_id) {
    struct flow_key key = {0};
    int client_to_server = 0;
    if (!tcpra_normalize_flow(view, agent->main_port, &key, &client_to_server))
        return ACTION_ACCEPT;
    if (agent->endpoint_quarantined)
        return ACTION_DROP;

    if (client_to_server && (view->tcp_flags & (TH_SYN | TH_ACK)) == TH_SYN) {
        uint64_t cookie;
        if (!tcpra_socket_cookie_state(&key, 0, 2, &cookie)) {
            if (agent->audit_only) {
                agent->audit.failed = 1;
                return ACTION_ACCEPT;
            }
            quarantine_endpoint(agent);
            return ACTION_DROP;
        }
        struct gate_flow *gate = gate_flow_slot(agent, &key);
        if (!gate) {
            agent->counters.flow_table_full++;
            if (agent->audit_only) {
                agent->audit.failed = 1;
                return ACTION_ACCEPT;
            }
            quarantine_endpoint(agent);
            return ACTION_DROP;
        }
        if (gate->occupancy == 1 && gate->client_hello_seen)
            agent->counters.flow_generation_resets++;
        reset_gate_flow(agent, gate, &key);
        gate->socket_cookie = cookie;
        if (agent->audit_only)
            gate->deadline_ns = 0;
        return ACTION_ACCEPT;
    }
    if (agent->audit_only) {
        struct gate_flow *gate = gate_flow_find(agent, &key);
        uint8_t ch[RA_KEY_SIZE], sh[RA_KEY_SIZE], pub[TCPRA_MAX_PUBLIC_KEY];
        uint16_t group;
        size_t pub_len;
        if (client_to_server && view->payload_length &&
            tcpra_tls_find_clienthello(view->payload, view->payload_length, ch)) {
            if (!gate || memcmp(gate->lookup_key, ch, RA_KEY_SIZE)) {
                gate = gate_flow_slot(agent, &key);
                if (!gate) {
                    agent->audit.failed = 1;
                    return ACTION_ACCEPT;
                }
                reset_gate_flow(agent, gate, &key);
                gate->deadline_ns = 0;
                gate->client_hello_seen = 1;
                memcpy(gate->lookup_key, ch, RA_KEY_SIZE);
                agent->counters.client_hellos++;
            }
        } else if (!client_to_server && view->payload_length &&
                   tcpra_tls_find_serverhello(view->payload, view->payload_length, &group, pub,
                                              &pub_len, sh)) {
            if (!gate || !gate->client_hello_seen)
                agent->audit.failed = 1;
            else if (!gate->server_hello_seen) {
                gate->server_hello_seen = 1;
                memcpy(gate->report_key, sh, RA_KEY_SIZE);
                agent->counters.server_hellos++;
                client_audit_record(&agent->audit, gate);
            }
        }

        if (gate && gate->server_hello_seen && client_to_server)
            return ACTION_AUTHORIZE;
        return ACTION_ACCEPT;
    }
    if (agent->endpoint_quarantined)
        return ACTION_DROP;

#if TCPRA_SELECTOR_CLOSE_CLEANUP
    if (client_to_server && view->payload_length == 0 &&
        (view->tcp_flags & (TH_FIN | TH_RST)) != 0 && agent->selector) {
        struct gate_flow *closing = gate_flow_find(agent, &key);
        if (closing && closing->held_count)
            finish_held(agent, closing, NF_DROP);

        if (closing) {
            memset(closing, 0, sizeof(*closing));
            closing->occupancy = 2;
        }
        return ACTION_ACCEPT;
    }
#endif

    if (client_to_server && view->payload_length) {
        uint8_t lookup_key[RA_KEY_SIZE];
        if (tcpra_tls_find_clienthello(view->payload, view->payload_length, lookup_key)) {
            uint64_t cookie;
            if (!tcpra_socket_cookie(&key, 0, &cookie)) {
                quarantine_endpoint(agent);
                return ACTION_DROP;
            }
            struct gate_flow *gate = gate_flow_slot(agent, &key);
            if (!gate) {
                agent->counters.flow_table_full++;
                quarantine_endpoint(agent);
                return ACTION_DROP;
            }
            if (gate->occupancy == 1 && gate->client_hello_seen &&
                memcmp(gate->lookup_key, lookup_key, RA_KEY_SIZE) != 0)
                agent->counters.flow_generation_resets++;
            if (gate->occupancy != 1 || !gate->client_hello_seen || gate->socket_cookie != cookie ||
                memcmp(gate->lookup_key, lookup_key, RA_KEY_SIZE) != 0) {
                reset_gate_flow(agent, gate, &key);
                gate->socket_cookie = cookie;
                gate->client_hello_seen = 1;
                memcpy(gate->lookup_key, lookup_key, RA_KEY_SIZE);
                agent->counters.client_hellos++;
                if (!client_observe_hello(agent, &key, lookup_key, gate->state_ns))
                    return ACTION_DROP;
            }
            return ACTION_ACCEPT;
        }
    }

    if (!client_to_server && view->payload_length) {
        uint16_t group_id = 0;
        uint8_t public_key[TCPRA_MAX_PUBLIC_KEY];
        size_t public_key_length = 0;
        uint8_t report_key[RA_KEY_SIZE];
        if (tcpra_tls_find_serverhello(view->payload, view->payload_length, &group_id, public_key,
                                       &public_key_length, report_key)) {
            (void)group_id;
            (void)public_key;
            (void)public_key_length;
            struct gate_flow *gate = gate_flow_find(agent, &key);
            if (!gate || !gate->client_hello_seen)
                return ACTION_DROP;
            if (!gate->server_hello_seen) {
                gate->server_hello_seen = 1;
                gate->state = GATE_SERVER_HELLO;
                gate->state_ns = tcpra_now_ns();
                memcpy(gate->report_key, report_key, RA_KEY_SIZE);
                agent->counters.server_hellos++;
                client_observe_server_key(agent, &key, gate->lookup_key, report_key,
                                          gate->state_ns);
            }
            return ACTION_ACCEPT;
        }
    }

    struct gate_flow *gate = gate_flow_find(agent, &key);
    if (!gate) {
        if (view->payload_length == 0)
            return ACTION_ACCEPT;
        return client_to_server ? ACTION_DROP : ACTION_ACCEPT;
    }
    if (gate->state == GATE_ADMITTED) {
        uint64_t cookie;
        if (!client_to_server)
            return ACTION_ACCEPT;
        if (!tcpra_socket_cookie(&key, 0, &cookie) || cookie != gate->socket_cookie) {
            quarantine_endpoint(agent);
            return ACTION_DROP;
        }
        return ACTION_AUTHORIZE;
    }
    if (gate->state == GATE_DENIED)
        return ACTION_DROP;
    if (view->payload_length == 0 || !client_to_server)
        return ACTION_ACCEPT;
    if (gate->held_count >= MAX_HELD_PACKETS) {
        agent->counters.held_table_full++;
        quarantine_endpoint(agent);
        return ACTION_DROP;
    }
    gate->held_ids[gate->held_count++] = packet_id;
    agent->counters.held_packets++;
    return ACTION_HOLD;
}

static int nfqueue_callback(struct nfq_q_handle *queue, struct nfgenmsg *message,
                            struct nfq_data *packet, void *opaque) {
    (void)queue;
    (void)message;
    struct client_agent *agent = opaque;
    struct nfqnl_msg_packet_hdr *header = nfq_get_msg_packet_hdr(packet);
    uint32_t packet_id = header ? ntohl(header->packet_id) : 0;
    unsigned char *payload = NULL;
    int length = nfq_get_payload(packet, &payload);
    if (length < 0)
        length = 0;
    agent->counters.copied_packets++;
    agent->counters.copied_bytes += (unsigned long long)length;
    enum packet_action action = ACTION_DROP;
    struct tcpra_ipv4_tcp_view view;
    if (length > 0 && tcpra_parse_ipv4_tcp(payload, (size_t)length, &view))
        action = handle_client_packet(agent, &view, packet_id);
    if (action == ACTION_HOLD)
        return 0;
    if (action == ACTION_DROP) {
        agent->counters.dropped_packets++;
        return nfq_set_verdict(agent->nfq_queue, packet_id, NF_DROP, 0, NULL);
    }
    agent->counters.accepted_packets++;
    if (action == ACTION_AUTHORIZE)
        return nfq_set_verdict2(agent->nfq_queue, packet_id, NF_ACCEPT, 0x544c0001u, 0, NULL);
    return nfq_set_verdict(agent->nfq_queue, packet_id, NF_ACCEPT, 0, NULL);
}

static void apply_decision_impl(struct client_agent *agent, struct client_session *session) {
    struct gate_flow *gate = gate_flow_find(agent, &session->flow);
    int allow = 0;
    if (gate && gate->client_hello_seen &&
        memcmp(gate->lookup_key, session->lookup_key, RA_KEY_SIZE) == 0) {
        allow = !agent->endpoint_quarantined && session->report_verify &&
                (!agent->mutual_ra || session->client_report_accepted) && gate->server_hello_seen &&
                memcmp(gate->report_key, session->local_report_key, RA_KEY_SIZE) == 0;
        if (allow && agent->selector) {
            uint64_t current_cookie;
            allow = tcpra_socket_cookie(&gate->key, 0, &current_cookie) &&
                    current_cookie == gate->socket_cookie;
        }
        if (allow && agent->selector) {
            uint64_t selector_start_ns = tcpra_now_ns();
            int selector_result = tcpra_flow_selector_delete(agent->selector, &gate->key);
            session->selector_delete_ns = tcpra_now_ns() - selector_start_ns;
            if (selector_result == 0)
                agent->counters.flow_map_deletes++;
            else {
                agent->counters.flow_map_delete_misses++;
                allow = 0;
            }
        }
        if (!allow && !agent->endpoint_quarantined) {
            fprintf(stderr,
                    "endpoint deny session=%d report=%d status=%d serverhello=%d keymatch=%d "
                    "selector_misses=%llu\n",
                    session->id, session->report_verify, session->response_status,
                    gate->server_hello_seen, session->key_match,
                    agent->counters.flow_map_delete_misses);
            agent->endpoint_quarantined = 1;
            if (!tcpra_quarantine(agent->server_host, agent->main_port))
                fprintf(stderr,
                        "FATAL: endpoint quarantine failed; pending packets remain blocked\n");
        }
        finish_held(agent, gate, allow ? NF_ACCEPT : NF_DROP);
        gate->state = allow ? GATE_ADMITTED : GATE_DENIED;
        gate->state_ns = tcpra_now_ns();
        gate->deadline_ns = 0;
        if (allow)
            agent->counters.decisions_allowed++;
        else
            agent->counters.decisions_denied++;
    } else {
        agent->counters.decision_mismatches++;
    }
    if (!allow)
        quarantine_endpoint(agent);
    pthread_mutex_lock(&session->mutex);
    session->gate_allowed = allow;
    session->local_decision_ns = tcpra_now_ns();
    session->decision_applied = 1;
    pthread_cond_broadcast(&session->changed);
    pthread_mutex_unlock(&session->mutex);
}

static void apply_decision(struct client_agent *agent, struct client_session *session) {
    struct prof_stamp t = prof_start();
    apply_decision_impl(agent, session);
    prof_end("gate_authorize_release", session->flow.client_port, session->gate_allowed, t);
}

static void drain_decisions(struct client_agent *agent) {
    uint64_t count;
    while (read(agent->decision_event_fd, &count, sizeof(count)) < 0 && errno == EINTR) {
    }
    for (;;) {
        struct client_session *session = dequeue_decision(agent);
        if (!session)
            break;
        apply_decision(agent, session);
    }
}

static void expire_gate_flows(struct client_agent *agent) {
    uint64_t current = tcpra_now_ns();
    if (current - agent->last_expiry_scan_ns < 10ull * 1000000ull)
        return;
    agent->last_expiry_scan_ns = current;
    for (size_t index = 0; index < CLIENT_FLOW_CAPACITY; index++) {
        struct gate_flow *gate = &agent->flows[index];
        if (gate->occupancy != 1)
            continue;
        if (gate->deadline_ns && current >= gate->deadline_ns && gate->state != GATE_ADMITTED &&
            gate->state != GATE_DENIED) {
            finish_held(agent, gate, NF_DROP);
            gate->state = GATE_DENIED;
            gate->deadline_ns = 0;
            gate->state_ns = current;
            agent->counters.timeouts++;
            quarantine_endpoint(agent);
        } else if (!gate->held_count &&
                   (gate->state == GATE_ADMITTED || gate->state == GATE_DENIED) &&
                   current - gate->state_ns > 120ull * 1000000000ull) {
            memset(gate, 0, sizeof(*gate));
            gate->occupancy = 2;
        }
    }
}

static int initialize_nfqueue(struct client_agent *agent) {
    agent->nfq_handle = nfq_open();
    if (!agent->nfq_handle)
        return 0;
    if (nfq_unbind_pf(agent->nfq_handle, AF_INET) < 0)
        fprintf(stderr, "warning: nfq_unbind_pf IPv4 failed\n");
    if (nfq_bind_pf(agent->nfq_handle, AF_INET) < 0)
        return 0;
    agent->nfq_queue =
        nfq_create_queue(agent->nfq_handle, agent->queue_number, nfqueue_callback, agent);
    if (!agent->nfq_queue || nfq_set_mode(agent->nfq_queue, NFQNL_COPY_PACKET, 0xffff) < 0)
        return 0;
    if (nfq_set_queue_maxlen(agent->nfq_queue, 65535) < 0)
        fprintf(stderr, "warning: cannot enlarge NFQUEUE length\n");
#ifdef NFQA_CFG_F_GSO
    if (nfq_set_queue_flags(agent->nfq_queue, NFQA_CFG_F_GSO, NFQA_CFG_F_GSO) < 0)
        fprintf(stderr, "warning: cannot enable NFQUEUE GSO flag\n");
#endif
    agent->nfq_fd = nfq_fd(agent->nfq_handle);
    int receive_buffer = 16 * 1024 * 1024;
    setsockopt(agent->nfq_fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer));
    int no_enobufs = 1;
    setsockopt(agent->nfq_fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &no_enobufs, sizeof(no_enobufs));
    int flags = fcntl(agent->nfq_fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(agent->nfq_fd, F_SETFL, flags | O_NONBLOCK);
    agent->nfq_buffer = aligned_alloc(4096, RECEIVE_BUFFER_SIZE);
    return agent->nfq_buffer != NULL;
}

static void close_nfqueue(struct client_agent *agent) {
    for (size_t index = 0; index < CLIENT_FLOW_CAPACITY; index++) {
        if (agent->flows[index].occupancy == 1 && agent->flows[index].held_count)
            finish_held(agent, &agent->flows[index], NF_DROP);
    }
    free(agent->nfq_buffer);
    if (agent->nfq_queue)
        nfq_destroy_queue(agent->nfq_queue);
    if (agent->nfq_handle)
        nfq_close(agent->nfq_handle);
    agent->nfq_buffer = NULL;
    agent->nfq_queue = NULL;
    agent->nfq_handle = NULL;
}

static int start_workers(struct client_agent *agent) {
    agent->workers = calloc(agent->worker_count, sizeof(*agent->workers));
    if (!agent->workers)
        return 0;
    for (size_t index = 0; index < agent->worker_count; index++)
        agent->workers[index].fd = -1;
    for (size_t index = 0; index < agent->worker_count; index++) {
        struct client_worker *worker = &agent->workers[index];
        worker->agent = agent;
        worker->index = (int)index;
        worker->fd = control_connect(agent);
        if (worker->fd < 0)
            return 0;
        if (pthread_create(&worker->thread, NULL, control_worker_main, worker) != 0)
            return 0;
        worker->started = 1;
    }
    return 1;
}

static void stop_workers(struct client_agent *agent) {
    atomic_store(&agent->stopping, 1);
    pthread_mutex_lock(&agent->job_mutex);
    pthread_cond_broadcast(&agent->job_available);
    pthread_mutex_unlock(&agent->job_mutex);
    pthread_mutex_lock(&agent->session_mutex);
    for (struct client_session *session = agent->sessions; session; session = session->next) {
        pthread_mutex_lock(&session->mutex);
        session->cancelled = 1;
        pthread_cond_broadcast(&session->changed);
        pthread_mutex_unlock(&session->mutex);
    }
    pthread_mutex_unlock(&agent->session_mutex);
    if (!agent->workers)
        return;
    for (size_t index = 0; index < agent->worker_count; index++) {
        if (agent->workers[index].fd >= 0)
            shutdown(agent->workers[index].fd, SHUT_RDWR);
    }
    for (size_t index = 0; index < agent->worker_count; index++) {
        if (agent->workers[index].started)
            pthread_join(agent->workers[index].thread, NULL);
        if (agent->workers[index].fd >= 0)
            close(agent->workers[index].fd);
    }
}

static int write_ready_file(const char *path) {
    if (!path)
        return 1;
    FILE *file = fopen(path, "w");
    if (!file)
        return 0;
    fprintf(file, "%ld\n", (long)getpid());
    int ok = fclose(file) == 0;
    return ok;
}

static void hex_encode(const uint8_t *input, size_t length, char *output) {
    static const char digits[] = "0123456789abcdef";
    for (size_t index = 0; index < length; index++) {
        output[index * 2] = digits[input[index] >> 4];
        output[index * 2 + 1] = digits[input[index] & 15];
    }
    output[length * 2] = '\0';
}

static int write_results(struct client_agent *agent) {
    FILE *output = fopen(agent->csv_path, "w");
    if (!output)
        return 0;
    fputs("session,mode,success,verified,client_port,server_port,lookup_key,local_serverhello_key,"
          "response_report_key,clienthello_observed_ns,request_start_ns,request_sent_ns,response_"
          "header_ns,response_done_ns,serverhello_observed_ns,verify_start_ns,verify_done_ns,"
          "decision_queued_ns,local_decision_ns,remote_verdict_ns,finished_ns,response_status,"
          "report_length,key_match,report_verify,gate_allowed,remote_verdict_sent,control_worker,"
          "control_reused,early_dispatch_ns,response_wait_ns,verify_ns,decision_dispatch_ns,total_"
          "ns,selector_delete_ns,mutual_ra,client_report_generated,client_report_accepted,client_"
          "report_generation_ns,early_report_send_ns\n",
          output);
    for (struct client_session *session = agent->sessions; session; session = session->next) {
        char lookup[RA_KEY_SIZE * 2 + 1];
        char local[RA_KEY_SIZE * 2 + 1];
        char response[RA_KEY_SIZE * 2 + 1];
        hex_encode(session->lookup_key, RA_KEY_SIZE, lookup);
        hex_encode(session->local_report_key, RA_KEY_SIZE, local);
        hex_encode(session->response_report_key, RA_KEY_SIZE, response);
        fprintf(
            output,
            "%d,%s,%d,%d,%u,%u,%s,%s,%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%"
            "llu,%d,%u,%d,%d,%d,%d,%d,%d,%llu,%llu,%llu,%llu,%llu,%llu,%d,%d,%d,%llu,%llu\n",
            session->id,
            agent->mode == MODE_NIRA
                ? "nira"
                : (agent->mutual_ra ? TCPRA_MUTUAL_MODE_NAME : TCPRA_DYNAMIC_MODE_NAME),
            session->success, session->gate_allowed, session->flow.client_port,
            session->flow.server_port, lookup, local, response,
            (unsigned long long)session->clienthello_observed_ns,
            (unsigned long long)session->request_start_ns,
            (unsigned long long)session->request_sent_ns,
            (unsigned long long)session->response_header_ns,
            (unsigned long long)session->response_done_ns,
            (unsigned long long)session->serverhello_observed_ns,
            (unsigned long long)session->verify_start_ns,
            (unsigned long long)session->verify_done_ns,
            (unsigned long long)session->decision_queued_ns,
            (unsigned long long)session->local_decision_ns,
            (unsigned long long)session->remote_verdict_ns,
            (unsigned long long)session->finished_ns, session->response_status,
            session->report_length, session->key_match, session->report_verify,
            session->gate_allowed, session->remote_verdict_sent, session->control_worker,
            session->control_reused,
            (unsigned long long)(session->request_sent_ns >= session->clienthello_observed_ns
                                     ? session->request_sent_ns - session->clienthello_observed_ns
                                     : 0),
            (unsigned long long)(session->response_done_ns >= session->request_sent_ns
                                     ? session->response_done_ns - session->request_sent_ns
                                     : 0),
            (unsigned long long)(session->verify_done_ns >= session->verify_start_ns
                                     ? session->verify_done_ns - session->verify_start_ns
                                     : 0),
            (unsigned long long)(session->local_decision_ns >= session->decision_queued_ns
                                     ? session->local_decision_ns - session->decision_queued_ns
                                     : 0),
            (unsigned long long)(session->finished_ns >= session->clienthello_observed_ns
                                     ? session->finished_ns - session->clienthello_observed_ns
                                     : 0),
            (unsigned long long)session->selector_delete_ns, agent->mutual_ra,
            session->client_report_generated, session->client_report_accepted,
            (unsigned long long)session->client_report_generation_ns,
            (unsigned long long)session->early_report_send_ns);
    }
    return fclose(output) == 0;
}

static void destroy_sessions(struct client_agent *agent) {
    struct client_session *session = agent->sessions;
    while (session) {
        struct client_session *next = session->next;
        pthread_cond_destroy(&session->changed);
        pthread_mutex_destroy(&session->mutex);
        free(session);
        session = next;
    }
}

static enum tcpra_mode parse_mode(const char *text) {
    if (text && strcmp(text, "nira") == 0)
        return MODE_NIRA;
    if (text && strcmp(text, TCPRA_DYNAMIC_MODE_NAME) == 0)
        return MODE_NIRAK;
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
            "usage: %s --mode nira|" TCPRA_DYNAMIC_MODE_NAME " --server HOST --ra-port PORT "
            "--main-port PORT --queue N --expected N --workers N --csv PATH "
            "[--flow-bpf OBJ --pin-dir DIR] [--ready-file PATH] "
            "[--timeout-ms MS] [--mutual-ra]\n",
            program);
}

int main(int argc, char **argv) {
    struct client_agent *agent_storage = calloc(1, sizeof(*agent_storage));
    if (!agent_storage)
        return 2;
    if (!freopen("/dev/null", "w", stdout)) {
        free(agent_storage);
        return 2;
    }
#define agent (*agent_storage)
    agent.nfq_fd = -1;
    agent.decision_event_fd = -1;
    agent.timeout_ms = DEFAULT_TIMEOUT_MS;
    agent.worker_count = DEFAULT_WORKERS;
    static const struct option options[] = {
        {"mode", required_argument, NULL, 'M'},
        {"server", required_argument, NULL, 's'},
        {"ra-port", required_argument, NULL, 'r'},
        {"main-port", required_argument, NULL, 'p'},
        {"queue", required_argument, NULL, 'q'},
        {"expected", required_argument, NULL, 'n'},
        {"workers", required_argument, NULL, 'w'},
        {"csv", required_argument, NULL, 'o'},
        {"flow-bpf", required_argument, NULL, 'b'},
        {"pin-dir", required_argument, NULL, 'd'},
        {"ready-file", required_argument, NULL, 'R'},
        {"timeout-ms", required_argument, NULL, 't'},
        {"audit-only", no_argument, NULL, 'A'},
        {"audit-epoch", required_argument, NULL, 'E'},
        {"audit-dlog", required_argument, NULL, 'D'},
        {"mutual-ra", no_argument, NULL, 'u'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    int option;
    while ((option = getopt_long(argc, argv, "M:s:r:p:q:n:w:o:b:d:R:t:uh", options, NULL)) != -1) {
        unsigned long value = 0;
        switch (option) {
        case 'M':
            agent.mode = parse_mode(optarg);
            break;
        case 's':
            agent.server_host = optarg;
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
        case 'w':
            if (!parse_unsigned(optarg, 1024, &value))
                return 2;
            agent.worker_count = (size_t)value;
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
        case 't':
            if (!parse_unsigned(optarg, 600000, &value))
                return 2;
            agent.timeout_ms = (uint32_t)value;
            break;
        case 'A':
            agent.audit_only = 1;
            break;
        case 'E':
            agent.audit_epoch = optarg;
            break;
        case 'D':
            agent.audit_directory = optarg;
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
    if (optind != argc || !agent.mode || !agent.server_host || !agent.ra_port || !agent.main_port ||
        !agent.expected_sessions || !agent.worker_count || !agent.csv_path ||
        (agent.mode != MODE_NIRA && (!agent.flow_bpf_object || !agent.pin_directory))) {
        usage(argv[0]);
        return 2;
    }
    if ((agent.audit_only && agent.mutual_ra) ||
        (agent.audit_directory && (!agent.audit_only || !agent.audit_epoch)))
        return 2;
    agent.timeout_ns = (uint64_t)agent.timeout_ms * 1000000ull;
    if (agent.worker_count > (size_t)agent.expected_sessions)
        agent.worker_count = (size_t)agent.expected_sessions;
    if (!resolve_server(agent.server_host, agent.ra_port, &agent.ra_server)) {
        fprintf(stderr, "cannot resolve RA server\n");
        return 2;
    }

    pthread_mutex_init(&agent.session_mutex, NULL);
    pthread_cond_init(&agent.progress, NULL);
    pthread_mutex_init(&agent.job_mutex, NULL);
    pthread_cond_init(&agent.job_available, NULL);
    pthread_mutex_init(&agent.decision_mutex, NULL);
    agent.decision_event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    int verifier_ready =
        tcpra_csv_context_open(&agent.verifier, (agent.mutual_ra || agent.audit_directory) ? 1 : 0);
    if (!verifier_ready || agent.decision_event_fd < 0)
        goto fail;
    if (agent.mode != MODE_NIRA) {
        agent.selector = tcpra_flow_selector_open(agent.flow_bpf_object, agent.server_host,
                                                  agent.main_port, agent.pin_directory);
        if (!agent.selector)
            goto fail;
    }
    if (agent.audit_only &&
        !client_audit_open(&agent.audit, agent.csv_path, (size_t)agent.expected_sessions,
                           agent.audit_epoch, agent.audit_directory, &agent.verifier))
        goto fail;
    if (!initialize_nfqueue(&agent) || (!agent.audit_only && !start_workers(&agent)) ||
        !write_ready_file(agent.ready_file))
        goto fail;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    fprintf(stderr, "tcpra_client_agent_ready mode=%s pid=%ld queue=%u workers=%zu\n",
            agent.mode == MODE_NIRA
                ? "nira"
                : (agent.mutual_ra ? TCPRA_MUTUAL_MODE_NAME : TCPRA_DYNAMIC_MODE_NAME),
            (long)getpid(), agent.queue_number, agent.worker_count);
    while (!signal_stop) {
        struct pollfd descriptors[2] = {
            {.fd = agent.decision_event_fd, .events = POLLIN},
            {.fd = agent.nfq_fd, .events = POLLIN},
        };
        int ready = poll(descriptors, 2, 100);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (descriptors[0].revents & POLLIN)
            drain_decisions(&agent);
        if (descriptors[1].revents & POLLIN) {
            int length = recv(agent.nfq_fd, agent.nfq_buffer, RECEIVE_BUFFER_SIZE, MSG_DONTWAIT);
            if (length >= 0)
                nfq_handle_packet(agent.nfq_handle, (char *)agent.nfq_buffer, length);
            else if (errno == ENOBUFS)
                agent.counters.enobufs++;
            else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                break;
        }
        expire_gate_flows(&agent);
    }
    stop_workers(&agent);
    drain_decisions(&agent);
    drop_all_held(&agent);
    int complete = agent.completed_sessions == agent.expected_sessions &&
                   agent.verified_sessions == agent.expected_sessions &&
                   agent.failed_sessions == 0 && agent.counters.enobufs == 0 &&
                   (agent.mode == MODE_NIRA || agent.counters.flow_map_delete_misses == 0);
    if (agent.audit_only) {
        client_audit_close(&agent.audit);
        complete = agent.audit.count == (size_t)agent.expected_sessions && !agent.audit.failed &&
                   !agent.counters.enobufs;
        fprintf(stderr, "AUDIT_SUMMARY records=%zu reports=%zu failed=%d\n", agent.audit.count,
                agent.audit.reporting ? agent.audit.consumed : 0, agent.audit.failed);
    } else
        write_results(&agent);
    fprintf(stderr,
            "sessions_started=%d completed=%d verified=%d failed=%d "
            "copied_packets=%llu copied_bytes=%llu held=%llu released=%llu "
            "map_deletes=%llu map_delete_misses=%llu "
            "selector_deletes=%llu selector_delete_misses=%llu "
            "close_cleanup_deletes=%llu close_cleanup_delete_misses=%llu "
            "generation_resets=%llu enobufs=%llu\n",
            agent.started_sessions, agent.completed_sessions, agent.verified_sessions,
            agent.failed_sessions, agent.counters.copied_packets, agent.counters.copied_bytes,
            agent.counters.held_packets, agent.counters.released_packets,
            agent.counters.flow_map_deletes, agent.counters.flow_map_delete_misses,
            agent.counters.flow_map_deletes, agent.counters.flow_map_delete_misses,
            agent.counters.close_cleanup_deletes, agent.counters.close_cleanup_delete_misses,
            agent.counters.flow_generation_resets, agent.counters.enobufs);
    if (agent.ready_file)
        unlink(agent.ready_file);
    close_nfqueue(&agent);
    tcpra_flow_selector_close(agent.selector);
    tcpra_csv_context_close(&agent.verifier);
    close(agent.decision_event_fd);
    destroy_sessions(&agent);
    free(agent.workers);
    pthread_mutex_destroy(&agent.decision_mutex);
    pthread_cond_destroy(&agent.job_available);
    pthread_mutex_destroy(&agent.job_mutex);
    pthread_cond_destroy(&agent.progress);
    pthread_mutex_destroy(&agent.session_mutex);
    free(agent_storage);
    return complete ? 0 : 3;

fail:
    fprintf(stderr, "tcpra_client_agent initialization failed: %s\n", strerror(errno));
    signal_stop = 1;
    stop_workers(&agent);
    if (agent.nfq_queue)
        drop_all_held(&agent);
    if (agent.ready_file)
        unlink(agent.ready_file);
    if (agent.nfq_handle)
        close_nfqueue(&agent);
    tcpra_flow_selector_close(agent.selector);
    if (verifier_ready)
        tcpra_csv_context_close(&agent.verifier);
    if (agent.decision_event_fd >= 0)
        close(agent.decision_event_fd);
    destroy_sessions(&agent);
    free(agent.workers);
    pthread_mutex_destroy(&agent.decision_mutex);
    pthread_cond_destroy(&agent.job_available);
    pthread_mutex_destroy(&agent.job_mutex);
    pthread_cond_destroy(&agent.progress);
    pthread_mutex_destroy(&agent.session_mutex);
    free(agent_storage);
    return 2;
#undef agent
}
